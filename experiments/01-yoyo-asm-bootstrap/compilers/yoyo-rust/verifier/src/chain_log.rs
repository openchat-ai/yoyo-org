use std::fs;
use std::io::{BufRead, Write};
use std::time::SystemTime;

/// One entry in the compilation chain log.
/// Stored as JSON lines (.jsonl).
#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub timestamp: String,
    pub compiler_id: String,
    pub input_path: String,
    pub output_path: String,
    pub input_sha: String,
    pub output_sha: String,
}

fn iso_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple ISO-like format without timezone complexity
    format!("{}", secs)
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Append a chain entry to the JSONL file.
pub fn append(path: &str, entry: &ChainEntry) -> Result<(), String> {
    let json = format!(
        r#"{{"ts":"{}","comp":"{}","in":"{}","out":"{}","in_sha":"{}","out_sha":"{}"}}"#,
        escape_json(&entry.timestamp),
        escape_json(&entry.compiler_id),
        escape_json(&entry.input_path),
        escape_json(&entry.output_path),
        escape_json(&entry.input_sha),
        escape_json(&entry.output_sha),
    );
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot append to {path}: {e}"))?;
    writeln!(f, "{json}").map_err(|e| format!("write error {path}: {e}"))?;
    Ok(())
}

/// Read all chain entries from a JSONL file.
pub fn read_all(path: &str) -> Result<Vec<ChainEntry>, String> {
    let f = fs::File::open(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let reader = std::io::BufReader::new(f);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read error {path}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        entries.push(parse_entry_json(&line)?);
    }
    Ok(entries)
}

/// Get the last N entries from the chain log.
pub fn last_entries(path: &str, n: usize) -> Result<Vec<ChainEntry>, String> {
    let all = read_all(path)?;
    let start = all.len().saturating_sub(n);
    Ok(all[start..].to_vec())
}

fn parse_entry_json(line: &str) -> Result<ChainEntry, String> {
    let get = |key: &str| -> Result<String, String> {
        let pattern = format!(r#""{}":""#, key);
        let start = line.find(&pattern).ok_or_else(|| format!("missing key {key}"))?;
        let start = start + pattern.len();
        let end = line[start..].find('"').ok_or_else(|| format!("unterminated value for {key}"))?;
        let raw = &line[start..start + end];
        Ok(raw.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r"))
    };
    Ok(ChainEntry {
        timestamp: get("ts")?,
        compiler_id: get("comp")?,
        input_path: get("in")?,
        output_path: get("out")?,
        input_sha: get("in_sha")?,
        output_sha: get("out_sha")?,
    })
}

/// Create a chain entry with computed SHAs.
pub fn record(
    compiler_id: &str,
    input_path: &str,
    output_path: &str,
) -> Result<ChainEntry, String> {
    let input_sha = crate::ddc::sha256_file(input_path)?;
    let output_sha = crate::ddc::sha256_file(output_path)?;
    Ok(ChainEntry {
        timestamp: iso_timestamp(),
        compiler_id: compiler_id.to_string(),
        input_path: input_path.to_string(),
        output_path: output_path.to_string(),
        input_sha,
        output_sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_entry() {
        let entry = ChainEntry {
            timestamp: "12345".into(),
            compiler_id: "yoyo.js".into(),
            input_path: "yoyo.ty".into(),
            output_path: "gen1.exe".into(),
            input_sha: "abc".into(),
            output_sha: "def".into(),
        };

        let tmp = std::env::temp_dir().join("chain_test.jsonl");
        let p = tmp.to_str().unwrap();
        append(p, &entry).unwrap();

        let entries = read_all(p).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp, "12345");
        assert_eq!(entries[0].compiler_id, "yoyo.js");
        assert_eq!(entries[0].input_sha, "abc");

        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn record_roundtrip() {
        let tmp_in = std::env::temp_dir().join("chain_in.bin");
        std::fs::write(&tmp_in, b"input data").unwrap();
        let tmp_out = std::env::temp_dir().join("chain_out.bin");
        std::fs::write(&tmp_out, b"output data").unwrap();

        let entry = record("test-comp", tmp_in.to_str().unwrap(), tmp_out.to_str().unwrap()).unwrap();
        assert_eq!(entry.compiler_id, "test-comp");
        assert_eq!(entry.input_sha.len(), 64);
        assert_eq!(entry.output_sha.len(), 64);

        let _ = std::fs::remove_file(&tmp_in);
        let _ = std::fs::remove_file(&tmp_out);
    }
}
