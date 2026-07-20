#[derive(Debug, Clone, PartialEq)]
pub struct IsaEntry {
    pub opcode: u16,
    pub mnemonic: String,
    pub args: Vec<String>,
    pub emit_pattern: Vec<String>,
}

pub fn parse_isa_line(line: &str) -> Result<IsaEntry, String> {
    let line = line.split(';').next().unwrap_or("").trim();
    if line.is_empty() {
        return Err("empty line".to_string());
    }
    let parts: Vec<&str> = line.splitn(2, "=>").map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Err("missing '=>' separator".to_string());
    }
    let left = parts[0];
    let right = parts[1];
    let left_tokens: Vec<&str> = left.split_whitespace().collect();
    if left_tokens.len() < 2 {
        return Err("left side needs at least opcode + mnemonic".to_string());
    }
    let opcode_str = left_tokens[0];
    let opcode = opcode_str
        .strip_prefix("0x")
        .and_then(|h| u16::from_str_radix(h, 16).ok())
        .ok_or_else(|| format!("invalid opcode: {opcode_str}"))?;
    let mnemonic = left_tokens[1].to_string();
    let args: Vec<String> = left_tokens[2..].iter().map(|s| s.to_string()).collect();
    let emit_pattern: Vec<String> = right.split_whitespace().map(|s| s.to_string()).collect();
    if emit_pattern.is_empty() {
        return Err("empty emit pattern".to_string());
    }
    Ok(IsaEntry { opcode, mnemonic, args, emit_pattern })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_imm_entry() {
        let e = parse_isa_line(
            "0x0030 SET slot imm => movabs rax imm store_state slot rax",
        )
        .unwrap();
        assert_eq!(e.opcode, 0x30);
        assert_eq!(e.mnemonic, "SET");
        assert_eq!(e.args, vec!["slot", "imm"]);
        assert_eq!(
            e.emit_pattern,
            vec!["movabs", "rax", "imm", "store_state", "slot", "rax"]
        );
    }

    #[test]
    fn parse_ret_entry() {
        let e = parse_isa_line("0x00FF RET => ret").unwrap();
        assert_eq!(e.opcode, 0xFF);
        assert_eq!(e.mnemonic, "RET");
        assert!(e.args.is_empty());
        assert_eq!(e.emit_pattern, vec!["ret"]);
    }

    #[test]
    fn parse_raw_byte_form() {
        let e = parse_isa_line("0x00A1 RAW byte => raw_byte byte").unwrap();
        assert_eq!(e.opcode, 0xA1);
        assert_eq!(e.emit_pattern, vec!["raw_byte", "byte"]);
    }

    #[test]
    fn parse_with_comment() {
        let e =
            parse_isa_line("0x0010 DEF name bytes => raw name bytes ; data definition").unwrap();
        assert_eq!(e.opcode, 0x10);
        assert_eq!(e.mnemonic, "DEF");
        assert_eq!(e.args, vec!["name", "bytes"]);
        assert_eq!(e.emit_pattern, vec!["raw", "name", "bytes"]);
    }

    #[test]
    fn parse_empty_yields_error() {
        assert!(parse_isa_line("").is_err());
        assert!(parse_isa_line("  ; just a comment").is_err());
    }

    #[test]
    fn parse_missing_arrow_errors() {
        assert!(parse_isa_line("0x0030 SET").is_err());
    }

    #[test]
    fn parse_bad_hex_opcode_errors() {
        assert!(parse_isa_line("0xGHIJ BAD => ret").is_err());
    }

    #[test]
    fn parse_unknown_prim_errors() {
        let e = parse_isa_line("0x00FF RET => nonexistent_prim").unwrap();
        assert_eq!(e.emit_pattern, vec!["nonexistent_prim"]);
    }

    #[test]
    fn parse_call_rel32_entry() {
        let e = parse_isa_line("0x0041 CALL hh => call_rel32 hh").unwrap();
        assert_eq!(e.opcode, 0x41);
        assert_eq!(e.mnemonic, "CALL");
        assert_eq!(e.args, vec!["hh"]);
        assert_eq!(e.emit_pattern, vec!["call_rel32", "hh"]);
    }

    #[test]
    fn parse_multiple_entries() {
        let lines = vec![
            "0x0030 SET slot imm => movabs rax imm store_state slot rax",
            "0x00FF RET => ret",
        ];
        let entries: Vec<_> = lines
            .iter()
            .map(|l| parse_isa_line(l).unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].mnemonic, "SET");
        assert_eq!(entries[1].mnemonic, "RET");
    }
}
