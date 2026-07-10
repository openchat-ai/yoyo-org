use std::fs;

/// The golden hash trust root.
/// Stores the verified SHA-256 of the seed compiler (yoyo.js).
#[derive(Debug, Clone)]
pub struct TrustRoot {
    /// SHA-256 of the seed compiler file.
    pub seed_compiler_hash: String,
    /// Human-readable label identifying the trust root.
    pub label: String,
}

const DEFAULT_LABEL: &str = "yoyo.js v2.13 seed compiler";

/// Load trust root from a JSON file.
pub fn load(path: &str) -> Result<TrustRoot, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let get = |key: &str| -> Result<String, String> {
        let pattern = format!(r#""{}":""#, key);
        let start = text.find(&pattern).ok_or_else(|| format!("missing key {key}"))? + pattern.len();
        let end = text[start..].find('"').ok_or_else(|| format!("unterminated value for {key}"))?;
        Ok(text[start..start + end].to_string())
    };
    Ok(TrustRoot {
        seed_compiler_hash: get("hash")?,
        label: get("label").unwrap_or_else(|_| DEFAULT_LABEL.to_string()),
    })
}

/// Save trust root to a JSON file.
pub fn save(path: &str, root: &TrustRoot) -> Result<(), String> {
    let json = format!(
        r#"{{"hash":"{}","label":"{}"}}"#,
        root.seed_compiler_hash, root.label
    );
    fs::write(path, json).map_err(|e| format!("cannot write {path}: {e}"))?;
    Ok(())
}

/// Create a new trust root by computing the SHA-256 of the seed compiler.
pub fn from_seed(seed_path: &str) -> Result<TrustRoot, String> {
    let hash = crate::ddc::sha256_file(seed_path)?;
    Ok(TrustRoot {
        seed_compiler_hash: hash,
        label: DEFAULT_LABEL.to_string(),
    })
}

/// Verify a compiler binary against the trust root.
/// Returns true if the binary's hash matches the trust root's golden hash.
pub fn verify(trust_root: &TrustRoot, compiler_path: &str) -> Result<bool, String> {
    let computed = crate::ddc::sha256_file(compiler_path)?;
    Ok(computed == trust_root.seed_compiler_hash)
}

/// Verify and print a human-readable result.
pub fn verify_report(trust_root_path: &str, compiler_path: &str) -> Result<String, String> {
    let root = load(trust_root_path)?;
    let computed = crate::ddc::sha256_file(compiler_path)?;
    let pass = computed == root.seed_compiler_hash;
    Ok(format!(
        "Trust root: {}\nExpected:   {}\nComputed:   {}\nVerdict:    {}",
        root.label,
        root.seed_compiler_hash,
        computed,
        if pass { "PASS - compiler is authentic" } else { "FAIL - compiler has been modified" },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let root = TrustRoot {
            seed_compiler_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            label: "test".into(),
        };
        let tmp = std::env::temp_dir().join("trust_root_test.json");
        save(tmp.to_str().unwrap(), &root).unwrap();
        let loaded = load(tmp.to_str().unwrap()).unwrap();
        assert_eq!(loaded.seed_compiler_hash, root.seed_compiler_hash);
        assert_eq!(loaded.label, "test");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_seed_roundtrip() {
        let tmp = std::env::temp_dir().join("trust_seed.js");
        std::fs::write(&tmp, b"// seed compiler").unwrap();
        let root = from_seed(tmp.to_str().unwrap()).unwrap();
        assert_eq!(root.seed_compiler_hash.len(), 64);

        let pass = verify(&root, tmp.to_str().unwrap()).unwrap();
        assert!(pass);

        let _ = std::fs::remove_file(&tmp);
    }
}
