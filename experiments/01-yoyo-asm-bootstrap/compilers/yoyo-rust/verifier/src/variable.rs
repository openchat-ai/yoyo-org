/// Named variable table: resolves names to u64 values.
#[derive(Debug, Clone)]
pub struct VarTable {
    entries: Vec<(String, u64)>,
}

impl VarTable {
    pub fn new() -> Self {
        VarTable { entries: Vec::new() }
    }

    pub fn define(&mut self, name: &str, value: u64) {
        // Update if already defined
        for e in &mut self.entries {
            if e.0 == name {
                e.1 = value;
                return;
            }
        }
        self.entries.push((name.to_string(), value));
    }

    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.entries.iter().find(|e| e.0 == name).map(|e| e.1)
    }

    /// Try to parse a token: first as hex u64, then as a named variable.
    pub fn try_parse(&self, token: &str) -> Result<u64, String> {
        // Try hex first
        if let Some(val) = parse_hex_any(token) {
            return Ok(val);
        }
        // Try named variable
        if let Some(val) = self.resolve(token) {
            return Ok(val);
        }
        Err(format!("cannot parse '{token}' as hex u64 or named variable"))
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, u64)> {
        self.entries.iter()
    }
}

/// Parse a hex string of any length (1 to 16 hex digits).
/// Returns None if not valid hex.
pub fn parse_hex_any(s: &str) -> Option<u64> {
    let stripped = s.strip_prefix('s').unwrap_or(s);
    if stripped.is_empty() || stripped.len() > 16 {
        return None;
    }
    u64::from_str_radix(stripped, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn define_and_resolve() {
        let mut vt = VarTable::new();
        vt.define("counter", 0x50);
        vt.define("buf", 0x51);
        assert_eq!(vt.resolve("counter"), Some(0x50));
        assert_eq!(vt.resolve("buf"), Some(0x51));
        assert_eq!(vt.resolve("nonexistent"), None);
    }

    #[test]
    fn update_existing() {
        let mut vt = VarTable::new();
        vt.define("x", 0x10);
        vt.define("x", 0x20);
        assert_eq!(vt.resolve("x"), Some(0x20));
    }

    #[test]
    fn try_parse_hex() {
        let vt = VarTable::new();
        assert_eq!(vt.try_parse("50").unwrap(), 0x50);
        assert_eq!(vt.try_parse("3ff8000000000000").unwrap(), 0x3ff8000000000000);
        assert!(vt.try_parse("ZZ").is_err());
    }

    #[test]
    fn try_parse_named() {
        let mut vt = VarTable::new();
        vt.define("counter", 0x50);
        assert_eq!(vt.try_parse("counter").unwrap(), 0x50);
        assert_eq!(vt.try_parse("50").unwrap(), 0x50); // hex still works
    }

    #[test]
    fn parse_hex_any_edge_cases() {
        assert_eq!(parse_hex_any("0"), Some(0));
        assert_eq!(parse_hex_any("FF"), Some(0xFF));
        assert_eq!(parse_hex_any("FFFFFFFFFFFFFFFF"), Some(0xFFFFFFFFFFFFFFFF));
        assert_eq!(parse_hex_any(""), None);
        assert_eq!(parse_hex_any("GG"), None);
    }
}
