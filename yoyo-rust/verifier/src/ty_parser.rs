//! Layer 1: .ty source parser.
//!
// A .ty file is a sequence of ASCII lines. Each non-empty, non-comment line is
//! one yoyo instruction, written as space-separated hex tokens. Comments start
//! with `;` or `#`. This parser produces a flat list of `SourceLine`s.

/// A single non-empty, non-comment .ty line.
#[derive(Debug, Clone)]
pub struct SourceLine {
    pub line_no: u32,   // 1-indexed
    pub op: u8,
    pub args: Vec<u64>, // arg tokens parsed as u64
}

pub fn parse(src: &str) -> Vec<SourceLine> {
    parse_inner(src, None)
}

/// Parse with a variable table for named slot resolution.
pub fn parse_with_vars(src: &str, vars: &crate::variable::VarTable) -> Vec<SourceLine> {
    parse_inner(src, Some(vars))
}

fn parse_inner(src: &str, vars: Option<&crate::variable::VarTable>) -> Vec<SourceLine> {
    let mut out = Vec::new();
    for (idx, raw_line) in src.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip comments: `;` or `#` to end of line
        let body = strip_comment(trimmed);
        if body.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = body.split_whitespace().collect();
        // Skip variable definition lines (name = hex_value)
        if tokens.len() >= 3 && tokens[1] == "=" {
            continue;
        }
        // 24-bit opcode (v3 Part 4.1): 3 bytes hi/mid/low. hi=mid=0 required.
        // Fall back to 1-byte opcode (legacy) for backward compatibility.
        let (op, args_offset) = if tokens.len() >= 3 {
            let b0 = match parse_hex_byte(tokens[0]) {
                Some(b) => b,
                None => panic!("line {}: invalid opcode byte {:?} (expected 2-hex-digit)", line_no, tokens[0]),
            };
            let b1 = match parse_hex_byte(tokens[1]) {
                Some(b) => b,
                None => panic!("line {}: invalid mid-byte {:?}", line_no, tokens[1]),
            };
            let b2 = match parse_hex_byte(tokens[2]) {
                Some(b) => b,
                None => panic!("line {}: invalid low-byte {:?}", line_no, tokens[2]),
            };
            if b0 != 0 || b1 != 0 {
                panic!("line {}: 24-bit opcode must be 0x00 in hi/mid bytes (per v3 Part 4.1); got {:02x}{:02x}", line_no, b0, b1);
            }
            (b2, 3)  // low byte is the actual opcode
        } else {
            // 1-byte legacy opcode
            let b = match parse_hex_byte(tokens[0]) {
                Some(b) => b,
                None => panic!("line {}: invalid opcode token {:?} (expected 2-hex-digit byte)", line_no, tokens[0]),
            };
            (b, 1)
        };
        // Skip arg parsing for data-definition opcodes (0x12 str, 0x13 raw bytes)
        // — they may contain `s<hex>` string tokens longer than 16 chars.
        if op == 0x12 || op == 0x13 {
            out.push(SourceLine { line_no, op, args: Vec::new() });
            continue;
        }
        let mut args = Vec::with_capacity(tokens.len().saturating_sub(args_offset));
        for t in &tokens[args_offset..] {
            let val = if let Some(vars) = vars {
                vars.try_parse(t).unwrap_or_else(|e| panic!(
                    "line {}: {}", line_no, e
                ))
            } else {
                parse_hex_u64(t).unwrap_or_else(|| panic!(
                    "line {}: invalid arg token {:?}", line_no, t
                ))
            };
            args.push(val);
        }
        out.push(SourceLine { line_no, op, args });
    }
    out
}

/// Extract variable definitions from source (lines with `name = hex_value`).
/// Recognizes `name = hex` where name is an ident and hex is a hex literal.
pub fn extract_var_defs(src: &str) -> crate::variable::VarTable {
    let mut vars = crate::variable::VarTable::new();
    for (idx, raw_line) in src.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let body = strip_comment(trimmed);
        if body.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = body.split_whitespace().collect();
        if tokens.len() >= 3 && tokens[1] == "=" {
            let name = tokens[0];
            // Validate name is a valid identifier
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                panic!("line {}: invalid variable name '{name}'", line_no);
            }
            // Parse the value (support up to 16 hex digits)
            let val_str = tokens[2];
            let val = crate::variable::parse_hex_any(val_str)
                .unwrap_or_else(|| panic!("line {}: invalid hex value '{val_str}'", line_no));
            vars.define(name, val);
        }
    }
    vars
}

fn strip_comment(s: &str) -> &str {
    // Comment starts at first `;` or `#` (when not inside a hex literal)
    // For our purposes, hex tokens never contain `;` or `#`, so a simple
    // byte search is sufficient.
    for (i, ch) in s.char_indices() {
        if ch == ';' || ch == '#' {
            return &s[..i];
        }
    }
    s
}

fn parse_hex_byte(s: &str) -> Option<u8> {
    if s.len() != 2 {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    // Allow up to 16 hex digits (u64). Also accept a leading `s` for string
    // literals (opcode 0x12/0x13 use `12 s<hex>` form to embed string data).
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
    fn parse_simple_set() {
        let src = "30 50 00";
        let lines = parse(src);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[0].op, 0x30);
        assert_eq!(lines[0].args, vec![0x50, 0x00]);
    }

    #[test]
    fn parse_skip_comment() {
        let src = "30 50 00 ; state_50 = 0\n# full line comment\n41 01";
        let lines = parse(src);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].op, 0x30);
        assert_eq!(lines[1].op, 0x41);
    }

    #[test]
    fn parse_64bit_arg() {
        // 8-byte hex (state bits for 1.5 in IEEE 754)
        let src = "30 50 3ff8000000000000";
        let lines = parse(src);
        assert_eq!(lines[0].op, 0x30);
        assert_eq!(lines[0].args, vec![0x50, 0x3ff8000000000000]);
    }
}