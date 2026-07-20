//! Byte-level diff between two byte sequences.
//!
//! Reports the first N differing positions with context. Used by M2 to compare
//! the .text section of two yoyo-produced binaries (e.g. gen1 vs gen2 for
//! bootstrap debugging).

#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub offset: u32,
    pub byte_a: u8,
    pub byte_b: u8,
}

pub fn diff(a: &[u8], b: &[u8]) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    let len = std::cmp::min(a.len(), b.len());
    for i in 0..len {
        if a[i] != b[i] {
            out.push(DiffEntry {
                offset: i as u32,
                byte_a: a[i],
                byte_b: b[i],
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn diff_one_byte() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 9, 3, 4];
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].offset, 1);
        assert_eq!(d[0].byte_a, 2);
        assert_eq!(d[0].byte_b, 9);
    }

    #[test]
    fn diff_length_mismatch() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4];
        let d = diff(&a, &b);
        // Only the common prefix is diffed; length difference is not reported
        // in this minimal version. Caller can compare lengths separately.
        assert!(d.is_empty());
    }
}