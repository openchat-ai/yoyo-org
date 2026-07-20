//! M3: byte-level diff with source-line annotation.
//!
//! Given a .ty source file, yoyo emits the expected x86 bytes. Given
//! a yoyo-produced .exe binary, yoyo extracts the .text section bytes.
//! The two are compared, and any differing byte is annotated with the .ty line
//! that produced it.
//!
//! This is the "gen1 vs gen2 byte difference tells you which .ty line is wrong"
//! feature that bootstrap debugging needs.

use crate::diff::DiffEntry;

/// One byte difference annotated with the source line that produced it.
#[derive(Debug, Clone)]
pub struct AnnotatedDiff {
    pub diff: DiffEntry,
    /// The .ty line number that produced this byte (or 0 if outside user code).
    pub source_line: u32,
    /// The source line text, if available.
    pub source_text: String,
}

/// Given a byte offset within the .text section (after startup skip), find
/// the source line that produced it. Returns the line number and the
/// original text from the source file.
pub fn annotate_offset(
    byte_offset_in_text: u32,
    chunks: &[crate::emit::X86Chunk],
    source_lines: &[crate::ty_parser::SourceLine],
) -> (u32, String) {
    for chunk in chunks {
        let start = chunk.byte_offset;
        let end = start + chunk.bytes.len() as u32;
        if byte_offset_in_text >= start && byte_offset_in_text < end {
            let line = chunk.tir_source_line;
            let text = source_lines
                .iter()
                .find(|s| s.line_no == line)
                .map(|s| format!("Line {}: {:02X}", s.line_no, s.op))
                .unwrap_or_else(|| format!("Line {}", line));
            return (line, text);
        }
    }
    (0, "(outside user code)".to_string())
}

/// Run a diff between two byte streams and annotate each entry with the
/// source line that produced it (using the .ty file).
pub fn annotated_diff(
    bytes_a: &[u8],
    bytes_b: &[u8],
    chunks: &[crate::emit::X86Chunk],
    source_lines: &[crate::ty_parser::SourceLine],
) -> Vec<AnnotatedDiff> {
    let raw = crate::diff::diff(bytes_a, bytes_b);
    raw.into_iter()
        .map(|d| {
            // d.offset is into text_a_aligned. The aligned_chunks have
            // byte_offset shifted by -5 (to align with text_a_aligned).
            // The original chunks had the first chunk (call H_01) at
            // byte_offset=0, so we need to skip past it (saturating_sub
            // already moved chunks with byte_offset=0 to byte_offset=0
            // after the shift, but they're still in the list).
            // For a correct annotation we need the byte_offset AS IF
            // it referenced the original chunks coordinate system.
            // text_a_aligned offset + 5 = original chunks coordinate.
            // But our aligned_chunks already shifted by -5, so we need
            // to add 5 back when looking up.
            let aligned_offset = d.offset;
            let unaligned_offset = aligned_offset + 5; // undo the -5 shift
            let (line, text) = annotate_offset(unaligned_offset, chunks, source_lines);
            AnnotatedDiff {
                diff: d,
                source_line: line,
                source_text: text,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{emit_with_chunks, X86Chunk};
    use crate::tir::{lower, TirOp};
    use crate::ty_parser;

    #[test]
    fn annotate_simple_diff() {
        let src = "30 50 00\n30 51 03";
        let source = ty_parser::parse(src);
        let tir = lower(&source);
        let (bytes, chunks) = emit_with_chunks(&tir);

        // Modify the second SET's imm to introduce a difference
        let mut modified = bytes.clone();
        // The second SET imm is at offset 17 (after first 17-byte SET).
        // The imm64 is bytes 2..10 of that chunk. So we change byte 19.
        modified[19] = 0xFF;

        let diffs = annotated_diff(&bytes, &modified, &chunks, &source);
        // We expect at least one difference in the second SET.
        assert!(!diffs.is_empty());
        for d in &diffs {
            assert!(d.source_line > 0, "expected source line, got {}", d.source_line);
        }
    }
}