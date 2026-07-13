//! Minimal PE reader tailored to yoyo's PE layout.
//!
//! Supports two PE variants:
//! 1. **Standard PE**: DOS header at offset 0 with e_lfanew pointing to PE signature,
//!    followed by COFF header, optional header, then section table.
//! 2. **yoyo-js custom**: PE signature at fixed offset 0xF0, .text section header at
//!    fixed offset 0x1F8 (legacy layout from src/pe-builder.js).
//!
//! What this reader does:
//! 1. Try standard PE parsing first.
//! 2. Fall back to yoyo-js custom layout if standard fails.
//! 3. Return raw pointer and raw size of .text section.
//!
//! Also exposes `find_user_code_offset` to heuristically detect where the user
//! code begins within the .text section (after the startup blob).

pub struct TextSection {
    pub file_offset: u64,
    pub size: u64,
}

/// Heuristically detect where the user code begins within the .text section.
///
/// **Primary heuristic**: find the FIRST `c3` (ret) byte in the .text section.
/// The startup blob always ends with a `ret`. User code starts at the byte
/// immediately after.
///
/// This works for all known templates:
/// - yoyo-rust: `sub rsp, 8; call; add rsp, 8; ret` → user code at offset 14
/// - yoyo-asm:  `sub rsp, X; mov r15, rsp; call; add rsp, X; ret` → user code at 23
/// - yoyo-js:   complex koffi startup ending in `ret` → user code at ~547
///
/// **Fallback**: legacy pattern `49 89 C6 E8` (yoyo-js's `mov r14, rax; call H_00`).
/// User code starts 9 bytes after the pattern.
///
/// Returns the byte offset (relative to the start of the .text section) where
/// the user code is expected to start. Returns None if not found.
pub fn find_user_code_offset(text: &[u8]) -> Option<u64> {
    // Primary: first c3 (ret) — user code starts at the next byte
    for i in 0..text.len() {
        if text[i] == 0xc3 {
            return Some((i + 1) as u64);
        }
    }
    // Fallback: legacy yoyo-js pattern 49 89 C6 E8 (mov r14, rax; call)
    if let Some(off) = find_last_pattern(text, &[0x49, 0x89, 0xC6, 0xE8], 9) {
        return Some(off);
    }
    None
}

/// Find the LAST occurrence of `pattern` in `text`, return offset + `offset_after`.
fn find_last_pattern(text: &[u8], pattern: &[u8], offset_after: usize) -> Option<u64> {
    let mut last: Option<u64> = None;
    if pattern.is_empty() || text.len() < pattern.len() {
        return None;
    }
    for i in 0..text.len() - pattern.len() + 1 {
        if &text[i..i + pattern.len()] == pattern {
            last = Some((i + offset_after) as u64);
        }
    }
    last
}

/// Read .text section from a PE file.
///
/// Tries standard PE parsing first (works for yoyo-rust and yoyo-asm outputs).
/// Falls back to yoyo-js custom layout if standard fails.
pub fn read_text_section(file: &[u8]) -> Result<TextSection, String> {
    if file.len() < 0x40 {
        return Err("file too small to be a PE".to_string());
    }

    // Try standard PE parsing first
    if let Ok(sec) = read_text_section_standard(file) {
        return Ok(sec);
    }

    // Fall back to yoyo-js custom layout
    read_text_section_yoyo_js(file)
}

/// Standard PE parser: DOS header at 0, e_lfanew at 0x3C points to PE signature.
fn read_text_section_standard(file: &[u8]) -> Result<TextSection, String> {
    if file.len() < 0x40 {
        return Err("file too small for DOS header".to_string());
    }
    // DOS header e_lfanew at offset 0x3C
    let pe_offset = u32::from_le_bytes([file[0x3C], file[0x3D], file[0x3E], file[0x3F]]) as usize;
    if pe_offset + 24 > file.len() {
        return Err("PE offset out of bounds".to_string());
    }
    // Validate PE signature "PE\0\0"
    if &file[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
        return Err("PE signature not found".to_string());
    }
    // COFF header at pe_offset+4
    let num_sections = u16::from_le_bytes([file[pe_offset + 6], file[pe_offset + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([file[pe_offset + 20], file[pe_offset + 21]]) as usize;
    // Section table starts after optional header
    let sec_table = pe_offset + 24 + opt_header_size;
    if sec_table + num_sections * 40 > file.len() {
        return Err("section table out of bounds".to_string());
    }
    // Find .text section
    for j in 0..num_sections {
        let s = sec_table + j * 40;
        // Section name is 8 bytes
        let name = &file[s..s + 8];
        if name.starts_with(b".text") {
            let raw_size = u32::from_le_bytes([
                file[s + 16],
                file[s + 17],
                file[s + 18],
                file[s + 19],
            ]) as u64;
            let raw_ptr = u32::from_le_bytes([
                file[s + 20],
                file[s + 21],
                file[s + 22],
                file[s + 23],
            ]) as u64;
            if raw_size == 0 {
                return Err(".text section has zero raw size".to_string());
            }
            return Ok(TextSection {
                file_offset: raw_ptr,
                size: raw_size,
            });
        }
    }
    Err(".text section not found in section table".to_string())
}

/// yoyo-js custom layout: PE signature at 0xF0, .text header at 0x1F8.
fn read_text_section_yoyo_js(file: &[u8]) -> Result<TextSection, String> {
    if file.len() < 0x200 {
        return Err("file too small to be a yoyo PE".to_string());
    }
    // PE signature at 0xF0 (yoyo's custom location, not 0x3C)
    if file[0xF0] != 0x50 || file[0xF1] != 0x45 {
        return Err("PE signature not found at 0xF0 (yoyo's custom offset)".to_string());
    }

    // .text section header at 0x1F8 (per src/pe-builder.js line 67: `sh = 0x1F8`)
    const SH: usize = 0x1F8;
    if file.len() < SH + 24 {
        return Err("file too small to contain .text section header".to_string());
    }
    let raw_size = u32::from_le_bytes([
        file[SH + 16],
        file[SH + 17],
        file[SH + 18],
        file[SH + 19],
    ]) as u64;
    let raw_ptr = u32::from_le_bytes([
        file[SH + 20],
        file[SH + 21],
        file[SH + 22],
        file[SH + 23],
    ]) as u64;

    if raw_size == 0 {
        return Err(".text section has zero size".to_string());
    }

    Ok(TextSection {
        file_offset: raw_ptr,
        size: raw_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_text_from_yoyo_js_custom() {
        // yoyo-js uses custom layout with PE at 0xF0
        // Test bytes: MZ header + padding + PE at 0xF0 + section table at 0x1F8
        let mut bytes = vec![0u8; 0x210];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0xF0] = 0x50;
        bytes[0xF1] = 0x45;
        bytes[0xF2] = 0x00;
        bytes[0xF3] = 0x00;
        // .text section header at 0x1F8
        bytes[0x1F8..0x200].copy_from_slice(b".text\0\0\0");
        // raw_size at SH+16
        let raw_size: u32 = 0x8000;
        let raw_ptr: u32 = 0x4000;
        bytes[0x208..0x20C].copy_from_slice(&raw_size.to_le_bytes());
        bytes[0x20C..0x210].copy_from_slice(&raw_ptr.to_le_bytes());
        let section = read_text_section(&bytes).expect("read .text");
        assert_eq!(section.file_offset, 0x4000);
        assert_eq!(section.size, 0x8000);
    }

    #[test]
    fn read_text_from_standard_pe() {
        // Standard PE layout
        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        // e_lfanew at 0x3C = 0x40
        let pe_offset: u32 = 0x40;
        bytes[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        // PE signature at 0x40
        bytes[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        // COFF header at 0x44: num_sections=1 at offset 0x46
        let num_sections: u16 = 1;
        bytes[0x46..0x48].copy_from_slice(&num_sections.to_le_bytes());
        // optional_header_size at 0x54 = 0xE0 (PE32 standard)
        let opt_size: u16 = 0xE0;
        bytes[0x54..0x56].copy_from_slice(&opt_size.to_le_bytes());
        // Section table starts at pe_offset + 24 + opt_size = 0x40 + 0x18 + 0xE0 = 0x138
        let sec_start = 0x40 + 24 + 0xE0;
        // .text section name (8 bytes)
        bytes[sec_start..sec_start + 5].copy_from_slice(b".text");
        // raw_size at sec_start + 16
        let raw_size: u32 = 0x200;
        bytes[sec_start + 16..sec_start + 20].copy_from_slice(&raw_size.to_le_bytes());
        // raw_ptr at sec_start + 20
        let raw_ptr: u32 = 0x200;
        bytes[sec_start + 20..sec_start + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        let section = read_text_section(&bytes).expect("read .text");
        assert_eq!(section.file_offset, 0x200);
        assert_eq!(section.size, 0x200);
    }
}
