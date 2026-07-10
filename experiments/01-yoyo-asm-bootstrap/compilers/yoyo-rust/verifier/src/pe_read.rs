//! Minimal PE reader tailored to yoyo's PE layout.
//!
//! yoyo's PE is non-standard. The PE signature is at 0xF0 (not 0x3C) and the
//! .text section header is at 0x1F8 (not the standard COFF section table).
//! The section table entries in the COFF header are scrambled and should not be
//! trusted. See src/pe-builder.js for the layout that yoyo emits.
//!
//! What this reader does:
//! 1. Validate PE signature at 0xF0.
//! 2. Hard-code the .text section header offset at 0x1F8 (per yoyo's
//!    pe-builder.js).
//! 3. Read raw pointer and raw size.

pub struct TextSection {
    pub file_offset: u64,
    pub size: u64,
}

/// Heuristically detect where the user code begins within the .text section.
/// yoyo's startup blob ends with: `mov r14, rax; call H_00` (i.e.
/// `49 89 C6 E8 ...`). After that call, the user code (H_00, the first
/// handler) starts.
///
/// We look for the LAST `49 89 C6 E8` (4 bytes) sequence in the text section,
/// then return the offset after the call instruction. The call is 5 bytes
/// (`E8 XX XX XX XX`), so user code starts at `i + 4 + 5 = i + 9`.
///
/// Returns the byte offset (relative to the start of the .text section) where
/// the user code is expected to start. Returns None if not found.
pub fn find_user_code_offset(text: &[u8]) -> Option<u64> {
    // The pattern: 49 89 C6 (mov r14, rax) followed by E8 (call) and 4-byte
    // rel32. After the call, user code begins.
    // Find the LAST occurrence.
    let mut last: Option<u64> = None;
    for i in 0..text.len().saturating_sub(9) {
        if text[i] == 0x49 && text[i + 1] == 0x89 && text[i + 2] == 0xC6
            && text[i + 3] == 0xE8
        {
            // i+3 is the E8, rel32 is i+4..i+8, after call is i+9
            last = Some((i + 9) as u64);
        }
    }
    last
}

pub fn read_text_section(file: &[u8]) -> Result<TextSection, String> {
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
    fn read_text_from_test_phase1() {
        let path = "F:/yoyo-ide/build/test-phase1.exe";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return, // skip if build artifact missing
        };
        let section = read_text_section(&bytes).expect("read .text");
        // For yoyo's test-phase1.exe: .text starts at file offset 0x400, size 0x8000
        assert_eq!(section.file_offset, 0x400);
        assert_eq!(section.size, 0x8000);
    }
}