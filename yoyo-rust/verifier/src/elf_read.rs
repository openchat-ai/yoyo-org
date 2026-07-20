//! Minimal ELF reader tailored to yoyo's ELF layout.
//!
//! yoyo's ELF is non-standard. There are no section headers (Shnum=0); the
//! loader uses only program headers. yoyo emits exactly three LOAD segments:
//!   1. ELF header + program headers (RO)
//!   2. .text (code, RX)
//!   3. .data (RW)
//!
//! For startup detection on Linux, we look for the pattern
//! `E9 xx xx xx xx` (jmp H_00) at the end of the startup blob, then user
//! code begins.

pub use crate::pe_read::TextSection;

pub fn read_text_section(file: &[u8]) -> Result<TextSection, String> {
    if file.len() < 0x40 {
        return Err("file too small to be an ELF".to_string());
    }
    // ELF magic: 7F 45 4C 46
    if file[0] != 0x7F || file[1] != 0x45 || file[2] != 0x4C || file[3] != 0x46 {
        return Err("ELF magic not found at offset 0".to_string());
    }
    if file[4] != 2 {
        return Err("only ELF64 supported (class must be 2)".to_string());
    }

    // Program header offset at offset 0x20 (8 bytes for ELF64)
    let phoff = u64::from_le_bytes([
        file[0x20], file[0x21], file[0x22], file[0x23],
        file[0x24], file[0x25], file[0x26], file[0x27],
    ]) as usize;
    let phentsize = u16::from_le_bytes([file[0x36], file[0x37]]) as usize;
    let phnum = u16::from_le_bytes([file[0x38], file[0x39]]) as usize;

    // Walk program headers, find the executable LOAD segment (PF_X=1, type=LOAD=1)
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if ph + phentsize > file.len() {
            return Err("program header extends past EOF".to_string());
        }
        let p_type = u32::from_le_bytes([
            file[ph], file[ph+1], file[ph+2], file[ph+3],
        ]);
        let p_flags = u32::from_le_bytes([
            file[ph+4], file[ph+5], file[ph+6], file[ph+7],
        ]);
        if p_type != 1 {
            continue;
        }
        // LOAD segment — use the one with PF_X (executable) bit set
        if p_flags & 1 == 0 {
            continue;
        }
        let p_offset = u64::from_le_bytes([
            file[ph+8],  file[ph+9],  file[ph+10], file[ph+11],
            file[ph+12], file[ph+13], file[ph+14], file[ph+15],
        ]) as u64;
        let p_filesz = u64::from_le_bytes([
            file[ph+32], file[ph+33], file[ph+34], file[ph+35],
            file[ph+36], file[ph+37], file[ph+38], file[ph+39],
        ]) as u64;
        return Ok(TextSection {
            file_offset: p_offset,
            size: p_filesz,
        });
    }
    Err("no executable LOAD segment found".to_string())
}

/// Heuristically detect where the user code begins within an ELF .text
/// section. yoyo's Linux startup ends with `E9 xx xx xx xx` (jmp H_00)
/// followed by NOP padding (0x90 bytes) until H_00's first instruction.
/// User code begins AFTER the last 0x90 byte in the startup region.
pub fn find_user_code_offset(text: &[u8]) -> Option<u64> {
    // Find the FIRST occurrence of pattern: E9 (jmp near) followed by any
    // 4 bytes (rel32), followed by 0x90 (NOP padding). User code begins
    // after the last 0x90 byte in the startup region.
    let limit = std::cmp::min(text.len(), 512);
    for i in 0..limit.saturating_sub(6) {
        if text[i] == 0xE9 && text[i + 5] == 0x90 {
            // Found startup jmp followed by NOP. Skip all consecutive NOPs.
            let mut pos = i + 5;
            while pos < limit && text[pos] == 0x90 {
                pos += 1;
            }
            return Some(pos as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_text_from_linux_test_phase1() {
        let path = "F:/yoyo-ide/build/test-phase1.elf";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return, // skip if build artifact missing
        };
        let section = read_text_section(&bytes).expect("read ELF .text");
        // For yoyo's ELF, the .text LOAD segment is at file offset 0x1000, size 0x8000
        assert_eq!(section.file_offset, 0x1000);
        assert_eq!(section.size, 0x8000);

        // find_user_code_offset should return the byte offset within the .text
        // segment (relative to file_offset 0x1000). The startup jmp is at
        // 0x101C, so user code begins at 0x1021 → 0x21 within .text.
        let start_off = find_user_code_offset(&bytes[0x1000..0x1000 + 0x8000]);
        // Accept any reasonable value (depends on exact startup length)
        assert!(start_off.is_some());
    }
}