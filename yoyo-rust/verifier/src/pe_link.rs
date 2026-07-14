//! Phase 5: PE builder — links emitted x64 bytes + IAT fixups into a valid
//! PE32+ executable with import table for kernel32.dll.
//!
//! `FF 15 ii 00 00 00` placeholders (call [rip + api_idx]) are scanned and
//! patched with real RIP-relative displacements to the IAT.

use std::fs;
use std::path::Path;
use crate::platform::{Win32Api, NUM_WIN32_APIS, WIN32_API_NAMES};

// ── PE constants ────────────────────────────────────────────────────

const FILE_ALIGN: u32 = 0x200;
const SECTION_ALIGN: u32 = 0x1000;
const IMAGE_BASE: u64 = 0x140_0000_0000;
const TEXT_RVA: u32 = 0x1000;

/// Build a PE32+ console executable.
///
/// `startup` = platform startup blob (must end with call/jmp to H_00).
/// `handler_code` = emitted code for all handlers (H_00 starts at byte 0).
///
/// The function:
/// 1. Patches `startup`'s H_00 call rel32 to point to handler_code
/// 2. Scans `handler_code` for `FF 15 ii 00 00 00` → collects IAT fixups
/// 3. Builds .text section = startup + handler_code
/// 4. Builds .idata section with import table for kernel32.dll
/// 5. Patches FF 15 placeholders with correct RIP-relative disp32
/// 6. Writes output PE file
pub fn link(startup: &[u8], handler_code: &[u8], out_path: &Path) -> Result<(), String> {
    let combined = build_text(startup, handler_code);
    let mut code = combined.bytes;
    let text_size = code.len() as u32;

    let fixups = collect_iat_fixups(&code[startup.len()..], startup.len() as u32);
    let unique = unique_apis(&fixups);

    let (idata_bytes, _iat_base_rva) = build_idata(&unique, TEXT_RVA + align_up(text_size, SECTION_ALIGN));

    let text_vsize = align_up(text_size, SECTION_ALIGN);
    let text_fsize = align_up(text_size, FILE_ALIGN);
    let idata_fsize = align_up(idata_bytes.len() as u32, FILE_ALIGN);

    let idata_vsize = align_up(idata_bytes.len() as u32, SECTION_ALIGN);
    let idata_rva = TEXT_RVA + text_vsize;
    let idata_file_off = HEADERS_SIZE + text_fsize;
    let total_size = idata_file_off + idata_fsize;

    // Patch FF 15 placeholders with correct RIP-relative displacements
    for &(code_off, api) in &fixups {
        // code_off is absolute offset in combined code
        // RIP-relative: disp32 = target - (instruction_addr + 6)
        // instruction_addr = TEXT_RVA + code_off
        // target = idata_rva + iat_offset(api)
        let iat_off = iat_entry_offset(&unique, api);
        let iat_rva = idata_rva + iat_off;
        let instr_rva = TEXT_RVA + code_off;
        let disp32 = iat_rva as i64 - (instr_rva as i64 + 6);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            return Err(format!("IAT displacement out of range: {}", disp32));
        }
        let off = code_off as usize + 2; // bytes 2..6 of FF 15 00000000 (rel32 at offset 2)
        // The byte at offset+2 is BOTH the IAT index hint AND the first byte of rel32.
        // The patch overwrites it (as disp32[0]).
        code[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    }

    // Build PE
    let mut pe = Vec::with_capacity((total_size + 0xFF) as usize);

    // ── DOS header ──
    pe.resize(0x40, 0);
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x40; // e_lfanew

    // ── PE signature + COFF header ──
    pe.extend(b"PE\x00\x00");
    pe.extend(&0x8664u16.to_le_bytes()); // Machine: x86-64
    pe.extend(&2u16.to_le_bytes());      // NumberOfSections
    pe.extend(&0u32.to_le_bytes());      // TimeDateStamp
    pe.extend(&0u32.to_le_bytes());      // PointerToSymbolTable
    pe.extend(&0u32.to_le_bytes());      // NumberOfSymbols
    let sizeof_opt_hdr: u16 = 112 + 2 * 8; // PE32+ + 2 data directories (import only)
    pe.extend(&sizeof_opt_hdr.to_le_bytes());
    pe.extend(&0x002Fu16.to_le_bytes()); // Characteristics

    // ── Optional header PE32+ ──
    let opt_start = pe.len() as u32;
    pe.extend(&0x020Bu16.to_le_bytes()); // Magic
    pe.extend(&[0u8; 18]);               // LMajor..SizeOfUninitializedData

    // AddressOfEntryPoint (offset 0x10 from opt_start = file offset will be tracked)
    let eop_off = (opt_start + 0x10) as usize;
    pe.resize(eop_off + 4, 0);
    pe[eop_off..eop_off + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());

    let base_code_off = (opt_start + 0x14) as usize;
    pe.resize(base_code_off + 4, 0);
    pe[base_code_off..base_code_off + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());

    let img_base_off = (opt_start + 0x18) as usize;
    pe.resize(img_base_off + 8, 0);
    pe[img_base_off..img_base_off + 8].copy_from_slice(&IMAGE_BASE.to_le_bytes());

    let sec_align_off = (opt_start + 0x20) as usize;
    pe.resize(sec_align_off + 4, 0);
    pe[sec_align_off..sec_align_off + 4].copy_from_slice(&SECTION_ALIGN.to_le_bytes());

    let file_align_off = (opt_start + 0x24) as usize;
    pe.resize(file_align_off + 4, 0);
    pe[file_align_off..file_align_off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes());

    // SizeOfImage (offset 0x38)
    let img_size_off = (opt_start + 0x38) as usize;
    pe.resize(img_size_off + 4, 0);
    let size_of_image = TEXT_RVA + text_vsize + idata_vsize;
    pe[img_size_off..img_size_off + 4].copy_from_slice(&size_of_image.to_le_bytes());

    // SizeOfHeaders (offset 0x3C)
    let hdr_size_off = (opt_start + 0x3C) as usize;
    pe.resize(hdr_size_off + 4, 0);
    pe[hdr_size_off..hdr_size_off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes());

    // SubSystem (offset 0x44) = 3 (CONSOLE)
    let subsys_off = (opt_start + 0x44) as usize;
    pe.resize(subsys_off + 2, 0);
    pe[subsys_off..subsys_off + 2].copy_from_slice(&3u16.to_le_bytes());

    // NumberOfRvaAndSizes (offset 0x6C)
    let nrvas_off = (opt_start + 0x6C) as usize;
    pe.resize(nrvas_off + 4, 0);
    pe[nrvas_off..nrvas_off + 4].copy_from_slice(&2u32.to_le_bytes()); // 2 data dirs

    // Data directory [1]: Import Directory (offset 0x70 + 1*8)
    let import_dir_off = (opt_start + 0x78) as usize;
    pe.resize(import_dir_off + 8, 0);
    pe[import_dir_off..import_dir_off + 4].copy_from_slice(&idata_rva.to_le_bytes());
    pe[import_dir_off + 4..import_dir_off + 8].copy_from_slice(&(idata_bytes.len() as u32).to_le_bytes());

    // SizeOfStackReserve, SizeOfHeapReserve etc. — default zeros are fine for console exe
    // But we need to pad to the end of optional header
    let opt_end = (opt_start + sizeof_opt_hdr as u32) as usize;
    pe.resize(opt_end, 0);

    // ── Section table ──
    // .text section
    write_section_header(&mut pe, b".text\x00\x00\x00", text_vsize, TEXT_RVA, text_fsize, HEADERS_SIZE, 0x60000020);
    // .idata section
    write_section_header(&mut pe, b".idata\x00\x00", idata_vsize, idata_rva, idata_fsize, idata_file_off, 0xC0000040);

    // Pad to HEADERS_SIZE
    pe.resize(HEADERS_SIZE as usize, 0);

    // ── .text section ──
    pe.extend(&code);

    // Pad to file alignment
    let text_end = HEADERS_SIZE + text_fsize;
    pe.resize(text_end as usize, 0);

    // ── .idata section ──
    pe.extend(&idata_bytes);

    Ok(fs::write(out_path, &pe).map_err(|e| format!("write {}: {}", out_path.display(), e))?)
}

// ── Helper functions ────────────────────────────────────────────────

const HEADERS_SIZE: u32 = align_up(0xD8 + 2 * 40, FILE_ALIGN); // = 0x200

const fn align_up(v: u32, a: u32) -> u32 {
    (v + a - 1) / a * a
}

/// Build the combined .text content from startup blob + handler code.
/// Patches the startup blob's H_00 call/jmp rel32.
struct TextResult {
    bytes: Vec<u8>,
}

fn build_text(startup: &[u8], handler: &[u8]) -> TextResult {
    let mut combined = Vec::with_capacity(startup.len() + handler.len());
    combined.extend_from_slice(startup);
    combined.extend_from_slice(handler);

    // Patch startup blob's H_00 call/jmp rel32.
    // Win32: sub rsp, 8; E8 xx xx xx xx (call rel32); add rsp, 8; ret
    // The call is at offset 4 (5 bytes). rel32 = handler_start - (call_addr + 5)
    //   = startup.len() - (4 + 5) = startup.len() - 9
    //
    // Linux: E9 xx xx xx xx (jmp rel32) at offset 0 (5 bytes).
    //   rel32 = handler_start - (jmp_addr + 5)
    //   = startup.len() - (0 + 5) = startup.len() - 5
    //
    // Detect which pattern: if startup starts with E9 → Linux jmp.
    // If startup starts with 48 83 EC 08 → Win32 call (look for E8 after sub).

    if startup.len() >= 5 {
        if startup[0] == 0xE9 {
            // Linux jmp at offset 0
            let rel32 = startup.len() as i32 - 5;
            if rel32 != 0 {
                combined[1..5].copy_from_slice(&(rel32 as i32).to_le_bytes());
            }
        } else {
            // Win32: find E8 (call) in the startup blob
            for i in 0..startup.len().saturating_sub(4) {
                if startup[i] == 0xE8 {
                    let rel32 = startup.len() as i32 - (i as i32 + 5);
                    if rel32 != 0 {
                        combined[i + 1..i + 5].copy_from_slice(&(rel32 as i32).to_le_bytes());
                    }
                    break;
                }
            }
        }
    }

    TextResult { bytes: combined }
}

/// Write a 40-byte section header.
fn write_section_header(pe: &mut Vec<u8>, name: &[u8; 8], vsize: u32, vaddr: u32,
                        fsize: u32, foff: u32, characteristics: u32) {
    pe.extend_from_slice(name);
    pe.extend(&vsize.to_le_bytes());
    pe.extend(&vaddr.to_le_bytes());
    pe.extend(&fsize.to_le_bytes());
    pe.extend(&foff.to_le_bytes());
    pe.extend(&0u32.to_le_bytes()); // PointerToRelocations
    pe.extend(&0u32.to_le_bytes()); // PointerToLinenumbers
    pe.extend(&0u16.to_le_bytes()); // NumberOfRelocations
    pe.extend(&0u16.to_le_bytes()); // NumberOfLinenumbers
    pe.extend(&characteristics.to_le_bytes());
}

/// Scan `code[code_base..]` for `FF 15 ii 00 00 00` patterns.
/// Returns list of (absolute_code_offset, api).
fn collect_iat_fixups(code: &[u8], code_base: u32) -> Vec<(u32, Win32Api)> {
    let mut fixups = Vec::new();
    let mut i = 0;
    while i + 5 < code.len() {
        if code[i] == 0xFF && code[i + 1] == 0x15
            && code[i + 3] == 0x00 && code[i + 4] == 0x00 && code[i + 5] == 0x00
        {
            let api = match code[i + 2] {
                0 => Win32Api::VirtualAlloc,
                1 => Win32Api::CreateFileA,
                2 => Win32Api::GetFileSize,
                3 => Win32Api::ReadFile,
                4 => Win32Api::WriteFile,
                5 => Win32Api::CloseHandle,
                6 => Win32Api::LibyoyoAlloc,
                7 => Win32Api::LibyoyoFree,
                8 => Win32Api::LibyoyoOpen,
                9 => Win32Api::LibyoyoRead,
                10 => Win32Api::LibyoyoWrite,
                11 => Win32Api::LibyoyoClose,
                12 => Win32Api::LibyoyoExit,
                13 => Win32Api::LibyoyoPrint,
                14 => Win32Api::LibyoyoTime,
                _ => return Vec::new(),
            };
            fixups.push((code_base + i as u32, api));
            i += 6;
        } else {
            i += 1;
        }
    }
    fixups
}

fn unique_apis(fixups: &[(u32, Win32Api)]) -> Vec<Win32Api> {
    let mut seen = [false; NUM_WIN32_APIS];
    let mut result = Vec::new();
    for &(_, api) in fixups {
        let idx = api as usize;
        if !seen[idx] {
            seen[idx] = true;
            result.push(api);
        }
    }
    result
}

/// Offset of an IAT entry within the FirstThunk array (in .idata).
fn iat_entry_offset(unique: &[Win32Api], api: Win32Api) -> u32 {
    for (i, &u) in unique.iter().enumerate() {
        if u == api {
            return 40 + (unique.len() as u32 + 1) * 8 + (i as u32) * 8;
        }
    }
    0
}

/// Build the .idata section bytes.
/// Returns (bytes, iat_base_rva).
fn build_idata(unique: &[Win32Api], idata_rva: u32) -> (Vec<u8>, u32) {
    let n = unique.len();
    let mut bytes = Vec::new();

    // RVA tracking
    let desc_rva = idata_rva;
    let int_rva = desc_rva + 40;
    let iat_rva = int_rva + (n as u32 + 1) * 8;
    // DLL name placed right after by_name entries
    let dll_name_rva = iat_rva + (n as u32 + 1) * 8   // IAT
        + n as u32 * (2 + 11 + 1);    // by_name (VirtualAlloc = longest at 11 chars)

    // Function by_name entries start here
    let func_names_start = dll_name_rva + 14; // "kernel32.dll\0"

    // Descriptor 0: kernel32.dll
    bytes.extend_from_slice(&int_rva.to_le_bytes());       // OriginalFirstThunk
    bytes.extend(&0u32.to_le_bytes());                     // TimeDateStamp
    bytes.extend(&0u32.to_le_bytes());                     // ForwarderChain
    bytes.extend(&dll_name_rva.to_le_bytes());             // Name
    bytes.extend(&iat_rva.to_le_bytes());                  // FirstThunk

    // Descriptor 1: terminator
    bytes.extend(&[0u8; 20]);

    // INT: n+1 entries
    for api in unique {
        let hint_name_rva = func_names_start + by_name_entry_offset(unique, *api, n);
        bytes.extend(&hint_name_rva.to_le_bytes());
    }
    bytes.extend(&0u64.to_le_bytes()); // terminator

    // IAT: n+1 entries (same as INT)
    for api in unique {
        let hint_name_rva = func_names_start + by_name_entry_offset(unique, *api, n);
        bytes.extend(&hint_name_rva.to_le_bytes());
    }
    bytes.extend(&0u64.to_le_bytes()); // terminator

    // IMAGE_IMPORT_BY_NAME entries: 2 bytes hint + function name + null
    let mut by_name_offsets: Vec<u32> = Vec::new();
    for api in unique {
        by_name_offsets.push(bytes.len() as u32);
        bytes.extend(&0u16.to_le_bytes()); // Hint
        let name = WIN32_API_NAMES[*api as usize];
        bytes.extend(name.as_bytes());
        bytes.push(0); // null terminator
    }
    // by_name_entry_offset returns the offset within the by_name block, so meh.

    // DLL name
    bytes.extend(b"kernel32.dll");
    bytes.push(0);

    (bytes, iat_rva)
}

/// Offset of by_name entry relative to func_names_start.
fn by_name_entry_offset(unique: &[Win32Api], target: Win32Api, _n: usize) -> u32 {
    let mut off = 0u32;
    for api in unique {
        if *api == target {
            return off;
        }
        let name = WIN32_API_NAMES[*api as usize];
        off += 2 + name.len() as u32 + 1; // hint(2) + name + null
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_iat_fixups_none() {
        let code = vec![0x90, 0xC3];
        let fixups = collect_iat_fixups(&code, 20);
        assert!(fixups.is_empty());
    }

    #[test]
    fn collect_iat_fixups_one() {
        let mut code = vec![0x48, 0x83, 0xEC, 0x08];
        code.extend(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        code.push(0xC3);
        let fixups = collect_iat_fixups(&code, 0);
        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].0, 4);
        assert_eq!(fixups[0].1, Win32Api::VirtualAlloc);
    }

    #[test]
    fn collect_iat_fixups_multiple() {
        let code = vec![
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x90,
            0xFF, 0x15, 0x01, 0x00, 0x00, 0x00,
        ];
        let fixups = collect_iat_fixups(&code, 0);
        assert_eq!(fixups.len(), 2);
        assert_eq!(fixups[0].1, Win32Api::VirtualAlloc);
        assert_eq!(fixups[1].1, Win32Api::CreateFileA);
    }

    #[test]
    fn collect_iat_fixups_skips_non_placeholder() {
        let code = vec![0xFF, 0x15, 0x00, 0x01, 0x00, 0x00];
        let fixups = collect_iat_fixups(&code, 0);
        assert!(fixups.is_empty());
    }

    #[test]
    fn unique_apis_deduplicates() {
        let fixups = vec![
            (0, Win32Api::VirtualAlloc),
            (6, Win32Api::CreateFileA),
            (12, Win32Api::VirtualAlloc),
            (18, Win32Api::CloseHandle),
        ];
        let unique = unique_apis(&fixups);
        assert_eq!(unique.len(), 3);
        assert_eq!(unique[0], Win32Api::VirtualAlloc);
        assert_eq!(unique[1], Win32Api::CreateFileA);
        assert_eq!(unique[2], Win32Api::CloseHandle);
    }

    #[test]
    fn iat_entry_offset_single() {
        let unique = vec![Win32Api::VirtualAlloc];
        // offset = 40 (descriptors) + (1+1)*8 (INT) + 0*8 (first IAT entry)
        assert_eq!(iat_entry_offset(&unique, Win32Api::VirtualAlloc), 40 + 16);
    }

    #[test]
    fn iat_entry_offset_second() {
        let unique = vec![Win32Api::CreateFileA, Win32Api::VirtualAlloc];
        assert_eq!(iat_entry_offset(&unique, Win32Api::CreateFileA), 40 + 24);
        assert_eq!(iat_entry_offset(&unique, Win32Api::VirtualAlloc), 40 + 24 + 8);
    }

    #[test]
    fn build_text_linux_startup() {
        let startup = vec![0xE9, 0x00, 0x00, 0x00, 0x00]; // jmp H_00
        let handler = vec![0xC3]; // ret
        let result = build_text(&startup, &handler);
        // jmp at offset 0, 5 bytes. rel32 = 5 - 5 = 0. Wait: startup.len() - 5 = 5 - 5 = 0
        // So rel32 should remain 0 because startup.len() = 5 and handler starts right after.
        // Actually rel32 = startup.len() - 5 = 0. That makes sense - jmp to next byte.
        assert_eq!(result.bytes, vec![0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    }

    #[test]
    fn build_text_win32_startup() {
        // sub rsp, 8; call rel32; add rsp, 8; ret = 14 bytes
        let startup = vec![
            0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
            0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
            0x48, 0x83, 0xC4, 0x08, // add rsp, 8
            0xC3, // ret
        ];
        let handler = vec![0x90]; // nop (H_00 = nop)
        let result = build_text(&startup, &handler);
        // startup.len() = 14. call at offset 4, 5 bytes. rel32 = 14 - (4+5) = 5.
        assert_eq!(result.bytes[5..9], (5i32).to_le_bytes());
        assert_eq!(result.bytes.len(), 15);
    }

    #[test]
    fn idata_structure_virtual_alloc_only() {
        let unique = vec![Win32Api::VirtualAlloc];
        let (bytes, _iat_rva) = build_idata(&unique, 0x2000);
        // Should contain "kernel32.dll"
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("kernel32.dll"), "should contain dll name");
        assert!(s.contains("VirtualAlloc"), "should contain function name");
        // Size sanity
        assert!(bytes.len() > 40, "should have descriptors");
    }

    #[test]
    fn idata_structure_two_apis() {
        let unique = vec![Win32Api::CreateFileA, Win32Api::CloseHandle];
        let (bytes, _) = build_idata(&unique, 0x2000);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("CreateFileA"));
        assert!(s.contains("CloseHandle"));
    }

    #[test]
    fn link_creates_valid_pe() {
        let startup = vec![
            0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
            0xE8, 0x00, 0x00, 0x00, 0x00, // call H_00
            0x48, 0x83, 0xC4, 0x08, // add rsp, 8
            0xC3, // ret
        ];
        let handler = vec![
            // H_00: VirtualAlloc(0, 0x1000, 0x3000, 0x40)
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
            0x48, 0xBA, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0x1000
            0x49, 0xB8, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, 0x3000
            0x49, 0xB9, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r9, 0x40
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call [rip+0] → VirtualAlloc via IAT
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
            0x4D, 0x89, 0x47, 0x20, // mov [r15+0x20], rax (store in state[4])
            0xC3, // ret
        ];
        let tmp = std::env::temp_dir().join("yoyo-link-iat-test.exe");
        link(&startup, &handler, &tmp).expect("link should succeed");
        let linked = fs::read(&tmp).expect("read linked file");
        // Verify it's a valid PE
        assert_eq!(&linked[0..2], b"MZ", "should have MZ header");
        assert_eq!(&linked[0x40..0x44], b"PE\x00\x00", "should have PE signature");
        // Verify the FF 15 placeholder was patched (IAT displacement non-zero).
        // Search for the FF 15 pattern in the output and verify disp32 is patched.
        let combined_ff15_off = (startup.len()..linked.len() - 6)
            .find(|&i| linked[i] == 0xFF && linked[i + 1] == 0x15)
            .expect("FF 15 pattern should exist in linked output");
        let disp32_off = combined_ff15_off + 2;
        let disp32 = i32::from_le_bytes([
            linked[disp32_off],
            linked[disp32_off + 1],
            linked[disp32_off + 2],
            linked[disp32_off + 3],
        ]);
        assert_ne!(disp32, 0, "IAT displacement should be patched, got 0");
        assert!(disp32 > 0, "IAT disp32 should be positive: {}", disp32);

        // Check the import directory
        let total_code_size = (startup.len() + handler.len()) as u32;
        let idata_file_off = HEADERS_SIZE + align_up(total_code_size, FILE_ALIGN);
        let idata_slice = &linked[idata_file_off as usize..];
        assert!(
            idata_slice.windows(12).any(|w| w == b"kernel32.dll"),
            "should contain kernel32.dll in .idata"
        );

        fs::remove_file(&tmp).ok();
    }
}
