//! Phase 5: PE builder — links emitted x64 bytes + IAT fixups into a valid
//! PE32+ executable with import table for kernel32.dll.
//!
//! `FF 15 ii 00 00 00` placeholders (call [rip + api_idx]) are scanned and
//! patched with real RIP-relative displacements to the IAT.

use std::fs;
use std::path::Path;
use crate::platform::{Win32Api, NUM_WIN32_APIS, WIN32_API_NAMES};

// ── PE constants ────────────────────────────────────────────────────

const FILE_ALIGN: u32 = 0x400;
const SECTION_ALIGN: u32 = 0x1000;
const IMAGE_BASE: u64 = 0x0000_0140_0000_0000;  // 5.2 GB (MS default)
const TEXT_RVA: u32 = 0x1000;
const BSS_RVA: u32 = 0x3000;       // .bss section RVA (zero-initialized, R/W)
                                  // Note: in v0.4 (stack-state), BSS is unused; H_00 overwrites r15 with lea rsp+0x800
                                  // We still emit the section so PE linker IAT/relocations work, but its RVA
                                  // overlaps with .text — keep BSS_RVA so any legacy references still compile.
const BSS_VSIZE: u32 = 0x1000;     // 4096 bytes = 256 slots × 16 bytes headroom

/// Win32/Linux startup blob contains `E8` (call) or `E9` (jmp) placeholder.
/// The rel32 offset is patched at link time to point past the startup blob.

/// Post-link validation: scan `.text` for suspicious ModRM patterns.
///
/// Catches the `B6`-class bug: a ModRM byte with Mod=2 (memory+disp32) was
/// used where Mod=3 (register-direct) was intended. The validator flags any
/// REX.W=1 MOV (0x89/0x8B) with ModRM.Mod ∈ {1,2} whose r/m field is NOT
/// R15 (low3=7), because all state memory access goes through R15.
fn validate_code_section(code: &[u8]) -> Result<(), String> {
    let mut i = 0;
    while i < code.len() {
        let b0 = code[i];
        let is_rex_w = (b0 & 0xF0) == 0x40 && (b0 & 0x08) != 0;
        if is_rex_w && i + 3 <= code.len() {
            let op = code[i + 1];
            if op == 0x89 || op == 0x8B {
                let modrm = code[i + 2];
                let mod_ = modrm >> 6;
                let rm = modrm & 7;
                if (mod_ == 1 || mod_ == 2) && rm != 7 {
                    return Err(format!(
                        "validate: offset 0x{:X}: ModRM.Mod={} with base r/m={} (expected r15 low3=7); \
                         REX=0x{:02X} op=0x{:02X} ModRM=0x{:02X}; ctx: {:02X?}",
                        i, mod_, rm, b0, op, modrm,
                        &code[i.saturating_sub(2)..(i + 8).min(code.len())]
                    ));
                }
            }
        }

        // Advance past this instruction
        let skip = instr_len(code, i);
        if skip == 0 { break; }
        i += skip;
    }
    Ok(())
}

/// Decode x64 instruction length at offset `i`.
/// Handles all patterns produced by yoyo's emit + platform modules.
fn instr_len(code: &[u8], i: usize) -> usize {
    if i >= code.len() { return 0; }
    let b0 = code[i];
    let is_rex = (b0 & 0xF0) == 0x40;
    let op = if is_rex { code.get(i + 1).copied().unwrap_or(0) } else { b0 };

    let modrm = code.get(i + if is_rex { 2 } else { 1 }).copied().unwrap_or(0);
    let mod_ = modrm >> 6;
    let rm = modrm & 7;

    if is_rex {
        let base = 3; // REX + opcode + ModRM minimum
        match op {
            0xB8..=0xBF => 10,
            0x89 | 0x8B | 0x01 | 0x09 | 0x19 | 0x29 | 0x39 | 0xAF => {
                match mod_ {
                    3 => base,          // register-direct
                    1 => base + 1,      // disp8
                    2 => base + 4,      // disp32
                    _ => base + if rm == 5 { 4 } else if rm == 4 { 1 } else { 0 },
                }
            }
            0x8D => { // LEA
                match mod_ {
                    3 => base,
                    1 => base + 1,
                    2 => base + 4,
                    _ => base + if rm == 5 { 4 } else if rm == 4 { 1 } else { 0 },
                }
            }
            0x83 | 0x63 => {
                // ALU imm8: base + imm8 + (disp if any)
                base + 1 + match mod_ { 1 => 1, 2 => 4, _ => 0 }
            }
            0x81 => {
                base + 4 + match mod_ { 1 => 1, 2 => 4, _ => 0 }
            }
            0xC7 => {
                // MOV r/m64, imm32
                let disp = match mod_ { 1 => 1, 2 => 4, _ => 0 };
                base + disp + 4 + if rm == 4 { 1 } else { 0 } // SIB if rm=4
            }
            0x0F => {
                let op2 = code.get(i + 2).copied().unwrap_or(0);
                if op2 == 0xAF || op2 == 0xB6 {
                    let mrm = code.get(i + 3).copied().unwrap_or(0);
                    4 + match mrm >> 6 { 1 => 1, 2 => 4, _ => 0 }
                } else { 10 }
            }
            _ => base,
        }
    } else {
        match op {
            0xC3 | 0x90 | 0xCC => 1,
            0xE8 | 0xE9 => 5,
            0xEB => 2,
            0x0F => {
                let op2 = code.get(i + 1).copied().unwrap_or(0);
                if (0x80..=0x8F).contains(&op2) { 6 } else { 2 }
            }
            0xF3 => {
                if code.get(i + 1).copied().unwrap_or(0) == 0xA4 { 2 } else { 2 }
            }
            0x66 => {
                if code.get(i + 1).copied().unwrap_or(0) == 0x90 { 2 } else { 2 }
            }
            _ => 1,
        }
    }
}

/// Build a PE32+ console executable.
///
/// `startup` = platform startup blob. Win32 startup is 24 bytes with two
/// relocatable fields: `mov r15, BSS_ADDR` (8-byte imm64 at offset 6)
/// and `call H_00` (4-byte rel32 at offset 15). Both are patched here.
/// `handler_code` = emitted code for all handlers (H_00 starts at byte 0).
///
/// The function:
/// 1. Patches `startup`'s call-H_00 rel32 and mov-r15 imm64
/// 2. Scans `handler_code` for `FF 15 ii 00 00 00` → collects IAT fixups
/// 3. Builds .text, .idata, .bss sections
/// 4. Builds .idata section with import table for kernel32.dll
/// 5. Patches FF 15 placeholders with correct RIP-relative disp32
/// 6. Validates code section for ModRM errors
/// 7. Writes output PE file
pub fn link(startup: &[u8], handler_code: &[u8], out_path: &Path) -> Result<(), String> {
    let combined = build_text(startup, handler_code);
    let mut code = combined.bytes;
    let text_size = code.len() as u32;

    let fixups = collect_iat_fixups(&code, 0);
    let unique = unique_apis(&fixups);

    let text_vsize = align_up(text_size, SECTION_ALIGN);
    let text_fsize = align_up(text_size, FILE_ALIGN);
    let idata_rva = TEXT_RVA + text_vsize;
    let (idata_bytes, _iat_base_rva) = build_idata(&unique, idata_rva);
    let idata_fsize = align_up(idata_bytes.len() as u32, FILE_ALIGN);
    let idata_vsize = align_up(idata_bytes.len() as u32, SECTION_ALIGN);
    let idata_file_off = HEADERS_SIZE + text_fsize;
    // BSS section RVA: place after .idata to avoid overlap with .text.
    // (v0.4 stack-state doesn't actually use BSS, but the section header
    // is kept for PE compatibility.)
    let bss_rva = align_up(idata_rva + idata_vsize, SECTION_ALIGN);

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

    // Compute SizeOfImage covering all sections (.text + .idata + .bss).
    // Must be the highest RVA + virtual size, aligned to SECTION_ALIGN.
    let size_of_image = align_up(
        std::cmp::max(idata_rva + idata_vsize, bss_rva + BSS_VSIZE)
            .max(TEXT_RVA + text_vsize),
        SECTION_ALIGN,
    );

    // Build PE
    let mut pe = Vec::with_capacity((idata_file_off as usize) + idata_fsize as usize + 0xFF);

    // ── DOS header ──
    pe.resize(0x40, 0);
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x40; // e_lfanew

    // ── PE signature + COFF header ──
    pe.extend(b"PE\x00\x00");
    pe.extend(&0x8664u16.to_le_bytes()); // Machine: x86-64
    pe.extend(&3u16.to_le_bytes());      // NumberOfSections (.text + .idata + .bss)
    pe.extend(&0u32.to_le_bytes());      // TimeDateStamp
    pe.extend(&0u32.to_le_bytes());      // PointerToSymbolTable
    pe.extend(&0u32.to_le_bytes());      // NumberOfSymbols
    let sizeof_opt_hdr: u16 = 240; // Standard PE32+ size
    pe.extend(&sizeof_opt_hdr.to_le_bytes());
    pe.extend(&0x002Fu16.to_le_bytes()); // Characteristics

    // ── Optional header PE32+ ──
    let opt_start = pe.len() as u32;
    pe.extend(&0x020Bu16.to_le_bytes()); // Magic (0x20B = PE32+)
    // 16 zero bytes for: MajorLinkerVersion(1) + MinorLinkerVersion(1) +
    //                    SizeOfCode(4) + SizeOfInitializedData(4) +
    //                    SizeOfUninitializedData(4) + AddressOfEntryPoint(2 of u16 helper below)
    // (We'll back-fill all of these explicitly below.)
    pe.extend(&[0u8; 14]);               // fills up to AddressOfEntryPoint

    // ── Fill in Standard Fields ──
    // SizeOfCode (offset 0x04)
    let soc_off = (opt_start + 0x04) as usize;
    pe.resize(soc_off + 4, 0);
    pe[soc_off..soc_off + 4].copy_from_slice(&text_fsize.to_le_bytes());

    // SizeOfInitializedData (offset 0x08)
    let soid_off = (opt_start + 0x08) as usize;
    pe.resize(soid_off + 4, 0);
    pe[soid_off..soid_off + 4].copy_from_slice(&idata_fsize.to_le_bytes());

    // SizeOfUninitializedData (offset 0x0C) — v0.4: must equal .bss VSize for loader to allocate the page
    let souid_off = (opt_start + 0x0C) as usize;
    pe.resize(souid_off + 4, 0);
    pe[souid_off..souid_off + 4].copy_from_slice(&BSS_VSIZE.to_le_bytes());

    // AddressOfEntryPoint (offset 0x10) = TEXT_RVA (startup code at .text head)
    let eop_off = (opt_start + 0x10) as usize;
    pe.resize(eop_off + 4, 0);
    pe[eop_off..eop_off + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());

    // BaseOfCode (offset 0x14)
    let base_code_off = (opt_start + 0x14) as usize;
    pe.resize(base_code_off + 4, 0);
    pe[base_code_off..base_code_off + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());

    // ImageBase (offset 0x18, u64)
    let img_base_off = (opt_start + 0x18) as usize;
    pe.resize(img_base_off + 8, 0);
    pe[img_base_off..img_base_off + 8].copy_from_slice(&IMAGE_BASE.to_le_bytes());

    // SectionAlignment (offset 0x20)
    let sec_align_off = (opt_start + 0x20) as usize;
    pe.resize(sec_align_off + 4, 0);
    pe[sec_align_off..sec_align_off + 4].copy_from_slice(&SECTION_ALIGN.to_le_bytes());

    // FileAlignment (offset 0x24)
    let file_align_off = (opt_start + 0x24) as usize;
    pe.resize(file_align_off + 4, 0);
    pe[file_align_off..file_align_off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes());

    // ── Windows-Specific Fields ──
    // Major/Minor OS Version (offset 0x28-0x2B). Win64 loader may reject
    // sub-5.2 OS version on console exes — use 6.0 (Win Vista+) which has
    // well-tested ABI behavior.
    let os_ver_off = (opt_start + 0x28) as usize;
    pe.resize(os_ver_off + 4, 0);
    pe[os_ver_off..os_ver_off + 2].copy_from_slice(&6u16.to_le_bytes()); // major 6
    pe[os_ver_off + 2..os_ver_off + 4].copy_from_slice(&0u16.to_le_bytes()); // minor 0

    // Major/Minor Image Version (offset 0x2C-0x2F) — 0.0 is fine
    let img_ver_off = (opt_start + 0x2C) as usize;
    pe.resize(img_ver_off + 4, 0);
    // Already 0 from resize

    // Major/Minor Subsystem Version (offset 0x30-0x33) — Win10+ requires 6.2 minimum
    let subsys_ver_off = (opt_start + 0x30) as usize;
    pe.resize(subsys_ver_off + 4, 0);
    pe[subsys_ver_off..subsys_ver_off + 2].copy_from_slice(&6u16.to_le_bytes());
    pe[subsys_ver_off + 2..subsys_ver_off + 4].copy_from_slice(&2u16.to_le_bytes());

    // Win32VersionValue (offset 0x34) — leave 0 (no extension used)

    // SizeOfImage (offset 0x38) — already computed at function top (incl. .bss)
    let img_size_off = (opt_start + 0x38) as usize;
    pe.resize(img_size_off + 4, 0);
    pe[img_size_off..img_size_off + 4].copy_from_slice(&size_of_image.to_le_bytes());

    // SizeOfHeaders (offset 0x3C)
    let hdr_size_off = (opt_start + 0x3C) as usize;
    pe.resize(hdr_size_off + 4, 0);
    pe[hdr_size_off..hdr_size_off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes());

    // SubSystem (offset 0x44) = 3 (CONSOLE)
    let subsys_off = (opt_start + 0x44) as usize;
    pe.resize(subsys_off + 2, 0);
    pe[subsys_off..subsys_off + 2].copy_from_slice(&3u16.to_le_bytes());

    // DllCharacteristics (offset 0x46) — v0.4: set DYNAMIC_BASE (0x40) + NX_COMPAT (0x100) for Win10
    let dllchars_off = (opt_start + 0x46) as usize;
    pe.resize(dllchars_off + 2, 0);
    pe[dllchars_off..dllchars_off + 2].copy_from_slice(&0x0140u16.to_le_bytes());

    // SizeOfStackReserve (offset 0x48, u64) — increased to 2 MB
    // to accommodate ntdll LFH-initialisation recursion depth.
    let stack_rsv_off = (opt_start + 0x48) as usize;
    pe.resize(stack_rsv_off + 8, 0);
    pe[stack_rsv_off..stack_rsv_off + 8].copy_from_slice(&(2u64 << 20).to_le_bytes());

    // SizeOfStackCommit (offset 0x50, u64) — full 2 MB commit (no guard pages)
    // avoids kernel-stack exhaustion from rapid guard-page faults during LFH init.
    let stack_cmt_off = (opt_start + 0x50) as usize;
    pe.resize(stack_cmt_off + 8, 0);
    pe[stack_cmt_off..stack_cmt_off + 8].copy_from_slice(&(2u64 << 20).to_le_bytes());

    // SizeOfHeapReserve (offset 0x58, u64) — Win64 default 1 MB
    let heap_rsv_off = (opt_start + 0x58) as usize;
    pe.resize(heap_rsv_off + 8, 0);
    pe[heap_rsv_off..heap_rsv_off + 8].copy_from_slice(&(1u64 << 20).to_le_bytes());

    // SizeOfHeapCommit (offset 0x60, u64) — 4 KB initial commit
    let heap_cmt_off = (opt_start + 0x60) as usize;
    pe.resize(heap_cmt_off + 8, 0);
    pe[heap_cmt_off..heap_cmt_off + 8].copy_from_slice(&(4u64 << 10).to_le_bytes());

    // LoaderFlags (offset 0x68, u32) — must be 0 (deprecated field)
    let loader_off = (opt_start + 0x68) as usize;
    pe.resize(loader_off + 4, 0);
    // already 0

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

    // ── Section table (must match NumberOfSections above = 3) ──
    // .text section
    write_section_header(&mut pe, b".text\x00\x00\x00", text_vsize, TEXT_RVA, text_fsize, HEADERS_SIZE, 0x60000020);
    // .idata section
    write_section_header(&mut pe, b".idata\x00\x00", idata_vsize, idata_rva, idata_fsize, idata_file_off, 0xC0000040);
    // .bss section — v0.4: provide FSize=BSS_VSIZE + PointerToRawData=idata_file_off+idata_fsize
    // so the loader actually commits a R/W page. (UNINITIALIZED_DATA + FSize=0 hung on Win10.)
    let bss_file_off = idata_file_off + idata_fsize;
    write_section_header(&mut pe, b".bss\x00\x00\x00\x00", BSS_VSIZE, bss_rva, BSS_VSIZE, idata_file_off + idata_fsize, 0xC0000040);  // v0.4 alt: FSize=BSS_VSIZE + INITIALIZED_DATA + DYNAMIC_BASE + SizeOfUninitializedData  // v0.4 revert: BSS uninit, FSize=0 (BSS isn't actually used for state — argv on stack)

    // Pad to HEADERS_SIZE — must accommodate 3 section headers (was 2):
    //   headers = 0xD8 + 3 * 40 = 0xD8 + 0x78 = 0x150, align to 0x200
    const HEADERS_SIZE_3: u32 = align_up(0xD8 + 3 * 40, FILE_ALIGN);
    pe.resize(HEADERS_SIZE_3 as usize, 0);

    // ── .text section ──
    pe.extend(&code);

    // Pad to file alignment
    let text_end = HEADERS_SIZE_3 + text_fsize;
    pe.resize(text_end as usize, 0);

    // ── .idata section ──
    pe.extend(&idata_bytes);

    // Pad to .idata section file end (file alignment boundary)
    pe.resize(idata_file_off as usize + idata_fsize as usize, 0);

    // .bss section: write 0x1000 zero bytes (BSS_FSIZE) at bss_file_off so loader
    // sees file content backing the section, commits page as PAGE_READWRITE.
    let bss_file_off = idata_file_off as usize + idata_fsize as usize;
    pe.resize(bss_file_off, 0);
    pe.extend(vec![0u8; BSS_VSIZE as usize]);

    // Post-link validation: catch ModRM.Mod errors in code section
    validate_code_section(&code)?;

    Ok(fs::write(out_path, &pe).map_err(|e| format!("write {}: {}", out_path.display(), e))?)
}

// ── Helper functions ────────────────────────────────────────────────

const HEADERS_SIZE: u32 = align_up(0xD8 + 3 * 40, FILE_ALIGN); // = 0x200 (still 0x200 since 3*40=0x78, 0xD8+0x78=0x150, ceil=0x200)

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

    // Scan for call (E8) or jmp (E9) in startup blob and patch rel32.
    // Target = first byte after startup (= start of H_00 handler code).
    for i in 0..startup.len().saturating_sub(5) {
        let b = startup[i];
        if b == 0xE8 || b == 0xE9 {
            let rel32 = startup.len() as i32 - (i as i32 + 5);
            if rel32 != 0 {
                combined[i + 1..i + 5].copy_from_slice(&(rel32 as i32).to_le_bytes());
            }
            break;
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
                15 => Win32Api::GetCommandLineA,
                _ => { i += 6; continue; },
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
        // Skip libyoyo_* APIs: they live in libyoyo.dll which we don't bundle.
        // EXCEPTION: LibyoyoExit (12) maps to kernel32!ExitProcess, which we DO
        // bundle. So include it specifically.
        if api as u8 >= 6 && api as u8 <= 14 && api != Win32Api::LibyoyoExit {
            continue;
        }
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

    // Compute actual by_name block size (hint(2) + name + null) per API
    let by_name_entry_sizes: Vec<u32> = unique.iter().map(|api| {
        let name = WIN32_API_NAMES[*api as usize];
        2 + name.len() as u32 + 1
    }).collect();
    let by_name_total_size: u32 = by_name_entry_sizes.iter().sum();

    // RVA tracking — actual byte order below is:
    //   [0..20]            desc 0 (20B)
    //   [20..40]           desc 1 / terminator (20B)
    //   [40..40+(n+1)*8]   INT (n+1 entries × 8B)
    //   [..iat_rva+(n+1)*8] IAT (n+1 entries × 8B)
    //   [..]+by_name_total_size  by_name entries (n entries × (2+name+1)B)
    //   [+14]              "kernel32.dll\0" (14B)
    let desc_rva = idata_rva;
    let int_rva = desc_rva + 40;
    let iat_rva = int_rva + (n as u32 + 1) * 8;
    // func_names_start = RVA of first by_name entry (immediately after IAT terminator)
    let func_names_start = iat_rva + (n as u32 + 1) * 8;
    // dll_name_rva = RVA of "kernel32.dll" string (immediately after by_name block)
    let dll_name_rva = func_names_start + by_name_total_size;

    // Descriptor 0: kernel32.dll
    bytes.extend_from_slice(&int_rva.to_le_bytes());       // OriginalFirstThunk
    bytes.extend(&0u32.to_le_bytes());                     // TimeDateStamp
    bytes.extend(&0u32.to_le_bytes());                     // ForwarderChain
    bytes.extend(&dll_name_rva.to_le_bytes());             // Name → "kernel32.dll"
    bytes.extend(&iat_rva.to_le_bytes());                  // FirstThunk → IAT

    // Descriptor 1: terminator
    bytes.extend(&[0u8; 20]);

    // INT: n+1 entries (PE32+ IMAGE_THUNK_DATA is 8 bytes per slot)
    for api in unique {
        let hint_name_rva = func_names_start + by_name_entry_offset(unique, *api, n);
        bytes.extend(&(hint_name_rva as u64).to_le_bytes());
    }
    bytes.extend(&0u64.to_le_bytes()); // terminator

    // IAT: n+1 entries (same as INT)
    for api in unique {
        let hint_name_rva = func_names_start + by_name_entry_offset(unique, *api, n);
        bytes.extend(&(hint_name_rva as u64).to_le_bytes());
    }
    bytes.extend(&0u64.to_le_bytes()); // terminator

    // IMAGE_IMPORT_BY_NAME entries: 2 bytes hint + function name + null
    for api in unique {
        bytes.extend(&0u16.to_le_bytes()); // Hint
        let name = WIN32_API_NAMES[*api as usize];
        bytes.extend(name.as_bytes());
        bytes.push(0); // null terminator
    }

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

// ═══════════════════════════════════════════════════════════════════════
// Runtime PE template generator
// ═══════════════════════════════════════════════════════════════════════

/// File alignment for output PE (smaller than gen2's 0x400 to reduce header size)
const OUT_FILE_ALIGN: u32 = 0x200;
/// Headers size = align_up(0x150, 0x200) = 0x200
const OUT_HEADERS_SIZE: u32 = align_up(0xD8 + 3 * 40, OUT_FILE_ALIGN);

/// Patch locations within the PE header template (file offsets).
pub struct PeHeaderPatches {
    pub size_of_code: u32,          // 0x05C
    pub size_of_initialized_data: u32, // 0x060
    pub size_of_image: u32,         // 0x090
    pub import_rva: u32,            // 0x0D0
    pub import_size: u32,           // 0x0D4
    pub text_vsize: u32,            // 0x150
    pub text_rawsize: u32,          // 0x158
    pub idata_vaddr: u32,           // 0x17C
    pub idata_rawsize: u32,         // 0x180
    pub idata_foff: u32,            // 0x184
    pub bss_vaddr: u32,            // 0x1A4
}

/// Pre-computed templates and metadata for building a PE from emitted code at runtime.
pub struct PeOutputInfo {
    pub header: Vec<u8>,                  // 0x200 byte PE header (with placeholder size fields)
    pub startup_stub: Vec<u8>,            // ~35 byte entry stub
    pub idata: Vec<u8>,                   // .idata section template (RVAs relative to .idata start)
    pub idata_rva_fixups: Vec<u32>,       // Offsets in .idata of u32/u64 RVA fields needing idata_rva addition
    pub patches: PeHeaderPatches,
    pub stub_size: u32,
    pub idata_size: u32,
    pub exit_process_iat_off: u32,        // Offset of ExitProcess IAT entry within .idata
    pub iat_rva_base: u32,                // Base offset of IAT entries within .idata
}

/// Return the runtime PE output templates.
pub fn pe_output_template() -> PeOutputInfo {
    // ── Compute .idata layout ──
    let unique_apis = vec![
        Win32Api::VirtualAlloc,   // 0
        Win32Api::CreateFileA,    // 1
        Win32Api::GetFileSize,    // 2
        Win32Api::ReadFile,       // 3
        Win32Api::WriteFile,      // 4
        Win32Api::CloseHandle,    // 5
        Win32Api::LibyoyoExit,    // 12 → "ExitProcess"
    ];
    let n = unique_apis.len();
    // INT start after 2 descriptors = 2 * 20 = 0x28
    let int_rva_base: u32 = 0x28;
    let iat_rva_base: u32 = int_rva_base + (n as u32 + 1) * 8; // +1 for terminator
    // Hint/Name RVAs relative to .idata start
    let mut hint_off = iat_rva_base + (n as u32 + 1) * 8;
    let mut hint_offsets = Vec::new();
    for api in &unique_apis {
        hint_offsets.push(hint_off);
        let name = WIN32_API_NAMES[*api as usize];
        hint_off += 2 + name.len() as u32 + 1;
    }
    let dll_name_off = hint_off;
    let idata_total_len = dll_name_off + 14; // "kernel32.dll\0"
    let idata_size = idata_total_len;

    // ── Build .idata template ──
    let mut idata = Vec::new();
    // Descriptor for kernel32.dll
    idata.extend_from_slice(&int_rva_base.to_le_bytes());        // OriginalFirstThunk
    idata.extend(&0u32.to_le_bytes());                           // TimeDateStamp
    idata.extend(&0u32.to_le_bytes());                           // ForwarderChain
    idata.extend(&dll_name_off.to_le_bytes());                   // Name → "kernel32.dll"
    idata.extend(&iat_rva_base.to_le_bytes());                   // FirstThunk → IAT
    // Terminator descriptor
    idata.extend(&[0u8; 20]);
    // INT: u64 entries (RVAs relative to .idata start)
    for hi in &hint_offsets {
        idata.extend(&(*hi as u64).to_le_bytes());
    }
    idata.extend(&0u64.to_le_bytes()); // terminator
    // IAT: u64 entries (same values)
    for hi in &hint_offsets {
        idata.extend(&(*hi as u64).to_le_bytes());
    }
    idata.extend(&0u64.to_le_bytes()); // terminator
    // Hint/Name entries
    for api in &unique_apis {
        idata.extend(&0u16.to_le_bytes()); // hint
        let name = WIN32_API_NAMES[*api as usize];
        idata.extend(name.as_bytes());
        idata.push(0);
    }
    // DLL name
    idata.extend(b"kernel32.dll");
    idata.push(0);

    // Collect RVA fixup offsets in .idata:
    //   Descriptor 0: [0]=OriginalFirstThunk(u32), [12]=Name(u32), [16]=FirstThunk(u32)
    //   INT entries: [0x28 .. 0x28+(n+1)*8) as u64
    //   IAT entries: [iat_rva_base .. iat_rva_base+(n+1)*8) as u64
    let mut idata_rva_fixups = Vec::new();
    idata_rva_fixups.push(0);   // OriginalFirstThunk (u32)
    idata_rva_fixups.push(12);  // Name (u32)
    idata_rva_fixups.push(16);  // FirstThunk (u32)
    for i in 0..n {
        idata_rva_fixups.push(int_rva_base + (i as u32) * 8); // INT entries (u64)
    }
    for i in 0..n {
        idata_rva_fixups.push(iat_rva_base + (i as u32) * 8); // IAT entries (u64)
    }

    // ExitProcess IAT entry offset within .idata
    let exit_process_idx = 6; // 7th API (0-indexed)
    let exit_process_iat_off = iat_rva_base + (exit_process_idx as u32) * 8;

    // ── Build header template ──
    let mut h = Vec::new();
    // DOS header
    h.resize(0x40, 0);
    h[0] = b'M'; h[1] = b'Z';
    h[0x3C] = 0x40; // e_lfanew

    // PE signature "PE\0\0"
    h.extend(b"PE\x00\x00");

    // COFF header
    h.extend(&0x8664u16.to_le_bytes()); // Machine: x86-64
    h.extend(&3u16.to_le_bytes());      // NumberOfSections: .text + .idata + .bss
    h.extend(&0u32.to_le_bytes());      // TimeDateStamp
    h.extend(&0u32.to_le_bytes());      // PointerToSymbolTable
    h.extend(&0u32.to_le_bytes());      // NumberOfSymbols
    let sizeof_opt_hdr: u16 = 240;      // PE32+
    h.extend(&sizeof_opt_hdr.to_le_bytes());
    h.extend(&0x002Fu16.to_le_bytes()); // Characteristics

    // Optional header PE32+
    let opt_start = h.len() as u32; // = 0x58
    assert_eq!(opt_start, 0x58, "optional header should start at 0x58");
    h.extend(&0x020Bu16.to_le_bytes()); // Magic

    // Fill optional header up to AddressOfEntryPoint (offset 0x10 from opt_start)
    // Standard fields region: linker version (2) + SizeOfCode(4) + SizeOfInitData(4) + SizeOfUninitData(4) + AddressOfEntryPoint(4)
    // = 2 + 4 + 4 + 4 + 4 = 18 bytes
    // We fill first 14 bytes here (up to SizeOfUninitData exclusive), then explicitly set
    h.extend(&[0u8; 14]);

    // SizeOfCode (opt_start + 0x04)
    let soc_off = opt_start + 0x04;
    h.resize((soc_off + 4) as usize, 0);
    h[soc_off as usize..(soc_off + 4) as usize].copy_from_slice(&0u32.to_le_bytes()); // placeholder

    // SizeOfInitializedData (opt_start + 0x08)
    let soid_off = opt_start + 0x08;
    h.resize((soid_off + 4) as usize, 0);
    h[soid_off as usize..(soid_off + 4) as usize].copy_from_slice(&0u32.to_le_bytes()); // placeholder

    // SizeOfUninitializedData (opt_start + 0x0C)
    let souid_off = opt_start + 0x0C;
    h.resize((souid_off + 4) as usize, 0);
    h[souid_off as usize..(souid_off + 4) as usize].copy_from_slice(&BSS_VSIZE.to_le_bytes());

    // AddressOfEntryPoint (opt_start + 0x10) = TEXT_RVA
    let eop_off = opt_start + 0x10;
    h.resize((eop_off + 4) as usize, 0);
    h[eop_off as usize..(eop_off + 4) as usize].copy_from_slice(&TEXT_RVA.to_le_bytes());

    // BaseOfCode (opt_start + 0x14)
    let base_code_off = opt_start + 0x14;
    h.resize((base_code_off + 4) as usize, 0);
    h[base_code_off as usize..(base_code_off + 4) as usize].copy_from_slice(&TEXT_RVA.to_le_bytes());

    // ImageBase (opt_start + 0x18, u64) at offset 0x70
    let img_base_off = opt_start + 0x18;
    h.resize((img_base_off + 8) as usize, 0);
    h[img_base_off as usize..(img_base_off + 8) as usize].copy_from_slice(&IMAGE_BASE.to_le_bytes());

    // SectionAlignment (opt_start + 0x20)
    let sec_align_off = opt_start + 0x20;
    h.resize((sec_align_off + 4) as usize, 0);
    h[sec_align_off as usize..(sec_align_off + 4) as usize].copy_from_slice(&SECTION_ALIGN.to_le_bytes());

    // FileAlignment (opt_start + 0x24)
    let file_align_off = opt_start + 0x24;
    h.resize((file_align_off + 4) as usize, 0);
    h[file_align_off as usize..(file_align_off + 4) as usize].copy_from_slice(&OUT_FILE_ALIGN.to_le_bytes());

    // Major/Minor OS Version (opt_start + 0x28)
    let os_ver_off = opt_start + 0x28;
    h.resize((os_ver_off + 4) as usize, 0);
    h[os_ver_off as usize..(os_ver_off + 2) as usize].copy_from_slice(&6u16.to_le_bytes());
    h[(os_ver_off + 2) as usize..(os_ver_off + 4) as usize].copy_from_slice(&0u16.to_le_bytes());

    // Major/Minor Subsystem Version (opt_start + 0x30)
    let subsys_ver_off = opt_start + 0x30;
    h.resize((subsys_ver_off + 4) as usize, 0);
    h[subsys_ver_off as usize..(subsys_ver_off + 2) as usize].copy_from_slice(&6u16.to_le_bytes());
    h[(subsys_ver_off + 2) as usize..(subsys_ver_off + 4) as usize].copy_from_slice(&2u16.to_le_bytes());

    // SizeOfImage (opt_start + 0x38)
    let img_size_off = opt_start + 0x38;
    h.resize((img_size_off + 4) as usize, 0);
    h[img_size_off as usize..(img_size_off + 4) as usize].copy_from_slice(&0u32.to_le_bytes()); // placeholder

    // SizeOfHeaders (opt_start + 0x3C)
    let hdr_size_off = opt_start + 0x3C;
    h.resize((hdr_size_off + 4) as usize, 0);
    h[hdr_size_off as usize..(hdr_size_off + 4) as usize].copy_from_slice(&OUT_HEADERS_SIZE.to_le_bytes());

    // SubSystem (opt_start + 0x44) = 3 (CONSOLE)
    let subsys_off = opt_start + 0x44;
    h.resize((subsys_off + 2) as usize, 0);
    h[subsys_off as usize..(subsys_off + 2) as usize].copy_from_slice(&3u16.to_le_bytes());

    // DllCharacteristics (opt_start + 0x46)
    let dllchars_off = opt_start + 0x46;
    h.resize((dllchars_off + 2) as usize, 0);
    h[dllchars_off as usize..(dllchars_off + 2) as usize].copy_from_slice(&0x0140u16.to_le_bytes());

    // SizeOfStackReserve (opt_start + 0x48, u64)
    let stack_rsv_off = opt_start + 0x48;
    h.resize((stack_rsv_off + 8) as usize, 0);
    h[stack_rsv_off as usize..(stack_rsv_off + 8) as usize].copy_from_slice(&(2u64 << 20).to_le_bytes());

    // SizeOfStackCommit (opt_start + 0x50, u64)
    let stack_cmt_off = opt_start + 0x50;
    h.resize((stack_cmt_off + 8) as usize, 0);
    h[stack_cmt_off as usize..(stack_cmt_off + 8) as usize].copy_from_slice(&(2u64 << 20).to_le_bytes());

    // SizeOfHeapReserve (opt_start + 0x58, u64)
    let heap_rsv_off = opt_start + 0x58;
    h.resize((heap_rsv_off + 8) as usize, 0);
    h[heap_rsv_off as usize..(heap_rsv_off + 8) as usize].copy_from_slice(&(1u64 << 20).to_le_bytes());

    // SizeOfHeapCommit (opt_start + 0x60, u64)
    let heap_cmt_off = opt_start + 0x60;
    h.resize((heap_cmt_off + 8) as usize, 0);
    h[heap_cmt_off as usize..(heap_cmt_off + 8) as usize].copy_from_slice(&(4u64 << 10).to_le_bytes());

    // LoaderFlags (opt_start + 0x68) = 0
    // NumberOfRvaAndSizes (opt_start + 0x6C) = 2
    let nrvas_off = opt_start + 0x6C;
    h.resize((nrvas_off + 4) as usize, 0);
    h[nrvas_off as usize..(nrvas_off + 4) as usize].copy_from_slice(&2u32.to_le_bytes());

    // Data directory [0]: Export (8 bytes) = 0
    // Already zero from resize

    // Data directory [1]: Import (8 bytes) at opt_start + 0x78
    let import_dir_off = opt_start + 0x78;
    h.resize((import_dir_off + 8) as usize, 0);
    // RVA placeholder (written at runtime)
    h[import_dir_off as usize..(import_dir_off + 4) as usize].copy_from_slice(&0u32.to_le_bytes());
    // Size placeholder
    h[(import_dir_off + 4) as usize..(import_dir_off + 8) as usize].copy_from_slice(&0u32.to_le_bytes());

    // Pad to end of optional header
    let opt_end = (opt_start + sizeof_opt_hdr as u32) as usize;
    h.resize(opt_end, 0);

    // ── Section table ──
    // .text section header at offset 0x148
    let text_sec_off = h.len() as u32;
    write_section_header(&mut h, b".text\x00\x00\x00", 0, TEXT_RVA, 0, OUT_HEADERS_SIZE, 0x60000020);
    // .idata section header at offset 0x170
    let idata_sec_off = h.len() as u32;
    write_section_header(&mut h, b".idata\x00\x00", 0, 0, 0, 0, 0xC0000040);
    // .bss section header at offset 0x198
    let bss_sec_off = h.len() as u32;
    write_section_header(&mut h, b".bss\x00\x00\x00\x00", BSS_VSIZE, 0, BSS_VSIZE, 0, 0xC0000040);

    // Pad to OUT_HEADERS_SIZE
    h.resize(OUT_HEADERS_SIZE as usize, 0);

    // ── Startup stub (placed at .text section start before generated code) ──
    let stub: Vec<u8> = vec![
        // sub rsp, 0x1008
        0x48, 0x81, 0xEC, 0x08, 0x10, 0x00, 0x00,
        // lea r15, [rsp+0x808]
        0x4C, 0x8D, 0xBC, 0x24, 0x08, 0x08, 0x00, 0x00,
        // call generated_code: E8 + rel32 (disp = stub_size - 20 = 35 - 20 = 15 = 0x0F)
        0xE8, 0x0F, 0x00, 0x00, 0x00,
        // add rsp, 0x1008
        0x48, 0x81, 0xC4, 0x08, 0x10, 0x00, 0x00,
        // xor ecx, ecx
        0x31, 0xC9,
        // call ExitProcess via FF 15 (rel32 placeholder = 0x00000000)
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    ];
    let stub_size = stub.len() as u32; // 35

    // ── Patch offsets ──
    let patches = PeHeaderPatches {
        size_of_code: soc_off,
        size_of_initialized_data: soid_off,
        size_of_image: img_size_off,
        import_rva: import_dir_off,
        import_size: import_dir_off + 4,
        text_vsize: text_sec_off + 8,
        text_rawsize: text_sec_off + 12,
        idata_vaddr: idata_sec_off + 4,
        idata_rawsize: idata_sec_off + 8,
        idata_foff: idata_sec_off + 12,
        bss_vaddr: bss_sec_off + 4,
    };

    PeOutputInfo {
        header: h,
        startup_stub: stub,
        idata,
        idata_rva_fixups,
        patches,
        stub_size,
        idata_size,
        exit_process_iat_off,
        iat_rva_base,
    }
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
        // Linux startup: sub rsp,0x1008 (7B) + lea r15,[rsp+0x808] (8B) + jmp +rel32 (5B) = 20B
        let mut startup = vec![
            0x48, 0x81, 0xEC, 0x08, 0x10, 0x00, 0x00, // sub rsp, 0x1008 (7B)
            0x4C, 0x8D, 0xBC, 0x24, 0x08, 0x08, 0x00, 0x00, // lea r15, [rsp+0x808] (8B)
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp +rel32 → H_00 (5B)
        ];
        assert_eq!(startup.len(), 20);
        let handler = vec![0xC3]; // ret
        let result = build_text(&startup, &handler);
        // jmp at offset 15, 5 bytes. rel32 = 20 - (15+5) = 0. jmp to next byte (handler start).
        assert_eq!(result.bytes[16..20], (0i32).to_le_bytes());
        assert_eq!(result.bytes.len(), 21);
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

    #[test]
    fn test_validate_code_section_good() {
        // A mix of valid yoyo-emitted instructions
        let code = vec![
            0x4D, 0x89, 0x77, 0x00, // store_state(0, R14) — R15 disp8, valid
            0x4D, 0x8B, 0x7F, 0x08, // load_state(1, R15) — R15 disp8 dst, valid
            0x4D, 0x89, 0xB7, 0x80, 0x00, 0x00, 0x00, // store_state(16, R14) — R15 disp32, valid
            0x4C, 0x89, 0xEE,       // mov_r_r(Rsi, R13) — register-direct, valid
            0x49, 0x89, 0xC7,       // mov_r_r(R15, Rax) — register-direct, valid
            0xC3,                   // ret
        ];
        assert!(validate_code_section(&code).is_ok(),
            "valid code should pass validation");
    }

    #[test]
    fn test_validate_code_section_b6_bug() {
        // The exact B6-class bug: ModRM.Mod=2 with r/m=6(RSI) instead of r/m=7(R15)
        // Encoding: 4C 89 B6 (mov [rsi+disp32], r14) — REX.W=0,R=1,B=0
        // Wait: this REX has W=0 (0x4C & 0x08 == 0). So validate won't flag it...
        // We need W=1: 4D 89 B6 (REX.W=1,R=1,B=0) — mov [rsi+disp32], r14
        // But our original bug was 4C 89 B6 which doesn't have W=1.
        // Let me construct a W=1 version that's semantically similar:
        // 4D 89 B6 XX XX XX XX — mov [rsi+disp32], r14 (ModRM.Mod=2, r/m=6=RSI, not R15)
        let code = vec![
            0x4D, 0x89, 0xB6, 0x40, 0x00, 0x00, 0x00, // mov [rsi+0x40], r14 (BUG!)
            0xC3, // ret
        ];
        let result = validate_code_section(&code);
        assert!(result.is_err(), "B6-class bug should be detected");
        let err = result.unwrap_err();
        assert!(err.contains("r/m=6"), "error should mention r/m=6 not r15");
        assert!(err.contains("r15"), "error should mention expected r15");
    }

    #[test]
    fn test_validate_code_section_accepts_iat_thunk() {
        // FF 15 (call [rip+disp32]) is the legitimate IAT thunk pattern.
        // Our validator only checks 0x89/0x8B, so FF 15 is silently accepted.
        let code = vec![
            0xFF, 0x15, 0x2A, 0x00, 0x00, 0x00, // call [rip+0x2A]
            0xC3,
        ];
        assert!(validate_code_section(&code).is_ok(),
            "IAT thunk FF 15 should pass validation silently");
    }

    #[test]
    fn test_validate_slot0_r13_store() {
        // store_state(0, R13) = 4D 89 6F 00 — this appeared in AGENTS.md and the actual emit
        let code = vec![0x4D, 0x89, 0x6F, 0x00, 0xC3];
        assert!(validate_code_section(&code).is_ok(),
            "store_state(0, R13) should pass");
    }

    #[test]
    fn test_validate_detects_mov_to_non_r15_base() {
        // mov [r12+disp32], r14: 4D 89 B4 24 XX XX XX XX (SIB: r12 via disp32)
        // Actually: 4D 89 B4 24 — with rm=4 (SIB) and mod=2
        // 4D = REX.W=1,R=1,B=0
        // 89 = MOV
        // B4 = mod=10, reg=110(R14=6), rm=100(SIB)
        // 24 = SIB: scale=00, index=100(SP-none), base=100(RSP)
        // So the base is RSP, not RSI. Let me test a simpler pattern:
        // mov [rdx+disp32], rax: 48 89 82 XX XX XX XX
        let code = vec![0x48, 0x89, 0x82, 0x40, 0x00, 0x00, 0x00, 0xC3];
        let result = validate_code_section(&code);
        assert!(result.is_err(), "MOV to non-R15 base should be flagged");
        assert!(result.unwrap_err().contains("r/m=2"),
            "should mention r/m=2 (RDX)");
    }
}
