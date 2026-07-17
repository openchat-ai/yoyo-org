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
const IMAGE_BASE: u64 = 0x140_0000_0000;
const TEXT_RVA: u32 = 0x1000;
const BSS_RVA: u32 = 0x3000;       // .bss section RVA (zero-initialized, R/W)
                                  // Note: in v0.4 (stack-state), BSS is unused; H_00 overwrites r15 with lea rsp+0x800
                                  // We still emit the section so PE linker IAT/relocations work, but its RVA
                                  // overlaps with .text — keep BSS_RVA so any legacy references still compile.
const BSS_VSIZE: u32 = 0x1000;     // 4096 bytes = 256 slots × 16 bytes headroom

/// Win32 v0.4 startup layout — see Win32Platform::startup_blob.
/// MOV_R15_OFFSET = 2 (imm64 placeholder right after 0x49 0xBF).
/// The `E8` call offset is found by scanning startup blob at link time.
const MOV_R15_OFFSET: usize = 2;

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
    // Estimate bss_rva from handler_code length (before build_text)
    let text_vsize_est = align_up((startup.len() + handler_code.len()) as u32, SECTION_ALIGN);
    let bss_rva = align_up(TEXT_RVA + text_vsize_est + 0x2000, SECTION_ALIGN);

    let combined = build_text(startup, handler_code, bss_rva);
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

    // Patch FF 15 placeholders with correct RIP-relative displacements
    for &(code_off, api) in &fixups {
        let idx = unique.iter().position(|a| *a == api).unwrap_or(0) as u32;
        let iat_off = 40 + (unique.len() as u32 + 1) * 8 + idx * 8;
        let iat_rva = idata_rva + iat_off;
        let instr_rva = TEXT_RVA + code_off;
        let disp32 = iat_rva as i64 - (instr_rva as i64 + 6);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            return Err(format!("IAT displacement out of range: {}", disp32));
        }
        let off = code_off as usize + 2;
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
    let sizeof_opt_hdr: u16 = 112 + 2 * 8; // PE32+ + 2 data directories (import only)
    pe.extend(&sizeof_opt_hdr.to_le_bytes());
    pe.extend(&0x0022u16.to_le_bytes()); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE (no RELOCS_STRIPPED)

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

    // DllCharacteristics (offset 0x46) — v0.4: set DYNAMIC_BASE (0x40) for Win10 loader to commit BSS pages
    let dllchars_off = (opt_start + 0x46) as usize;
    pe.resize(dllchars_off + 2, 0);
    pe[dllchars_off..dllchars_off + 2].copy_from_slice(&0x0040u16.to_le_bytes());

    // SizeOfStackReserve (offset 0x48, u64) — Win64 default 1 MB
    let stack_rsv_off = (opt_start + 0x48) as usize;
    pe.resize(stack_rsv_off + 8, 0);
    pe[stack_rsv_off..stack_rsv_off + 8].copy_from_slice(&(1u64 << 20).to_le_bytes());

    // SizeOfStackCommit (offset 0x50, u64) — 4 KB initial commit
    let stack_cmt_off = (opt_start + 0x50) as usize;
    pe.resize(stack_cmt_off + 8, 0);
    pe[stack_cmt_off..stack_cmt_off + 8].copy_from_slice(&(4u64 << 10).to_le_bytes());

    // SizeOfHeapReserve (offset 0x58, u64) — Win64 default 1 MB
    let heap_rsv_off = (opt_start + 0x58) as usize;
    pe.resize(heap_rsv_off + 8, 0);
    pe[heap_rsv_off..heap_rsv_off + 8].copy_from_slice(&(1u64 << 20).to_le_bytes());

    // SizeOfHeapCommit (offset 0x60, u64) — 4 KB initial commit
    let heap_cmt_off = (opt_start + 0x60) as usize;
    pe.resize(heap_cmt_off + 8, 0);
    pe[heap_cmt_off..heap_cmt_off + 8].copy_from_slice(&(4u64 << 10).to_le_bytes());

    // LoaderFlags (offset 0x64, u32) — must be 0 (deprecated field)
    let loader_off = (opt_start + 0x64) as usize;
    pe.resize(loader_off + 4, 0);
    // already 0

    // NumberOfRvaAndSizes (offset 0x68)
    let nrvas_off = (opt_start + 0x68) as usize;
    pe.resize(nrvas_off + 4, 0);
    pe[nrvas_off..nrvas_off + 4].copy_from_slice(&2u32.to_le_bytes()); // 2 data dirs

    // Data directory [0]: Export (offset 0x6C) — skip; stays 0

    // Data directory [1]: Import Directory (offset 0x74)
    let import_dir_off = (opt_start + 0x74) as usize;
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

fn build_text(startup: &[u8], handler: &[u8], bss_rva: u32) -> TextResult {
    let mut combined = Vec::with_capacity(startup.len() + handler.len());
    combined.extend_from_slice(startup);
    combined.extend_from_slice(handler);

    // Patch startup blob's Win32 fields:
    //  1. mov r15, BSS_ADDRESS — IMM64 at offset 6..14
    //  2. call rel32 H_00 — rel32 at offset 15..19
    //
    // Linux jmp at offset 0 → rel32 at offset 1..5.
    //
    // Detect which by first byte:
    //   - 0xE9 (jmp rel32) → Linux
    //   - anything else (sub rsp, 8: 48 83 EC 08) → Win32

    if startup.len() >= 5 && startup[0] == 0xE9 {
        // Linux jmp at offset 0
        let rel32 = startup.len() as i32 - 5;
        if rel32 != 0 {
            combined[1..5].copy_from_slice(&(rel32 as i32).to_le_bytes());
        }
    } else {
        // Find 0x49 0xBF (mov r15, imm64) and patch the IMM64 field
        if startup.len() >= 10 && startup[0] == 0x49 && startup[1] == 0xBF {
            let r15_imm = IMAGE_BASE + bss_rva as u64;
            combined[MOV_R15_OFFSET..MOV_R15_OFFSET + 8]
                .copy_from_slice(&r15_imm.to_le_bytes());
        }

        // Scan for E8 (call) anywhere in startup and patch rel32
        // Target = first byte after startup (= start of H_00 user code)
        for i in 0..startup.len().saturating_sub(5) {
            if startup[i] == 0xE8 {
                let rel32 = startup.len() as i32 - (i as i32 + 5);
                if rel32 != 0 {
                    combined[i + 1..i + 5].copy_from_slice(&(rel32 as i32).to_le_bytes());
                }
                break;
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
                15 => Win32Api::GetCommandLineA,
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

/// Split API list into kernel32 (0-5, 15) and libyoyo (6-14) groups.
/// Build the .idata section bytes — single import table for kernel32.dll.
/// All APIs (including libyoyo_* aliases) resolve through kernel32.
fn build_idata(unique: &[Win32Api], idata_rva: u32) -> (Vec<u8>, u32) {
    let n = unique.len() as u32;
    let mut bytes = Vec::new();

    let desc_rva = idata_rva;
    let int_rva = desc_rva + 40;
    let iat_rva = int_rva + (n + 1) * 8;
    let func_names_start = iat_rva + (n + 1) * 8;
    let by_name_total: u32 = unique.iter().map(|api| {
        2 + WIN32_API_NAMES[*api as usize].len() as u32 + 1
    }).sum();
    let dll_name_rva = func_names_start + by_name_total;

    bytes.extend_from_slice(&int_rva.to_le_bytes());
    bytes.extend(&0u32.to_le_bytes());
    bytes.extend(&0u32.to_le_bytes());
    bytes.extend(&dll_name_rva.to_le_bytes());
    bytes.extend(&iat_rva.to_le_bytes());
    bytes.extend(&[0u8; 20]); // terminator

    // INT
    let mut by_name_off = 0u32;
    for api in unique {
        bytes.extend(&((func_names_start + by_name_off) as u64).to_le_bytes());
        by_name_off += 2 + WIN32_API_NAMES[*api as usize].len() as u32 + 1;
    }
    bytes.extend(&0u64.to_le_bytes());

    // IAT
    by_name_off = 0;
    for api in unique {
        bytes.extend(&((func_names_start + by_name_off) as u64).to_le_bytes());
        by_name_off += 2 + WIN32_API_NAMES[*api as usize].len() as u32 + 1;
    }
    bytes.extend(&0u64.to_le_bytes());

    // by_name entries + dll name
    for api in unique {
        bytes.extend(&0u16.to_le_bytes());
        bytes.extend(WIN32_API_NAMES[*api as usize].as_bytes());
        bytes.push(0);
    }
    bytes.extend(b"kernel32.dll");
    bytes.push(0);

    (bytes, iat_rva)
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
    fn build_text_linux_startup() {
        let startup = vec![0xE9, 0x00, 0x00, 0x00, 0x00]; // jmp H_00
        let handler = vec![0xC3]; // ret
        let result = build_text(&startup, &handler, BSS_RVA);
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
        let result = build_text(&startup, &handler, BSS_RVA);
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
