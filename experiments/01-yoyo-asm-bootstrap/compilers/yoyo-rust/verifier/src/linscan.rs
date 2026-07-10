//! M5: relocation-safety scanner (linear x64 decoder for yoyo's .text).
//!
//! Purpose: the yoyo Windows M2→M3 bootstrap bug is a `relocateSlice`
//! defect. `relocateSlice` scans `.text` byte-by-byte for `E8`/`E9`
//! (call/jmp rel32) opcodes to relocate, but it cannot tell whether a given
//! `E8`/`E9` byte is a *real* opcode or just a data byte living inside a
//! `movabs r, imm64` immediate or a `lea rip`/`call [rip]` displacement.
//! When it "relocates" one of those data bytes it corrupts the instruction —
//! exactly the observed `movabs` / `lea_rip` corruption.
//!
//! This module linearly disassembles the yoyo instruction subset so it knows
//! *instruction boundaries*. From that it produces:
//!   1. the authoritative list of legitimate rel32 relocation sites, and
//!   2. the list of "trap bytes": `E8`/`E9` bytes that a naive byte scanner
//!      would wrongly relocate, together with the instruction they hide in.
//!
//! It only decodes the instruction forms yoyo actually emits (see
//! `src/encode-x64.js` and `src/backends/{win,linux}-emit-core.js`). Any byte
//! it cannot classify is reported as `Unknown` so a desync is never silent.

/// Classification of a decoded instruction, focused on what the relocation
/// analysis cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `E8 rel32` — a genuine call, a legitimate relocation site.
    RelCall,
    /// `E9 rel32` — a genuine near jmp, a legitimate relocation site.
    RelJmp,
    /// `0F 8x rel32` — a genuine conditional near jump (rel32 site).
    RelJcc,
    /// `EB rel8` / `7x rel8` — short branch (no rel32).
    ShortBranch,
    /// `REX.W B8+r imm64` — movabs; its 8 immediate bytes may contain E8/E9.
    Movabs,
    /// `8D /r` with RIP-relative ModRM — lea; disp32 may contain E8/E9.
    LeaRip,
    /// `FF /2` with RIP-relative ModRM — call [rip+disp32].
    CallRip,
    /// `FF /4` with RIP-relative ModRM — jmp [rip+disp32].
    JmpRip,
    /// `0x90` padding.
    Nop,
    /// Any other decoded instruction (mov/add/cmp/ret/…).
    Other,
    /// Could not decode — potential desync.
    Unknown,
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Instr {
    /// Byte offset of the instruction start (within the scanned slice).
    pub offset: usize,
    /// Total instruction length in bytes.
    pub len: usize,
    pub kind: Kind,
    /// For rel32 branches: the byte offset of the rel32 field.
    pub rel32_off: Option<usize>,
    /// For rel32 branches: the decoded signed displacement.
    pub rel32: Option<i32>,
}

/// ModRM/SIB/disp length, counting the ModRM byte itself. `p` indexes the
/// ModRM byte within `b`.
fn modrm_len(b: &[u8], p: usize) -> usize {
    if p >= b.len() {
        return 1;
    }
    let modrm = b[p];
    let md = modrm >> 6;
    let rm = modrm & 7;
    if md == 3 {
        return 1;
    }
    let mut len = 1;
    let mut base_disp32 = false;
    if rm == 4 {
        // SIB byte present
        len += 1;
        if md == 0 && p + 1 < b.len() && (b[p + 1] & 7) == 5 {
            base_disp32 = true;
        }
    }
    match md {
        0 => {
            if rm == 5 || base_disp32 {
                len += 4; // disp32 (RIP-relative when rm==5)
            }
        }
        1 => len += 1, // disp8
        2 => len += 4, // disp32
        _ => {}
    }
    len
}

/// Decode a single instruction at `i`. Returns the decoded `Instr`.
/// On an unrecognized opcode, returns `Kind::Unknown` with a 1-byte length so
/// the caller can resync (and count the anomaly).
pub fn decode_one(b: &[u8], i: usize) -> Instr {
    let start = i;
    let mut p = i;

    // Legacy prefixes (F3 rep / F2 / 66 operand-size) precede REX.
    while p < b.len() && matches!(b[p], 0xF3 | 0xF2 | 0x66) {
        p += 1;
    }
    // REX prefix.
    let mut rex_w = false;
    if p < b.len() && (b[p] & 0xF0) == 0x40 {
        rex_w = (b[p] & 0x08) != 0;
        p += 1;
    }

    let unknown = |consumed: usize| Instr {
        offset: start,
        len: consumed.max(1),
        kind: Kind::Unknown,
        rel32_off: None,
        rel32: None,
    };
    let plain = |consumed: usize, kind: Kind| Instr {
        offset: start,
        len: consumed,
        kind,
        rel32_off: None,
        rel32: None,
    };

    if p >= b.len() {
        return unknown(p - start);
    }
    let op = b[p];
    p += 1;

    match op {
        0x90 => plain(p - start, Kind::Nop),
        0xC3 => plain(p - start, Kind::Other), // ret
        0xE8 | 0xE9 => {
            // call/jmp rel32
            let rel32_off = p;
            let rel = read_i32(b, p);
            Instr {
                offset: start,
                len: p - start + 4,
                kind: if op == 0xE8 { Kind::RelCall } else { Kind::RelJmp },
                rel32_off: Some(rel32_off),
                rel32: rel,
            }
        }
        0xEB => plain(p - start + 1, Kind::ShortBranch),       // jmp rel8
        0x70..=0x7F => plain(p - start + 1, Kind::ShortBranch), // jcc rel8
        0xB8..=0xBF => plain(p - start + if rex_w { 8 } else { 4 }, Kind::Movabs),
        0x50..=0x5F => plain(p - start, Kind::Other), // push/pop r
        0x0F => {
            if p >= b.len() {
                return unknown(p - start);
            }
            let op2 = b[p];
            p += 1;
            match op2 {
                0x80..=0x8F => {
                    // jcc rel32
                    let rel32_off = p;
                    let rel = read_i32(b, p);
                    Instr {
                        offset: start,
                        len: p - start + 4,
                        kind: Kind::RelJcc,
                        rel32_off: Some(rel32_off),
                        rel32: rel,
                    }
                }
                0x05 => plain(p - start, Kind::Other), // syscall
                0xAF | 0xB6 | 0xB7 | 0xBE | 0xBF => {
                    let ml = modrm_len(b, p);
                    plain(p - start + ml, Kind::Other) // imul / movzx / movsx
                }
                _ => unknown(p - start),
            }
        }
        // ALU / mov reg forms with ModRM, no immediate
        0x89 | 0x8B | 0x01 | 0x03 | 0x29 | 0x2B | 0x39 | 0x3B | 0x31 | 0x09
        | 0x21 | 0x85 | 0x88 | 0x8A => {
            let ml = modrm_len(b, p);
            plain(p - start + ml, Kind::Other)
        }
        0x8D => {
            // lea r, m — RIP-relative when mod==0, rm==5
            let ml = modrm_len(b, p);
            let kind = if p < b.len() && (b[p] >> 6) == 0 && (b[p] & 7) == 5 {
                Kind::LeaRip
            } else {
                Kind::Other
            };
            plain(p - start + ml, kind)
        }
        0x83 | 0xC6 => {
            let ml = modrm_len(b, p);
            plain(p - start + ml + 1, Kind::Other) // + imm8
        }
        0x81 | 0xC7 => {
            let ml = modrm_len(b, p);
            plain(p - start + ml + 4, Kind::Other) // + imm32
        }
        0xA4 => plain(p - start, Kind::Other), // movsb (with optional F3 rep prefix)
        0xFF => {
            if p >= b.len() {
                return unknown(p - start);
            }
            let modrm = b[p];
            let reg = (modrm >> 3) & 7;
            let riprel = (modrm >> 6) == 0 && (modrm & 7) == 5;
            let ml = modrm_len(b, p);
            let kind = match reg {
                2 if riprel => Kind::CallRip,
                4 if riprel => Kind::JmpRip,
                _ => Kind::Other,
            };
            plain(p - start + ml, kind)
        }
        _ => unknown(p - start),
    }
}

fn read_i32(b: &[u8], p: usize) -> Option<i32> {
    if p + 4 <= b.len() {
        Some(i32::from_le_bytes(b[p..p + 4].try_into().unwrap()))
    } else {
        None
    }
}

/// A byte that a naive `relocateSlice` (scan for E8/E9) would wrongly touch.
#[derive(Debug, Clone)]
pub struct Trap {
    /// Offset of the stray E8/E9 byte.
    pub offset: usize,
    /// The byte value (0xE8 or 0xE9).
    pub byte: u8,
    /// The instruction that actually owns this byte.
    pub owner_kind: Kind,
    /// The owning instruction's start offset.
    pub owner_offset: usize,
}

/// Full relocation-safety report for a scanned code slice.
pub struct Report {
    pub instrs: Vec<Instr>,
    /// Genuine rel32 relocation sites (RelCall / RelJmp / RelJcc).
    pub reloc_sites: Vec<Instr>,
    /// E8/E9 bytes a naive scanner would corrupt.
    pub traps: Vec<Trap>,
    pub unknown_count: usize,
    /// Offsets (within the scanned slice) of undecodable bytes.
    pub unknown_offsets: Vec<usize>,
}

/// Linearly decode `code` and produce the relocation-safety report.
pub fn scan(code: &[u8]) -> Report {
    let mut instrs = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let ins = decode_one(code, i);
        let step = ins.len.max(1);
        instrs.push(ins);
        i += step;
    }

    let unknown_count = instrs.iter().filter(|x| x.kind == Kind::Unknown).count();
    let unknown_offsets: Vec<usize> = instrs
        .iter()
        .filter(|x| x.kind == Kind::Unknown)
        .map(|x| x.offset)
        .collect();

    let reloc_sites: Vec<Instr> = instrs
        .iter()
        .filter(|x| matches!(x.kind, Kind::RelCall | Kind::RelJmp | Kind::RelJcc))
        .cloned()
        .collect();

    // Genuine E8/E9 opcode offsets (RelCall/RelJmp start with the opcode
    // byte; no prefix in yoyo's emit).
    let mut legit_e8e9: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for x in &instrs {
        if matches!(x.kind, Kind::RelCall | Kind::RelJmp) {
            legit_e8e9.insert(x.offset);
        }
    }

    // For each stray E8/E9 byte, find the owning instruction.
    let mut traps = Vec::new();
    for (off, &byte) in code.iter().enumerate() {
        if (byte == 0xE8 || byte == 0xE9) && !legit_e8e9.contains(&off) {
            let owner = owning_instr(&instrs, off);
            traps.push(Trap {
                offset: off,
                byte,
                owner_kind: owner.map(|o| o.kind).unwrap_or(Kind::Unknown),
                owner_offset: owner.map(|o| o.offset).unwrap_or(off),
            });
        }
    }

    Report { instrs, reloc_sites, traps, unknown_count, unknown_offsets }
}

/// Which decoded instruction spans byte offset `off`?
fn owning_instr(instrs: &[Instr], off: usize) -> Option<&Instr> {
    instrs
        .iter()
        .find(|x| off >= x.offset && off < x.offset + x.len)
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::RelCall => "call rel32",
        Kind::RelJmp => "jmp rel32",
        Kind::RelJcc => "jcc rel32",
        Kind::ShortBranch => "short branch",
        Kind::Movabs => "movabs imm64",
        Kind::LeaRip => "lea [rip+d32]",
        Kind::CallRip => "call [rip+d32]",
        Kind::JmpRip => "jmp [rip+d32]",
        Kind::Nop => "nop",
        Kind::Other => "other",
        Kind::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_call_rel32() {
        // E8 02 00 00 00 → call rel32, len 5
        let b = vec![0xE8, 0x02, 0x00, 0x00, 0x00];
        let ins = decode_one(&b, 0);
        assert_eq!(ins.len, 5);
        assert_eq!(ins.kind, Kind::RelCall);
        assert_eq!(ins.rel32, Some(2));
        assert_eq!(ins.rel32_off, Some(1));
    }

    #[test]
    fn decode_movabs_is_10_bytes() {
        // 48 B8 + 8 imm bytes
        let b = vec![0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0];
        let ins = decode_one(&b, 0);
        assert_eq!(ins.len, 10);
        assert_eq!(ins.kind, Kind::Movabs);
    }

    #[test]
    fn decode_jcc_rel32_is_6_bytes() {
        let b = vec![0x0F, 0x85, 0, 0, 0, 0];
        let ins = decode_one(&b, 0);
        assert_eq!(ins.len, 6);
        assert_eq!(ins.kind, Kind::RelJcc);
        assert_eq!(ins.rel32_off, Some(2));
    }

    #[test]
    fn decode_lea_rip_and_call_rip() {
        // 48 8D 05 dd dd dd dd → lea rax, [rip+d32]
        let lea = vec![0x48, 0x8D, 0x05, 1, 2, 3, 4];
        let ins = decode_one(&lea, 0);
        assert_eq!(ins.len, 7);
        assert_eq!(ins.kind, Kind::LeaRip);
        // FF 15 dd dd dd dd → call [rip+d32]
        let call = vec![0xFF, 0x15, 1, 2, 3, 4];
        let ins = decode_one(&call, 0);
        assert_eq!(ins.len, 6);
        assert_eq!(ins.kind, Kind::CallRip);
    }

    #[test]
    fn trap_detection_finds_e8_inside_movabs() {
        // movabs rax, 0x00000000_000000E8  then ret
        // 48 B8 E8 00 00 00 00 00 00 00 C3
        // The E8 at offset 2 is data, NOT a real call → must be a trap.
        let code = vec![0x48, 0xB8, 0xE8, 0, 0, 0, 0, 0, 0, 0, 0xC3];
        let rep = scan(&code);
        assert_eq!(rep.reloc_sites.len(), 0, "no genuine rel32 sites");
        assert_eq!(rep.traps.len(), 1, "one stray E8 inside the movabs");
        assert_eq!(rep.traps[0].offset, 2);
        assert_eq!(rep.traps[0].owner_kind, Kind::Movabs);
        assert_eq!(rep.traps[0].owner_offset, 0);
    }

    #[test]
    fn genuine_call_not_flagged_as_trap() {
        // call rel32 (E8 05 00 00 00) then 5 nops
        let code = vec![0xE8, 0x05, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90];
        let rep = scan(&code);
        assert_eq!(rep.reloc_sites.len(), 1);
        assert_eq!(rep.traps.len(), 0);
    }
}
