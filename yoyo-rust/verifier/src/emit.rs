use crate::isa::TirOp;
use crate::platform::{Platform, PlatformKind};
use crate::primitives::*;
use crate::tir::TirInst;
use crate::types::{FixedBuf, Reg};

const BUF_SIZE: usize = 1024 * 1024;

/// One emitted chunk of x64 bytes, annotated with the source line it came from.
#[derive(Debug, Clone)]
pub struct X86Chunk {
    pub byte_offset: u32,
    pub bytes: Vec<u8>,
    pub tir_source_line: u32,
}

struct PendingFixup {
    inst_start: u32,
    inst_len: u8,
    hh: u8,
}

/// Emit TIR to x64 bytes using the default Win32 platform.
pub fn emit(tir: &[TirInst]) -> Vec<u8> {
    emit_on(tir, PlatformKind::Win32)
}

/// Emit TIR using the specified platform.
pub fn emit_on(tir: &[TirInst], platform: PlatformKind) -> Vec<u8> {
    emit_inner(tir, true, platform).0
}

/// Emit with chunk metadata (used by diff/annotate).
pub fn emit_with_chunks(tir: &[TirInst]) -> (Vec<u8>, Vec<X86Chunk>) {
    emit_inner(tir, true, PlatformKind::Win32)
}

/// Emit without rel32 fixup (all placeholders left as 0).
pub fn emit_with_chunks_unfixed(tir: &[TirInst]) -> (Vec<u8>, Vec<X86Chunk>) {
    emit_inner(tir, false, PlatformKind::Win32)
}

fn emit_inner(tir: &[TirInst], do_fixup: bool, platform: PlatformKind) -> (Vec<u8>, Vec<X86Chunk>) {
    let mut buf = FixedBuf::<BUF_SIZE>::new();
    let mut chunks: Vec<X86Chunk> = Vec::new();
    let mut handler_offsets = [u32::MAX; 256];
    let mut pending: Vec<PendingFixup> = Vec::new();

    for inst in tir {
        let start = buf.len() as u32;

        let is_handler = matches!(inst.op, TirOp::HandlerStart { .. });
        if is_handler {
            if let TirOp::HandlerStart { hh } = &inst.op {
                handler_offsets[*hh as usize] = start;
            }
            continue;
        }

        match &inst.op {
            // ── Integer / Control Flow ──
            TirOp::SetImm { slot, imm } => {
                movabs(&mut buf, Reg::Rax, *imm).unwrap();
                store_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
            }
            TirOp::Get { dst, src } => {
                load_state(&mut buf, *src as u8, Reg::Rax).unwrap();
                store_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
            }
            TirOp::AddImm { slot, imm } => {
                load_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
                add_imm(&mut buf, Reg::Rax, *imm as i32).unwrap();
                store_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
            }
            TirOp::SubImm { slot, imm } => {
                load_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
                sub_imm(&mut buf, Reg::Rax, *imm as i32).unwrap();
                store_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
            }
            TirOp::Inc { slot } => {
                load_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
                add_imm(&mut buf, Reg::Rax, 1).unwrap();
                store_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
            }
            TirOp::Dec { slot } => {
                load_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
                sub_imm(&mut buf, Reg::Rax, 1).unwrap();
                store_state(&mut buf, *slot as u8, Reg::Rax).unwrap();
            }
            TirOp::AddV { dst, src } => {
                load_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
                load_state(&mut buf, *src as u8, Reg::Rdx).unwrap();
                add_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
                store_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
            }
            TirOp::SubV { dst, src } => {
                load_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
                load_state(&mut buf, *src as u8, Reg::Rdx).unwrap();
                sub_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
                store_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
            }
            TirOp::Imul { dst, src } => {
                load_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
                load_state(&mut buf, *src as u8, Reg::Rdx).unwrap();
                mul_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
                store_state(&mut buf, *dst as u8, Reg::Rax).unwrap();
            }
            TirOp::Cmp { a, b } => {
                load_state(&mut buf, *a as u8, Reg::Rax).unwrap();
                load_state(&mut buf, *b as u8, Reg::Rdx).unwrap();
                cmp_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
            }

            // ── Branches (placeholder rel32, fixed in second pass) ──
            TirOp::CallHh { hh } => {
                call_rel32(&mut buf, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 5, hh: *hh });
            }
            TirOp::JmpHh { hh } => {
                jmp_rel32(&mut buf, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 5, hh: *hh });
            }
            TirOp::JeHh { hh } => {
                jcc_rel32(&mut buf, 0x84, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JneHh { hh } => {
                jcc_rel32(&mut buf, 0x85, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JlHh { hh } => {
                jcc_rel32(&mut buf, 0x8C, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JgeHh { hh } => {
                jcc_rel32(&mut buf, 0x8D, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JleHh { hh } => {
                jcc_rel32(&mut buf, 0x8E, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JgHh { hh } => {
                jcc_rel32(&mut buf, 0x8F, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JbHh { hh } => {
                jcc_rel32(&mut buf, 0x82, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JaeHh { hh } => {
                jcc_rel32(&mut buf, 0x83, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JbeHh { hh } => {
                jcc_rel32(&mut buf, 0x86, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JaHh { hh } => {
                jcc_rel32(&mut buf, 0x87, 0).unwrap();
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }

            // ── Memory ──
            TirOp::Ldb { dd, ss, oo } => {
                load_state(&mut buf, *ss as u8, Reg::Rdx).unwrap();
                // movzx eax, byte [rdx + oo]
                let disp8 = *oo >= -128 && *oo <= 127;
                buf.push(0x0F).unwrap();
                buf.push(0xB6).unwrap();
                if disp8 {
                    buf.push(0x42).unwrap(); // ModRM: mod=01 reg=000 rm=010 (rdx+disp8)
                    buf.push(*oo as u8 as i8 as u8).unwrap();
                } else {
                    buf.push(0x82).unwrap(); // ModRM: mod=10 reg=000 rm=010 (rdx+disp32)
                    buf.extend(&(*oo as i32).to_le_bytes()).unwrap();
                }
                store_state(&mut buf, *dd as u8, Reg::Rax).unwrap();
            }
            TirOp::MemcpyData { dd, off, sz } => {
                load_state(&mut buf, *dd as u8, Reg::Rdi).unwrap();
                lea_rsi_rip(&mut buf, *off as i32).unwrap();
                movabs(&mut buf, Reg::Rcx, *sz).unwrap();
                rep_movsb(&mut buf).unwrap();
            }
            TirOp::MemcpyState { dd, ss, sz } => {
                load_state(&mut buf, *dd as u8, Reg::Rdi).unwrap();
                load_state(&mut buf, *ss as u8, Reg::Rsi).unwrap();
                movabs(&mut buf, Reg::Rcx, *sz).unwrap();
                rep_movsb(&mut buf).unwrap();
            }

            // ── Raw Data ──
            TirOp::RawByte { byte } => {
                buf.push(*byte as u8).unwrap();
            }
            TirOp::RawBytes { bytes } => {
                buf.extend(&bytes.to_le_bytes()).unwrap();
            }

            // ── Syscall / Complex (delegated to platform) ──
            TirOp::Alloc { slot, sz } => {
                platform.emit_alloc(&mut buf, *slot as u16, *sz).unwrap();
            }
            TirOp::LoadFile { slot, str_idx } => {
                platform.emit_loadfile(&mut buf, *slot as u16, *str_idx as u8).unwrap();
            }
            TirOp::WriteFile { id, str_idx, sz } => {
                platform.emit_writefile(&mut buf, *id as u16, *str_idx as u8, *sz as u16).unwrap();
            }

            // ── HandlerStart (already handled above) ──
            TirOp::HandlerStart { .. } => unreachable!(),

            // ── Ret ──
            TirOp::Ret => {
                ret(&mut buf).unwrap();
            }
        }

        let end = buf.len() as u32;
        chunks.push(X86Chunk {
            byte_offset: start,
            bytes: buf.as_slice()[start as usize..end as usize].to_vec(),
            tir_source_line: inst.source_line,
        });
    }

    // ── Second pass: fixup rel32 placeholders ──
    if do_fixup {
        for p in &pending {
            let target = handler_offsets[p.hh as usize];
            let rel32 = target as i32 - (p.inst_start as i32 + p.inst_len as i32);
            let rel32_off = p.inst_start as usize + if p.inst_len == 5 { 1 } else { 2 };
            buf.write_i32_at(rel32_off, rel32).unwrap();
        }
    }

    (buf.as_slice().to_vec(), chunks)
}
