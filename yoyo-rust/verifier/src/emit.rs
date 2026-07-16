use crate::assembler::X64Assembler;
use crate::isa::TirOp;
use crate::platform::{emit_str_idx_addr, IatThunk, Platform, PlatformKind};
use crate::tir::TirInst;
use crate::types::Reg;

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
    let mut asm = X64Assembler::new();
    let mut chunks: Vec<X86Chunk> = Vec::new();
    let mut handler_offsets = [u32::MAX; 256];
    let mut pending: Vec<PendingFixup> = Vec::new();
    let mut skip_body = false;

    for inst in tir {
        let start = asm.bytes.len() as u32;

        let is_handler = matches!(inst.op, TirOp::HandlerStart { .. });
        if is_handler {
            skip_body = false;
            if let TirOp::HandlerStart { hh } = &inst.op {
                handler_offsets[*hh as usize] = start;
                if *hh == 0x40 && matches!(platform, PlatformKind::Win32) {
                    platform.emit_h00_code(&mut asm).unwrap();
                    skip_body = true;
                    let end = asm.bytes.len() as u32;
                    chunks.push(X86Chunk {
                        byte_offset: start,
                        bytes: asm.bytes[start as usize..end as usize].to_vec(),
                        tir_source_line: inst.source_line,
                    });
                }
            }
            continue;
        }

        if skip_body {
            continue;
        }

        match &inst.op {
            TirOp::SetImm { slot, imm } => {
                asm.mov_imm64(Reg::Rax, *imm);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::Get { dst, src } => {
                asm.load_state(Reg::Rax, *src as u8);
                asm.store_state(*dst as u8, Reg::Rax);
            }
            TirOp::AddImm { slot, imm } => {
                asm.load_state(Reg::Rax, *slot as u8);
                asm.add_imm(Reg::Rax, *imm as i32);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::SubImm { slot, imm } => {
                asm.load_state(Reg::Rax, *slot as u8);
                asm.sub_imm(Reg::Rax, *imm as i32);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::Inc { slot } => {
                asm.load_state(Reg::Rax, *slot as u8);
                asm.add_imm(Reg::Rax, 1);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::Dec { slot } => {
                asm.load_state(Reg::Rax, *slot as u8);
                asm.sub_imm(Reg::Rax, 1);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::AddV { dst, src } => {
                asm.load_state(Reg::Rax, *dst as u8);
                asm.load_state(Reg::Rdx, *src as u8);
                asm.add_rr(Reg::Rax, Reg::Rdx);
                asm.store_state(*dst as u8, Reg::Rax);
            }
            TirOp::SubV { dst, src } => {
                asm.load_state(Reg::Rax, *dst as u8);
                asm.load_state(Reg::Rdx, *src as u8);
                asm.sub_rr(Reg::Rax, Reg::Rdx);
                asm.store_state(*dst as u8, Reg::Rax);
            }
            TirOp::Imul { dst, src } => {
                asm.load_state(Reg::Rax, *dst as u8);
                asm.load_state(Reg::Rdx, *src as u8);
                asm.imul_rr(Reg::Rax, Reg::Rdx);
                asm.store_state(*dst as u8, Reg::Rax);
            }
            TirOp::Cmp { a, b } => {
                asm.load_state(Reg::Rax, *a as u8);
                asm.load_state(Reg::Rdx, *b as u8);
                asm.cmp_rr(Reg::Rax, Reg::Rdx);
            }

            // ── Branches (placeholder rel32, fixed in second pass) ──
            TirOp::CallHh { hh } => {
                asm.call_rel32_placeholder();
                pending.push(PendingFixup { inst_start: start, inst_len: 5, hh: *hh });
            }
            TirOp::JmpHh { hh } => {
                asm.jmp_rel32_placeholder();
                pending.push(PendingFixup { inst_start: start, inst_len: 5, hh: *hh });
            }
            TirOp::JeHh { hh } => {
                asm.jcc_rel32_placeholder(0x84);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JneHh { hh } => {
                asm.jcc_rel32_placeholder(0x85);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JlHh { hh } => {
                asm.jcc_rel32_placeholder(0x8C);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JgeHh { hh } => {
                asm.jcc_rel32_placeholder(0x8D);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JleHh { hh } => {
                asm.jcc_rel32_placeholder(0x8E);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JgHh { hh } => {
                asm.jcc_rel32_placeholder(0x8F);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JbHh { hh } => {
                asm.jcc_rel32_placeholder(0x82);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JaeHh { hh } => {
                asm.jcc_rel32_placeholder(0x83);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JbeHh { hh } => {
                asm.jcc_rel32_placeholder(0x86);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }
            TirOp::JaHh { hh } => {
                asm.jcc_rel32_placeholder(0x87);
                pending.push(PendingFixup { inst_start: start, inst_len: 6, hh: *hh });
            }

            // ── Memory ──
            TirOp::Ldb { dd, ss, oo } => {
                asm.load_state(Reg::Rdx, *ss as u8);
                asm.movzx_eax_byte_mem(Reg::Rdx, *oo as i32);
                asm.store_state(*dd as u8, Reg::Rax);
            }
            TirOp::MemcpyData { dd, off, sz } => {
                asm.load_state(Reg::Rdi, *dd as u8);
                asm.bytes.extend_from_slice(&[0x48, 0x8D, 0x35]);
                asm.bytes.extend(&(*off as i32).to_le_bytes());
                asm.mov_imm64(Reg::Rcx, *sz);
                asm.rep_movsb();
            }
            TirOp::MemcpyState { dd, ss, sz } => {
                asm.load_state(Reg::Rdi, *dd as u8);
                asm.load_state(Reg::Rsi, *ss as u8);
                asm.mov_imm64(Reg::Rcx, *sz);
                asm.rep_movsb();
            }

            // ── Raw Data ──
            TirOp::RawByte { byte } => {
                asm.bytes.push(*byte as u8);
            }
            TirOp::RawBytes { bytes } => {
                asm.bytes.extend(&bytes.to_le_bytes());
            }

            // ── Syscall / Complex (delegated to platform) ──
            TirOp::Alloc { slot, sz } => {
                platform.emit_alloc(&mut asm, *slot as u16, *sz).unwrap();
            }
            TirOp::LoadFile { slot, str_slot } => {
                platform.emit_loadfile(&mut asm, *slot as u16, *str_slot as u16).unwrap();
            }
            TirOp::WriteFile { id, str_slot, sz } => {
                platform.emit_writefile(&mut asm, *id as u16, *str_slot as u16, *sz as u16).unwrap();
            }

            // ── libyoyo_* calls ──
            TirOp::LibyoyoAlloc { slot, sz } => {
                asm.mov_imm64(Reg::Rdi, *sz);
                IatThunk::LibyoyoAlloc.emit_call(&mut asm);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::LibyoyoFree { slot } => {
                asm.load_state(Reg::Rdi, *slot as u8);
                IatThunk::LibyoyoFree.emit_call(&mut asm);
            }
            TirOp::LibyoyoOpen { slot, str_idx } => {
                let _ = str_idx;
                emit_str_idx_addr(&mut asm);
                IatThunk::LibyoyoOpen.emit_call(&mut asm);
                asm.store_state(*slot as u8, Reg::Rax);
            }
            TirOp::LibyoyoRead { slot, fd, sz } => {
                asm.load_state(Reg::Rdi, *fd as u8);
                asm.load_state(Reg::Rsi, *slot as u8);
                asm.mov_imm64(Reg::Rdx, *sz as u64);
                IatThunk::LibyoyoRead.emit_call(&mut asm);
                asm.store_state((*slot + 1) as u8, Reg::Rax);
            }
            TirOp::LibyoyoWrite { fd, slot, sz } => {
                asm.load_state(Reg::Rdi, *fd as u8);
                asm.load_state(Reg::Rsi, *slot as u8);
                asm.mov_imm64(Reg::Rdx, *sz as u64);
                IatThunk::LibyoyoWrite.emit_call(&mut asm);
            }
            TirOp::LibyoyoClose { fd } => {
                asm.load_state(Reg::Rdi, *fd as u8);
                IatThunk::LibyoyoClose.emit_call(&mut asm);
            }
            TirOp::LibyoyoExit { slot } => {
                asm.load_state(Reg::Rdi, *slot as u8);
                IatThunk::LibyoyoExit.emit_call(&mut asm);
                asm.ret();
            }
            TirOp::LibyoyoPrint { slot } => {
                asm.load_state(Reg::Rdi, *slot as u8);
                IatThunk::LibyoyoPrint.emit_call(&mut asm);
            }
            TirOp::LibyoyoTime { slot } => {
                IatThunk::LibyoyoTime.emit_call(&mut asm);
                asm.store_state(*slot as u8, Reg::Rax);
            }

            TirOp::StringDef { .. } => {}
            TirOp::RawDef { .. } => {}
            TirOp::HandlerStart { .. } => unreachable!(),

            TirOp::Ret => {
                asm.ret();
            }
        }

        let end = asm.bytes.len() as u32;
        chunks.push(X86Chunk {
            byte_offset: start,
            bytes: asm.bytes[start as usize..end as usize].to_vec(),
            tir_source_line: inst.source_line,
        });
    }

    // ── Second pass: fixup rel32 placeholders ──
    if do_fixup {
        for p in &pending {
            let target = handler_offsets[p.hh as usize];
            let rel32 = target as i32 - (p.inst_start as i32 + p.inst_len as i32);
            let rel32_off = p.inst_start as usize + if p.inst_len == 5 { 1 } else { 2 };
            asm.write_at(rel32_off, &rel32.to_le_bytes());
        }
    }

    (asm.bytes, chunks)
}


