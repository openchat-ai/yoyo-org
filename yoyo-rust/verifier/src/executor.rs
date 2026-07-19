//! V3 Executor — compiles .ty hex to x64 at runtime inside gen2.exe.
//!
//! Single-pass with fixup table for forward JMP/CALL/JCC references.
//!
//! Output layout [R14 relative]:
//!   [0x000..0x400) = handler_offsets (256 × i32, -1 = unseen)
//!   [0x400]        = pass_flag (u32: 0=pass1, 1=pass2)
//!   [0x404]        = fixup_count (u32)
//!   [0x408..0x800) = fixups (83 × 12 B: u32 rel32_ofs, u32 hh, u32 inst_len)
//!   [0x800..)      = emitted code

use crate::assembler::X64Assembler;
use crate::platform::Win32Api;
use crate::types::{IsaResult, Reg};

const JCC_TABLE: [u8; 10] = [0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F, 0x82, 0x83, 0x86, 0x87];

fn hex_table() -> Vec<u8> {
    let mut t = vec![0xFFu8; 256];
    for c in b'0'..=b'9' { t[c as usize] = c - b'0'; }
    for c in b'A'..=b'F' { t[c as usize] = 10 + c - b'A'; }
    for c in b'a'..=b'f' { t[c as usize] = 10 + c - b'a'; }
    t
}

fn raw(asm: &mut X64Assembler, b: &[u8]) { asm.bytes.extend_from_slice(b); }

/// Emit call rel32 with compile-time computed displacement (no fixup entry).
fn emit_direct_call(asm: &mut X64Assembler, target: usize) {
    let off = asm.bytes.len();
    let target_pos = asm.get_label_offset(target);
    let disp = target_pos as i32 - (off as i32 + 5);
    asm.emit_u8(0xE8);
    asm.emit_i32(disp);
}

pub fn emit_v3_executor(asm: &mut X64Assembler) -> IsaResult<()> {
    let hex_lbl = asm.alloc_label();
    let jcc_lbl = asm.alloc_label();
    let after_tbl = asm.alloc_label();
    let main_start = asm.alloc_label();
    let after_sub = asm.alloc_label();

    // ── Prologue (executed FIRST at runtime) ──
    for &r in &[Reg::R12, Reg::R13, Reg::R14, Reg::Rbx, Reg::Rsi, Reg::Rdi, Reg::R8, Reg::R9] {
        asm.push(r);
    }
    asm.push(Reg::R15); // save state pointer
    asm.sub_imm(Reg::Rsp, 0x10);
    asm.mov_rr(Reg::R13, Reg::R12); asm.add_rr(Reg::R13, Reg::Rdx);
    asm.mov_imm64(Reg::Rcx, 0); asm.mov_imm64(Reg::Rdx, 0x40000);
    asm.mov_imm64(Reg::R8, 0x3000); asm.mov_imm64(Reg::R9, 0x40);
    asm.shadow_frame();
    asm.call_iat_thunk(Win32Api::VirtualAlloc as u8);
    asm.shadow_ret();
    asm.mov_rr(Reg::R14, Reg::Rax);
    raw(asm, &[0x45, 0x31, 0xFF]); // xor r15d, r15d (fixup count = 0)

    // Hex table + JCC table (10 entries: 0x84,0x85,0x8C,0x8D,0x8E,0x8F,0x82,0x83,0x86,0x87)
    asm.jmp_rel32_label(after_tbl);
    asm.set_label(hex_lbl); raw(asm, &hex_table());
    asm.set_label(jcc_lbl); raw(asm, &JCC_TABLE);
    asm.set_label(after_tbl);

    let rip = asm.bytes.len() as i64;
    let tbl = asm.get_label_offset(hex_lbl) as i64;
    asm.lea_rbx_rip((tbl - rip - 7) as i32);
    let jcc_off = asm.get_label_offset(jcc_lbl) as i64;
    raw(asm, &[0x4C, 0x8D, 0x15]); asm.emit_i32((jcc_off - rip - 14) as i32); // lea r10, [rip+disp]

    // Jump over subroutines to main logic
    asm.jmp_rel32_label(after_sub);

    // Subroutines (reachable only by CALL)
    let sw = emit_skip_ws(asm);
    let rh = emit_read_hex(asm);
    asm.set_label(after_sub);

    // ═════════ MAIN ═════════
    asm.set_label(main_start);

    // Zero [R14+0..0x400) = -1
    asm.mov_rr(Reg::Rdi, Reg::R14);
    asm.mov_imm64(Reg::Rcx, 256);
    raw(asm, &[0x31, 0xC0]); asm.dec(Reg::Rax);
    raw(asm, &[0xF3, 0xAB]); // rep stosd

    // Zero pass_flag + fixup_count
    raw(asm, &[0x41, 0xC7, 0x86, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    raw(asm, &[0x41, 0xC7, 0x86, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    asm.lea_mem(Reg::Rdi, Reg::R14, 0x800);
    asm.mov_rr(Reg::Rsi, Reg::R12);
    raw(asm, &[0x4D, 0x31, 0xC0]); // xor r8, r8

    let p1_loop = asm.alloc_label();
    let p1_done = asm.alloc_label();
    let p2_loop = asm.alloc_label();
    let p2_done = asm.alloc_label();
    let skip1 = asm.alloc_label();
    let skip2 = asm.alloc_label();
    let h_set1 = asm.alloc_label(); let h_hand1 = asm.alloc_label(); let h_ret1 = asm.alloc_label();
    let h_set2 = asm.alloc_label(); let h_hand2 = asm.alloc_label(); let h_ret2 = asm.alloc_label();
    let h_get1 = asm.alloc_label(); let h_get2 = asm.alloc_label();
    let h_add1 = asm.alloc_label(); let h_add2 = asm.alloc_label();
    let h_sub1 = asm.alloc_label(); let h_sub2 = asm.alloc_label();
    let h_cmp1 = asm.alloc_label(); let h_cmp2 = asm.alloc_label();
    let h_inc1 = asm.alloc_label(); let h_inc2 = asm.alloc_label();
    let h_dec1 = asm.alloc_label(); let h_dec2 = asm.alloc_label();
    let h_addv1 = asm.alloc_label(); let h_addv2 = asm.alloc_label();
    let h_subv1 = asm.alloc_label(); let h_subv2 = asm.alloc_label();
    let h_jmp1 = asm.alloc_label(); let h_jmp2 = asm.alloc_label();
    let h_call1 = asm.alloc_label(); let h_call2 = asm.alloc_label();
    let h_jcc1 = asm.alloc_label(); let h_jcc2 = asm.alloc_label();
    let h_alloc1 = asm.alloc_label(); let h_alloc2 = asm.alloc_label();
    let h_read1 = asm.alloc_label(); let h_read2 = asm.alloc_label();
    let h_write1 = asm.alloc_label(); let h_write2 = asm.alloc_label();
    let after_jcc1 = asm.alloc_label(); let after_jcc2 = asm.alloc_label();

    // ══════ PASS 1 ══════
    asm.set_label(p1_loop);
    emit_prefix_read(asm, sw, rh, skip1, p1_done, 0x80);
    // Dispatch SET(0x30), HANDLER(0x40), RET(0xFF)
    asm.cmp_al_imm8(0x30); asm.jcc_rel8_label(4, h_set1);
    asm.cmp_al_imm8(0x40); asm.jcc_rel8_label(4, h_hand1);
    asm.cmp_al_imm8(0x41); asm.jcc_rel8_label(4, h_call1);
    asm.cmp_al_imm8(0x60); asm.jcc_rel8_label(4, h_get1);
    asm.cmp_al_imm8(0x62); asm.jcc_rel8_label(4, h_sub1);
    asm.cmp_al_imm8(0x65); asm.jcc_rel8_label(4, h_cmp1);
    asm.cmp_al_imm8(0x66); asm.jcc_rel8_label(4, h_inc1);
    asm.cmp_al_imm8(0x67); asm.jcc_rel8_label(4, h_dec1);
    asm.cmp_al_imm8(0x68); asm.jcc_rel8_label(4, h_add1);
    asm.cmp_al_imm8(0x69); asm.jcc_rel8_label(4, h_addv1);
    asm.cmp_al_imm8(0x6A); asm.jcc_rel8_label(4, h_subv1);
asm.cmp_al_imm8(0x70); asm.jcc_rel8_label(4, h_jmp1);
    asm.cmp_al_imm8(0x71); asm.jcc_rel8_label(2, after_jcc1);
    asm.cmp_al_imm8(0x7B); asm.jcc_rel8_label(3, after_jcc1);
    asm.jmp_rel8_label(h_jcc1);
    asm.set_label(after_jcc1);
    asm.cmp_al_imm8(0x20); asm.jcc_rel8_label(4, h_alloc1);
    asm.cmp_al_imm8(0x50); asm.jcc_rel8_label(4, h_read1);
    asm.cmp_al_imm8(0x51); asm.jcc_rel8_label(4, h_write1);
    asm.cmp_al_imm8(0xFF); asm.jcc_rel8_label(4, h_ret1);
    asm.jmp_rel8_label(skip1); // unknown → skip

    // SET pass1
    asm.set_label(h_set1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // HANDLER pass1
    asm.set_label(h_hand1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x88, 0xC1]); // mov cl, al (hh → CL)
    raw(asm, &[0x44, 0x89, 0xC0]); // mov eax, r8d
    raw(asm, &[0x41, 0x89, 0x04, 0x8E]); // mov [r14+rcx*4], eax
    asm.jmp_rel8_label(p1_loop);

    // RET pass1
    asm.set_label(h_ret1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x01]); // add r8, 1
    asm.jmp_rel8_label(p1_loop);

    // ALLOC pass1: read ss, vv → add r8, 8
    asm.set_label(h_alloc1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // READ pass1: read ss, ff → add r8, 8
    asm.set_label(h_read1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // WRITE pass1: read id, ff, ss → add r8, 12
    asm.set_label(h_write1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x0C]); // add r8, 12
    asm.jmp_rel8_label(p1_loop);

    // GET pass1: read dd, ss → add r8, 8
    asm.set_label(h_get1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // SUB pass1: read ss, vv → add r8, 8
    asm.set_label(h_sub1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // CMP pass1: read a, b → add r8, 8
    asm.set_label(h_cmp1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // INC pass1: read ss → add r8, 4
    asm.set_label(h_inc1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x04]); // add r8, 4
    asm.jmp_rel8_label(p1_loop);

    // DEC pass1: read ss → add r8, 4
    asm.set_label(h_dec1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x04]); // add r8, 4
    asm.jmp_rel8_label(p1_loop);

    // ADD pass1: read a, b → add r8, 8
    asm.set_label(h_add1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // ADDV pass1: read a, b → add r8, 8
    asm.set_label(h_addv1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // SUBV pass1: read a, b → add r8, 8
    asm.set_label(h_subv1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x08]); // add r8, 8
    asm.jmp_rel8_label(p1_loop);

    // JMP pass1: read hh → add r8, 5
    asm.set_label(h_jmp1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x05]); // add r8, 5
    asm.jmp_rel8_label(p1_loop);

    // CALL pass1: read hh → add r8, 5
    asm.set_label(h_call1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x05]); // add r8, 5
    asm.jmp_rel8_label(p1_loop);

    // JCC pass1: read hh → add r8, 6
    asm.set_label(h_jcc1);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip1);
    raw(asm, &[0x49, 0x83, 0xC0, 0x06]); // add r8, 6
    asm.jmp_rel8_label(p1_loop);

    // ─── PASS 1 → PASS 2 ───
    asm.set_label(p1_done);
    // pass_flag = 1
    raw(asm, &[0x41, 0xC7, 0x86, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    asm.mov_rr(Reg::Rsi, Reg::R12);
    asm.lea_mem(Reg::Rdi, Reg::R14, 0x800);

    // ══════ PASS 2 ══════
    asm.set_label(p2_loop);
    emit_prefix_read(asm, sw, rh, skip2, p2_done, 0x80);
    asm.cmp_al_imm8(0x30); asm.jcc_rel8_label(4, h_set2);
    asm.cmp_al_imm8(0x40); asm.jcc_rel8_label(4, h_hand2);
    asm.cmp_al_imm8(0x41); asm.jcc_rel8_label(4, h_call2);
    asm.cmp_al_imm8(0x60); asm.jcc_rel8_label(4, h_get2);
    asm.cmp_al_imm8(0x62); asm.jcc_rel8_label(4, h_sub2);
    asm.cmp_al_imm8(0x65); asm.jcc_rel8_label(4, h_cmp2);
    asm.cmp_al_imm8(0x66); asm.jcc_rel8_label(4, h_inc2);
    asm.cmp_al_imm8(0x67); asm.jcc_rel8_label(4, h_dec2);
    asm.cmp_al_imm8(0x68); asm.jcc_rel8_label(4, h_add2);
    asm.cmp_al_imm8(0x69); asm.jcc_rel8_label(4, h_addv2);
    asm.cmp_al_imm8(0x6A); asm.jcc_rel8_label(4, h_subv2);
    asm.cmp_al_imm8(0x70); asm.jcc_rel8_label(4, h_jmp2);
    asm.cmp_al_imm8(0x71); asm.jcc_rel8_label(2, after_jcc2);
    asm.cmp_al_imm8(0x7B); asm.jcc_rel8_label(3, after_jcc2);
    asm.jmp_rel8_label(h_jcc2);
    asm.set_label(after_jcc2);
    asm.cmp_al_imm8(0x20); asm.jcc_rel8_label(4, h_alloc2);
    asm.cmp_al_imm8(0x50); asm.jcc_rel8_label(4, h_read2);
    asm.cmp_al_imm8(0x51); asm.jcc_rel8_label(4, h_write2);
    asm.cmp_al_imm8(0xFF); asm.jcc_rel8_label(4, h_ret2);
    asm.jmp_rel8_label(skip2);

    // SET pass2: emit 49 C7 46 <ss*8> <vv:i32> (8 B) into output buffer via stosb/stosd
    asm.set_label(h_set2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (vv → R8B)
    // Emit prefix bytes: 49 C7 47 (REX.WB + MOV r/m64 + ModRM [R15+disp8])
    raw(asm, &[0xB0, 0x49]); asm.stosb(); // mov al, 0x49; stosb
    raw(asm, &[0xB0, 0xC7]); asm.stosb(); // mov al, 0xC7; stosb
    raw(asm, &[0xB0, 0x47]); asm.stosb(); // mov al, 0x47; stosb
    // Compute disp8 = R9B * 8, emit via stosb
    raw(asm, &[0x41, 0x8A, 0xC1]); // mov al, r9b
    raw(asm, &[0xC0, 0xE0, 0x03]); // shl al, 3
    asm.stosb(); // emit disp8, RDI++
    // Zero-extend vv to EAX and emit simm32 via stosd
    raw(asm, &[0x31, 0xC0]); // xor eax, eax
    raw(asm, &[0x41, 0x8A, 0xC0]); // mov al, r8b
    asm.stosd(); // emit simm32, RDI += 4
    asm.jmp_rel8_label(p2_loop);

    // GET pass2: emit 49 8B 47 <src*8> 49 89 47 <dst*8> (8B)
    asm.set_label(h_get2);
    emit_direct_call(asm, sw); emit_direct_call(asm, rh);
    asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]);
    emit_direct_call(asm, sw); emit_direct_call(asm, rh);
    asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]);
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x89]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // HANDLER pass2: read hh byte (just skip it, offset already recorded in pass1), no code emitted
    asm.set_label(h_hand2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    asm.jmp_rel8_label(p2_loop);

    // RET pass2: emit C3 (ret)
    asm.set_label(h_ret2);
    raw(asm, &[0xB0, 0xC3]); asm.stosb(); // mov al, 0xC3; stosb → emit C3 into output buffer
    asm.jmp_rel8_label(p2_loop);

    // SUB pass2: emit 49 81 6F <ss*8> <vv:i32> (8 B)
    asm.set_label(h_sub2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (vv → R8B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); // REX.WB
    raw(asm, &[0xB0, 0x81]); asm.stosb(); // sub r/m64, imm32
    raw(asm, &[0xB0, 0x6F]); asm.stosb(); // ModRM [R15+disp8], sub ext
    raw(asm, &[0x41, 0x8A, 0xC1]); // mov al, r9b
    raw(asm, &[0xC0, 0xE0, 0x03]); // shl al, 3
    asm.stosb(); // disp8
    raw(asm, &[0x31, 0xC0]); // xor eax, eax
    raw(asm, &[0x41, 0x8A, 0xC0]); // mov al, r8b
    asm.stosd(); // simm32
    asm.jmp_rel8_label(p2_loop);

    // CMP pass2: emit 49 8B 47 <a*8> 49 3B 47 <b*8> (8 B)
    asm.set_label(h_cmp2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (a → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (b → R8B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x3B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // INC pass2: emit 49 FF 47 <ss*8> (4 B)
    asm.set_label(h_inc2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0xFF]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // DEC pass2: emit 49 FF 4F <ss*8> (4 B)
    asm.set_label(h_dec2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0xFF]); asm.stosb();
    raw(asm, &[0xB0, 0x4F]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // ADD pass2: emit 49 8B 47 <b*8> 49 01 47 <a*8> (8 B)
    asm.set_label(h_add2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (a → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (b → R8B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x01]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // ADDV pass2: same as ADD (state[a] += state[b])
    asm.set_label(h_addv2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (a → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (b → R8B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x01]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // SUBV pass2: emit 49 8B 47 <b*8> 49 29 47 <a*8> (8 B, state[a] -= state[b])
    asm.set_label(h_subv2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (a → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (b → R8B)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x29]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // ══ JMP pass2: emit E9 [rel32 placeholder] (5 B), record fixup via stack ══
    asm.set_label(h_jmp2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (hh → R8B)
    // rel32_ofs = RDI - R14 - 0x800 + 1 → R9D
    raw(asm, &[0x41, 0x89, 0xF9]); // mov r9d, edi
    raw(asm, &[0x4D, 0x29, 0xF1]); // sub r9d, r14d
    raw(asm, &[0x41, 0x81, 0xE9, 0x00, 0x08, 0x00, 0x00]); // sub r9d, 0x800
    raw(asm, &[0x41, 0x83, 0xC1, 0x01]); // add r9d, 1
    // Emit E9 + placeholder
    raw(asm, &[0xB0, 0xE9]); asm.stosb();
    raw(asm, &[0x31, 0xC0]); asm.stosd();
    // Record fixup: push rel32_ofs, push hh (stack grows down; pop hh first)
    raw(asm, &[0x41, 0x51]); // push r9  (rel32_ofs)
    raw(asm, &[0x41, 0x50]); // push r8  (hh)
    raw(asm, &[0x45, 0xFF, 0xC7]); // inc r15d (fixup count)
    asm.jmp_rel8_label(p2_loop);

    // ══ CALL pass2: emit E8 [rel32 placeholder] (5 B), record fixup ══
    asm.set_label(h_call2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (hh → R8B)
    raw(asm, &[0x41, 0x89, 0xF9]); // mov r9d, edi
    raw(asm, &[0x4D, 0x29, 0xF1]); // sub r9d, r14d
    raw(asm, &[0x41, 0x81, 0xE9, 0x00, 0x08, 0x00, 0x00]); // sub r9d, 0x800
    raw(asm, &[0x41, 0x83, 0xC1, 0x01]); // add r9d, 1
    raw(asm, &[0xB0, 0xE8]); asm.stosb();
    raw(asm, &[0x31, 0xC0]); asm.stosd();
    raw(asm, &[0x41, 0x51]); // push r9  (rel32_ofs)
    raw(asm, &[0x41, 0x50]); // push r8  (hh)
    raw(asm, &[0x45, 0xFF, 0xC7]); // inc r15d
    asm.jmp_rel8_label(p2_loop);

    // ══ JCC pass2: emit 0F <cc> [rel32 placeholder] (6 B), record fixup ══
    asm.set_label(h_jcc2);
    raw(asm, &[0x41, 0x88, 0xC3]); // mov r11b, al (save opcode)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (hh → R8B)
    // rel32_ofs = RDI - R14 - 0x800 + 2 → R9D
    raw(asm, &[0x41, 0x89, 0xF9]); // mov r9d, edi
    raw(asm, &[0x4D, 0x29, 0xF1]); // sub r9d, r14d
    raw(asm, &[0x41, 0x81, 0xE9, 0x00, 0x08, 0x00, 0x00]); // sub r9d, 0x800
    raw(asm, &[0x41, 0x83, 0xC1, 0x02]); // add r9d, 2
    // Emit 0F
    raw(asm, &[0xB0, 0x0F]); asm.stosb();
    // Emit cc = jcc_table[opcode - 0x71] via R10
    raw(asm, &[0x41, 0x8A, 0xC3]); // mov al, r11b (restore opcode)
    raw(asm, &[0x2C, 0x71]);       // sub al, 0x71
    raw(asm, &[0x0F, 0xB6, 0xC8]); // movzx ecx, al
    raw(asm, &[0x41, 0x8A, 0x04, 0x0A]); // mov al, [r10 + rcx]
    asm.stosb();
    raw(asm, &[0x31, 0xC0]); asm.stosd(); // placeholder
    raw(asm, &[0x41, 0x51]); // push r9  (rel32_ofs)
    raw(asm, &[0x41, 0x50]); // push r8  (hh)
    raw(asm, &[0x45, 0xFF, 0xC7]); // inc r15d
    asm.jmp_rel8_label(p2_loop);

    // ══ ALLOC pass2: emit VirtualAlloc(0, vv, MEM_RW, PAGE_RW) → store to state[ss] ══
    // Emitted: xor ecx,ecx; xor edx,edx; mov dl,r8b; mov r8d,0x3000; mov r9d,0x40;
    //          sub rsp,0x28; FF 15 00 00 00 00; add rsp,0x28; mov [r15+ss*8],rax
    asm.set_label(h_alloc2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (vv → R8B)
    // xor ecx, ecx (31 C9)
    raw(asm, &[0xB0, 0x31]); asm.stosb(); raw(asm, &[0xB0, 0xC9]); asm.stosb();
    // xor edx, edx (31 D2)
    raw(asm, &[0xB0, 0x31]); asm.stosb(); raw(asm, &[0xB0, 0xD2]); asm.stosb();
    // mov dl, r8b (44 88 C2)
    raw(asm, &[0xB0, 0x44]); asm.stosb(); raw(asm, &[0xB0, 0x88]); asm.stosb(); raw(asm, &[0xB0, 0xC2]); asm.stosb();
    // mov r8d, 0x3000 (41 B8 00 30 00 00)
    raw(asm, &[0xB0, 0x41]); asm.stosb(); raw(asm, &[0xB0, 0xB8]); asm.stosb();
    raw(asm, &[0xB8]); asm.emit_u32(0x3000); asm.stosd();
    // mov r9d, 0x40 (41 B9 40 00 00 00)
    raw(asm, &[0xB0, 0x41]); asm.stosb(); raw(asm, &[0xB0, 0xB9]); asm.stosb();
    raw(asm, &[0xB8]); asm.emit_u32(0x40); asm.stosd();
    // sub rsp, 0x28 (48 83 EC 28)
    raw(asm, &[0xB0, 0x48]); asm.stosb(); raw(asm, &[0xB0, 0x83]); asm.stosb();
    raw(asm, &[0xB0, 0xEC]); asm.stosb(); raw(asm, &[0xB0, 0x28]); asm.stosb();
    // FF 15 00 00 00 00 (VirtualAlloc IAT thunk, api_index=0)
    raw(asm, &[0xB0, 0xFF]); asm.stosb(); raw(asm, &[0xB0, 0x15]); asm.stosb();
    raw(asm, &[0x31, 0xC0]); raw(asm, &[0xB0, 0x00]); asm.stosd(); // EAX=0 → writes 00 00 00 00
    // add rsp, 0x28 (48 83 C4 28)
    raw(asm, &[0xB0, 0x48]); asm.stosb(); raw(asm, &[0xB0, 0x83]); asm.stosb();
    raw(asm, &[0xB0, 0xC4]); asm.stosb(); raw(asm, &[0xB0, 0x28]); asm.stosb();
    // mov [r15+ss*8], rax (49 89 47 <ss*8>)
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x89]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    // Compute disp8 = R9B * 8, emit via stosb
    raw(asm, &[0x41, 0x8A, 0xC1]); // mov al, r9b
    raw(asm, &[0xC0, 0xE0, 0x03]); // shl al, 3
    asm.stosb(); // emit disp8, RDI++
    asm.jmp_rel8_label(p2_loop);

    // ══ READ pass2: emit loadfile sequence ══
    // Emitted: load state[ff]→RCX; CreateFileA; GetFileSize; VirtualAlloc; ReadFile; CloseHandle
    // store buffer to state[ss], fileSize to state[ss+1]
    asm.set_label(h_read2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B, dest slot)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (ff → R8B, filename slot)
    // TODO: emit full READ sequence (CreateFileA + GetFileSize + VirtualAlloc + ReadFile + CloseHandle)
    asm.jmp_rel8_label(p2_loop);

    // ══ WRITE pass2: emit writefile sequence ══
    // Emitted: load state[ff]→RCX; CreateFileA; WriteFile(state[id], state[ss]); CloseHandle
    asm.set_label(h_write2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (id → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (ff → R8B, filename slot)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC3]); // mov r11b, al (ss → R11B, size slot)
    // TODO: emit full WRITE sequence (CreateFileA + WriteFile + CloseHandle)
    asm.jmp_rel8_label(p2_loop);

    // ---- Skip to EOL (pass 1) ----
    asm.set_label(skip1);
    emit_skip_eol(asm, p1_loop);

    // ── Skip to EOL (pass 2) ──
    asm.set_label(skip2);
    emit_skip_eol(asm, p2_loop);

    // ══════ FIXUP RESOLUTION (stack-based) ══════
    asm.set_label(p2_done);
    // Check fixup count in R15D
    let after_fixup = asm.alloc_label();
    raw(asm, &[0x45, 0x85, 0xFF]); // test r15d, r15d
    asm.jcc_rel8_label(4, after_fixup); // jz after_fixup (no fixups → skip)

    // fixup_loop:
    let fixup_loop = asm.alloc_label();
    asm.set_label(fixup_loop);
    // Pop fixup entry: hh then rel32_ofs
    raw(asm, &[0x41, 0x59]); // pop r9  (R9 = hh)
    raw(asm, &[0x41, 0x5A]); // pop r10 (R10 = rel32_ofs)

    // handler_off = *(u32*)(R14 + hh*4)
    raw(asm, &[0x41, 0x8B, 0xC1]); // mov eax, r9d   (EAX = hh)
    raw(asm, &[0xC1, 0xE0, 0x02]); // shl eax, 2     (EAX = hh * 4)
    raw(asm, &[0x4C, 0x01, 0xF0]); // add rax, r14   (RAX = &handler_offsets[hh])
    raw(asm, &[0x8B, 0x00]);       // mov eax, [rax] (EAX = handler_off)

    // rel32 = handler_off - rel32_ofs - 4
    raw(asm, &[0x44, 0x29, 0xD0]); // sub eax, r10d (EAX -= rel32_ofs)
    raw(asm, &[0x83, 0xE8, 0x04]); // sub eax, 4

    // patch_addr = R14 + 0x800 + rel32_ofs
    raw(asm, &[0x4D, 0x8D, 0x86, 0x00, 0x08, 0x00, 0x00]); // lea r8, [r14+0x800]
    raw(asm, &[0x4D, 0x01, 0xD0]); // add r8, r10    (R8 = patch_addr)
    raw(asm, &[0x41, 0x89, 0x00]); // mov [r8], eax  (patch)

    raw(asm, &[0x45, 0xFF, 0xCF]); // dec r15d
    raw(asm, &[0x75, 0xD4]); // jnz fixup_loop (rel8 back, ~44 bytes)

    asm.set_label(after_fixup);
    // Output code base and size
    asm.lea_mem(Reg::Rdx, Reg::R14, 0x800);
    asm.mov_rr(Reg::Rax, Reg::Rdi);
    asm.sub_rr(Reg::Rax, Reg::R14);
    raw(asm, &[0x48, 0x2D, 0x00, 0x08, 0x00, 0x00]); // sub rax, 0x800

    // ── Epilogue (reverse order of pushes: LIFO) ──
    asm.add_imm(Reg::Rsp, 0x10);
    asm.pop(Reg::R15); // restore state pointer
    for &r in &[Reg::R9, Reg::R8, Reg::Rdi, Reg::Rsi, Reg::Rbx, Reg::R14, Reg::R13, Reg::R12] {
        asm.pop(r);
    }

    Ok(())
}

/// Emit prefix reading: reads 00 00 <opcode>, returns AL=opcode.
/// Jumps to `skip` on bad hex / bad prefix bytes.
/// Jumps to `done` on EOF (from skip_ws returning CF).
fn emit_prefix_read(asm: &mut X64Assembler, sw: usize, rh: usize, skip: usize, done: usize, _max_jmp: u8) {
    // byte 1: must be 00
    asm.call_rel32_label(sw); asm.jcc_rel32_label(2, done); // EOF → done (rel32 because done is far)
    asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip); // bad hex → skip
    asm.cmp_al_imm8(0); asm.jcc_rel8_label(5, skip); // != 0 → skip
    // byte 2: must be 00
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip);
    asm.cmp_al_imm8(0); asm.jcc_rel8_label(5, skip); // != 0 → skip
    // byte 3: opcode (any value OK)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip);
    // AL = opcode, fall through to dispatch
}

/// Skip to end of line (next \n or \r or EOF).
fn emit_skip_eol(asm: &mut X64Assembler, next: usize) {
    let top = asm.alloc_label();
    let eol = asm.alloc_label();
    asm.set_label(top);
    asm.cmp_rr(Reg::Rsi, Reg::R13); asm.jcc_rel8_label(2, eol); // EOF
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.cmp_al_imm8(b'\n'); asm.jcc_rel8_label(4, eol);
    asm.cmp_al_imm8(b'\r'); asm.jcc_rel8_label(4, eol);
    asm.inc(Reg::Rsi);
    asm.jmp_rel8_label(top);
    asm.set_label(eol);
    asm.jmp_rel8_label(next);
}

// ══════════════════════════════════════════
// Subroutines
// ══════════════════════════════════════════

fn emit_skip_ws(asm: &mut X64Assembler) -> usize {
    let lbl = asm.alloc_label();
    let top = asm.alloc_label();
    let adv = asm.alloc_label();
    let cmt = asm.alloc_label();
    let hexc = asm.alloc_label();
    let eof = asm.alloc_label();

    asm.set_label(lbl);
    asm.set_label(top);
    asm.cmp_rr(Reg::Rsi, Reg::R13);
    asm.jcc_rel8_label(3, eof); // JAE → EOF
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.xlatb();
    asm.cmp_al_imm8(0xFF);
    asm.jcc_rel8_label(5, hexc); // JNE → found hex char
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.cmp_al_imm8(b' ');  asm.jcc_rel8_label(4, adv);
    asm.cmp_al_imm8(b'\t'); asm.jcc_rel8_label(4, adv);
    asm.cmp_al_imm8(b'\n'); asm.jcc_rel8_label(4, adv);
    asm.cmp_al_imm8(b'\r'); asm.jcc_rel8_label(4, adv);
    asm.cmp_al_imm8(b';');  asm.jcc_rel8_label(4, cmt);
    asm.cmp_al_imm8(b'#');  asm.jcc_rel8_label(4, cmt);
    asm.jmp_rel8_label(adv);

    asm.set_label(adv);
    asm.inc(Reg::Rsi);
    asm.jmp_rel8_label(top);

    asm.set_label(cmt);
    asm.cmp_rr(Reg::Rsi, Reg::R13);
    asm.jcc_rel8_label(3, eof);
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.cmp_al_imm8(b'\n'); asm.jcc_rel8_label(4, adv);
    asm.cmp_al_imm8(b'\r'); asm.jcc_rel8_label(4, adv);
    asm.inc(Reg::Rsi);
    asm.jmp_rel8_label(cmt);

    asm.set_label(hexc);
    asm.clc();
    asm.ret();
    asm.set_label(eof);
    asm.stc();
    asm.ret();
    lbl
}

fn emit_read_hex(asm: &mut X64Assembler) -> usize {
    let lbl = asm.alloc_label();
    let err = asm.alloc_label();
    asm.set_label(lbl);
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.xlatb();
    asm.cmp_al_imm8(0xFF);
    asm.jcc_rel8_label(4, err);
    asm.shl_al_imm8(4);
    asm.movzx_ecx_al();
    asm.inc(Reg::Rsi);
    asm.cmp_rr(Reg::Rsi, Reg::R13);
    asm.jcc_rel8_label(3, err);
    asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi);
    asm.xlatb();
    asm.cmp_al_imm8(0xFF);
    asm.jcc_rel8_label(4, err);
    asm.or_al_cl();
    asm.inc(Reg::Rsi);
    asm.clc();
    asm.ret();
    asm.set_label(err);
    asm.stc();
    asm.ret();
    lbl
}
