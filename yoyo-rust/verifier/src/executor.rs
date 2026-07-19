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

fn hex_table() -> Vec<u8> {
    let mut t = vec![0xFFu8; 256];
    for c in b'0'..=b'9' { t[c as usize] = c - b'0'; }
    for c in b'A'..=b'F' { t[c as usize] = 10 + c - b'A'; }
    for c in b'a'..=b'f' { t[c as usize] = 10 + c - b'a'; }
    t
}

fn raw(asm: &mut X64Assembler, b: &[u8]) { asm.bytes.extend_from_slice(b); }

pub fn emit_v3_executor(asm: &mut X64Assembler) -> IsaResult<()> {
    let hex_lbl = asm.alloc_label();
    let after_tbl = asm.alloc_label();
    let main_start = asm.alloc_label();
    let after_sub = asm.alloc_label();

    // ── Prologue (executed FIRST at runtime) ──
    for &r in &[Reg::R12, Reg::R13, Reg::R14, Reg::Rbx, Reg::Rsi, Reg::Rdi, Reg::R8, Reg::R9] {
        asm.push(r);
    }
    asm.sub_imm(Reg::Rsp, 0x10);
    asm.mov_rr(Reg::R13, Reg::R12); asm.add_rr(Reg::R13, Reg::Rdx);
    asm.mov_imm64(Reg::Rcx, 0); asm.mov_imm64(Reg::Rdx, 0x40000);
    asm.mov_imm64(Reg::R8, 0x3000); asm.mov_imm64(Reg::R9, 0x40);
    asm.shadow_frame();
    asm.call_iat_thunk(Win32Api::VirtualAlloc as u8);
    asm.shadow_ret();
    asm.mov_rr(Reg::R14, Reg::Rax);

    // Hex table
    asm.jmp_rel32_label(after_tbl);
    asm.set_label(hex_lbl); raw(asm, &hex_table());
    asm.set_label(after_tbl);

    let rip = asm.bytes.len() as i64;
    let tbl = asm.get_label_offset(hex_lbl) as i64;
    asm.lea_rbx_rip((tbl - rip - 7) as i32);

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

    // ══════ PASS 1 ══════
    asm.set_label(p1_loop);
    emit_prefix_read(asm, sw, rh, skip1, p1_done, 0x80);
    // Dispatch SET(0x30), HANDLER(0x40), RET(0xFF)
    asm.cmp_al_imm8(0x30); asm.jcc_rel8_label(4, h_set1);
    asm.cmp_al_imm8(0x40); asm.jcc_rel8_label(4, h_hand1);
    asm.cmp_al_imm8(0x60); asm.jcc_rel8_label(4, h_get1);
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
    asm.cmp_al_imm8(0x60); asm.jcc_rel8_label(4, h_get2);
    asm.cmp_al_imm8(0xFF); asm.jcc_rel8_label(4, h_ret2);
    asm.jmp_rel8_label(skip2);

    // SET pass2: emit 49 C7 46 <ss*8> <vv:i32> (8 B) into output buffer via stosb/stosd
    asm.set_label(h_set2);
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]); // mov r9b, al (ss → R9B)
    asm.call_rel32_label(sw); asm.call_rel32_label(rh); asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]); // mov r8b, al (vv → R8B)
    // Emit prefix bytes: 49 C7 46
    raw(asm, &[0xB0, 0x49]); asm.stosb(); // mov al, 0x49; stosb
    raw(asm, &[0xB0, 0xC7]); asm.stosb(); // mov al, 0xC7; stosb
    raw(asm, &[0xB0, 0x46]); asm.stosb(); // mov al, 0x46; stosb
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
    { let o=asm.bytes.len(); let tp=asm.get_label_offset(sw); let d=(tp as i32-(o as i32+5)).to_le_bytes();
      asm.emit_u8(0xE8); asm.emit_u8(d[0]); asm.emit_u8(d[1]); asm.emit_u8(d[2]); asm.emit_u8(d[3]); }
    { let o=asm.bytes.len(); let tp=asm.get_label_offset(rh); let d=(tp as i32-(o as i32+5)).to_le_bytes();
      asm.emit_u8(0xE8); asm.emit_u8(d[0]); asm.emit_u8(d[1]); asm.emit_u8(d[2]); asm.emit_u8(d[3]); }
    asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC1]);
    { let o=asm.bytes.len(); let tp=asm.get_label_offset(sw); let d=(tp as i32-(o as i32+5)).to_le_bytes();
      asm.emit_u8(0xE8); asm.emit_u8(d[0]); asm.emit_u8(d[1]); asm.emit_u8(d[2]); asm.emit_u8(d[3]); }
    { let o=asm.bytes.len(); let tp=asm.get_label_offset(rh); let d=(tp as i32-(o as i32+5)).to_le_bytes();
      asm.emit_u8(0xE8); asm.emit_u8(d[0]); asm.emit_u8(d[1]); asm.emit_u8(d[2]); asm.emit_u8(d[3]); }
    asm.jcc_rel8_label(2, skip2);
    raw(asm, &[0x41, 0x88, 0xC0]);
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x8B]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC0]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    raw(asm, &[0xB0, 0x49]); asm.stosb(); raw(asm, &[0xB0, 0x89]); asm.stosb();
    raw(asm, &[0xB0, 0x47]); asm.stosb();
    raw(asm, &[0x41, 0x8A, 0xC1]); raw(asm, &[0xC0, 0xE0, 0x03]); asm.stosb();
    asm.jmp_rel8_label(p2_loop);

    // ---- Skip to EOL (pass 1) ----
    // ---- Skip to EOL (pass 1) ---- ──
    asm.set_label(skip1);
    emit_skip_eol(asm, p1_loop);

    // ── Skip to EOL (pass 2) ──
    asm.set_label(skip2);
    emit_skip_eol(asm, p2_loop);

    // ── Done ──
    asm.set_label(p2_done);
    // Output buffer layout: handler_offsets[0x000..0x400), fixups[0x408..0x800), code[0x800..]
    // RDX = output buffer base (=R14 + 0x800, start of actual emitted code)
    // RAX = emitted code size (RDI - R14 - 0x800)
    asm.lea_mem(Reg::Rdx, Reg::R14, 0x800);
    asm.mov_rr(Reg::Rax, Reg::Rdi);
    asm.sub_rr(Reg::Rax, Reg::R14);
    raw(asm, &[0x48, 0x2D, 0x00, 0x08, 0x00, 0x00]); // sub rax, 0x800

    // ── Epilogue (reverse order of pushes: LIFO) ──
    asm.add_imm(Reg::Rsp, 0x10);
    for &r in &[Reg::R9, Reg::R8, Reg::Rdi, Reg::Rsi, Reg::Rbx, Reg::R14, Reg::R13, Reg::R12] {
        asm.pop(r);
    }

    // NOTE: resolve_fixups() is called from emit_h00_code, not here.
    // All labels must be set before fixup resolution.
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
