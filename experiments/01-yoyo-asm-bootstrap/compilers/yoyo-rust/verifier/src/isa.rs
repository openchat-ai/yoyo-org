// yoyo ISA table: opcode → TIR + emit pattern
// Format: OPCODE MNEMONIC [ARGS...] => emit_prim [args...]
// Lines before `=>` define the instruction; after `=>` documents the x64 emit.

isaproc::isa! {

// ── Integer / Control Flow ──────────────────────────────────────────
0x0030 SET slot imm   => movabs rax imm store_state slot rax
0x0060 GET dst src    => load_state src rax  store_state dst rax
0x0061 ADD slot imm   => load_state slot rax  add_imm rax imm  store_state slot rax
0x0062 SUB slot imm   => load_state slot rax  sub_imm rax imm  store_state slot rax
0x0065 CMP a b        => load_state a rax  load_state b rdx  cmp_reg rax rdx
0x0066 INC slot       => load_state slot rax  add_imm rax 1  store_state slot rax
0x0067 DEC slot       => load_state slot rax  sub_imm rax 1  store_state slot rax
0x0068 ADDV dst src   => load_state dst rax  load_state src rdx  add_reg rax rdx  store_state dst rax
0x0069 SUBV dst src   => load_state dst rax  load_state src rdx  sub_reg rax rdx  store_state dst rax
0x0063 IMUL dst src   => load_state dst rax  load_state src rdx  mul_reg rax rdx  store_state dst rax

// ── Handler / Branching ────────────────────────────────────────────
0x0040 HANDLER hh   => ; label only, no bytes
0x0041 CALL hh      => call_rel32 hh    ; rel32 fixed in second pass
0x0070 JMP hh       => jmp_rel32 hh     ; rel32 fixed in second pass
0x0071 JE hh        => jcc_rel32 4 hh   ; x64 JE = cc 4
0x0072 JNE hh       => jcc_rel32 5 hh   ; x64 JNE = cc 5
0x0073 JL hh        => jcc_rel32 12 hh  ; x64 JL = cc 12
0x0074 JGE hh       => jcc_rel32 13 hh  ; x64 JGE = cc 13
0x0075 JLE hh       => jcc_rel32 14 hh  ; x64 JLE = cc 14
0x0076 JG hh        => jcc_rel32 15 hh  ; x64 JG = cc 15
0x0077 JB hh        => jcc_rel32 2 hh   ; x64 JB = cc 2
0x0078 JAE hh       => jcc_rel32 3 hh   ; x64 JAE = cc 3
0x0079 JBE hh       => jcc_rel32 6 hh   ; x64 JBE = cc 6
0x007A JA hh        => jcc_rel32 7 hh   ; x64 JA = cc 7
0x00FF RET          => ret

// ── Memory ──────────────────────────────────────────────────────────
0x0080 LDB dd ss oo    => load_state ss rdx  movzx_rdx_byte rax  store_state dd rax
0x0084 MEMCPYD dd off sz => load_state dd rdi  lea_rsi_rip off  movabs rcx sz  rep_movsb
0x0085 MEMCPYS dd ss sz  => load_state dd rdi  load_state ss rsi  movabs rcx sz  rep_movsb

// ── Raw Data ────────────────────────────────────────────────────────
0x00A0 RAW_BYTE  byte  => raw_byte byte   ; emit single byte literal
0x00A1 RAW_BYTES bytes => raw_bytes bytes ; emit block of literal bytes

// ── Syscall / Complex ───────────────────────────────────────────────
0x0020 ALLOC slot sz      ; VirtualAlloc(0, sz, 0x3000, 0x40)
0x0050 LOADFILE slot str_idx  ; ReadFile(str_idx) state[slot]=ptr state[slot+1]=sz
0x0051 WRITEFILE id str_idx sz  ; CreateFileA+WriteFile+CloseHandle

} // isa!
