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
0x0012 STRING_DEF => ; data definition, bytes flow via TirInst.data (no x64 emit)
0x0013 RAW_DEF    => ; data definition, bytes flow via TirInst.data (no x64 emit)
0x00A0 RAW_BYTE  byte  => raw_byte byte   ; emit single byte literal
0x00A1 RAW_BYTES bytes => raw_bytes bytes ; emit block of literal bytes

// ── libyoyo_* Calls (Phase 4c) ─────────────────────────────────────
0x0052 LIBYOYO_ALLOC slot sz      => emit_libyoyo_alloc slot sz
0x0053 LIBYOYO_FREE slot          => emit_libyoyo_free slot
0x0054 LIBYOYO_OPEN slot str_idx  => emit_libyoyo_open slot str_idx
0x0055 LIBYOYO_READ slot fd sz    => emit_libyoyo_read slot fd sz
0x0056 LIBYOYO_WRITE fd slot sz   => emit_libyoyo_write fd slot sz
0x0057 LIBYOYO_CLOSE fd           => emit_libyoyo_close fd
0x0058 LIBYOYO_EXIT slot          => emit_libyoyo_exit slot
0x0059 LIBYOYO_PRINT slot         => emit_libyoyo_print slot
0x005A LIBYOYO_TIME slot          => emit_libyoyo_time slot

// ── Legacy Syscall / Complex (deprecated by libyoyo_* above) ───────────
0x0020 ALLOC slot sz      => emit_alloc slot sz     ; VirtualAlloc (via platform) - deprecated
0x0050 LOADFILE slot str_idx => emit_loadfile slot str_idx  ; ReadFile (via platform) - deprecated
0x0051 WRITEFILE id str_idx sz => emit_writefile id str_idx sz  ; CreateFile+WriteFile+Close (via platform) - deprecated

} // isa!
