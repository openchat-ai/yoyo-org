# Sub-Exp A — COMPLETED (renderer chunks misalignment bug fixed)

> **Date**: 2026-07-15
> **Bug ID**: 003-A
> **Subject**: `yoy0-rust/verifier/src/render.rs` chunk-based disasm slicing
> **Status**: ✅ DONE — `cargo build --release` succeeds, decode realigned, link byte-equal

---

## 1. Root Cause

`chunks_for_source_line` (was render.rs:161) returned a hardcoded
**"x86 chunks per TIR op"** count from a per-opcode lookup table.
This count had no relation to actual emit behavior:
- `emit.rs` produces **1 X86Chunk per TIR op** (each chunk has
  `byte_offset` + `bytes` + `tir_source_line`)
- `disasm.rs` produces **K DisasmLines per TIR op** (K = number of
  x64 instructions the TIR op expands into)

The renderer then took **the wrong number of DisasmLines** for each
source line, desynchronizing the SOURCE / TIR / X86 three-column output.

## 2. Fix Applied

Edited `render.rs`:
1. **Signature change**: `render_three_column` now takes a 4th arg
   `chunks: &[X86Chunk]` (imported `crate::emit::X86Chunk`)
2. **Disasm slicing**: replaced `chunks_for_source_line(&line_tirs)` call
   with a chunk-based loop:
   ```rust
   for chunk in chunks.iter() {
       if chunk.tir_source_line != line.line_no { continue; }
       let chunk_end = chunk.byte_offset + chunk.bytes.len() as u32;
       while disasm_idx + advance_disasm < disasm.len() {
           let d = &disasm[disasm_idx + advance_disasm];
           if d.byte_offset < chunk.byte_offset { advance_disasm += 1; continue; }
           if d.byte_offset >= chunk_end { break; }
           disasm_lines.push(d);
           advance_disasm += 1;
       }
   }
   ```
3. **Removed dead code**: deleted `chunks_for_source_line` (114 lines) +
   its unused `TirOp` imports in that section.
4. **main.rs:102** updated to pass chunks from `emit_with_chunks`.

Also cleaned: redundant `let x86_program = emit::emit(&tir_program);` line
in main.rs run_decode, switched to `let (x86_bytes, chunks) = emit::emit_with_chunks(&tir_program);`.

## 3. Verification

### 3.1 Build

`cargo build --release` succeeded in 9.47s (no new warnings introduced
beyond pre-existing unused-import in fixup.rs & IsaError dead-code).

### 3.2 Decode Realignment

`yoyo.exe decode yoy0/projects/yoy0.ty > .../rust-decode-post-fix.txt`

Before fix (exp 002):
```
Line 124: 61 0E 07   add state[0x0E], 0x7   [0x01F0] jmp H_??  ; rel=-274, target=0x00FF   ← WRONG (line 124 = ADD, X86 column = jmp from line 130)
                                                ret
                                                mov rax, [r15+0x70]
```

After fix (this sub-exp):
```
Line 124: 61 0E 07   add state[0x0E], 0x7   [0x01F0] mov rax, [r15+0x70]   ← CORRECT
Line 130: 61 0E 04   add state[0x0E], 0x4   [0x0200] mov rax, [r15+0x70]   ← CORRECT
Line 150: 70 01       jmp H_01               [0x0246] jmp H_??  ; rel=-332, target=0x00FF   ← jmp at correct source line
```

**All three lines now align** between TIR column and X86 column.

### 3.3 No Regression in Emit/Fixup/Pe_Link

```
yoyo.exe link yoy0/projects/yoy0.ty →  build\yoy0-v0.1-rust-post-fix.exe

Sub-002 pre-fix  attempt.exe  :  1605 B, SHA256 E4311DC265F5D8605AF40EC888D68DFFF047345BB77657BFA948F3F5FE1539F7
Sub-A  post-fix post-fix.exe  :  1605 B, SHA256 E4311DC265F5D8605AF40EC888D68DFFF047345BB77657BFA948F3F5FE1539F7
                                                                ↑ byte-identical
```

The link output is byte-equal with the pre-fix binary. The renderer
change is cosmetic (decode output only); emit + fixup + pe_link paths
produce the same bytes.

## 4. Open Questions

After Sub-A, decode output reveals a **separate** Phase 2 root-cause bug
unrelated to rendering:
- Line 150 `70 01` (jmp H_01) shows `rel=-332, target=0x00FF` —
  the disassembler computes `offset + inst_len + rel` where the rel32
  bytes are still 0x00 placeholders OR the fixup pass has an off-by-N bug.
- This bug is **NOT** fixed in Sub-A. It will be addressed in
  Sub-D (or as part of 003-C if it turns out to be in pe_link rel32).

## 5. Commit Plan

This sub-exp will be committed as a single Rust change + this completion report.
