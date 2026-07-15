# Sub-Exp A — Fix renderer chunks/misalignment bug

> **Date**: 2026-07-15
> **Bug ID**: 003-A
> **Subject**: `yoy0-rust/verifier/src/render.rs:161` `chunks_for_source_line`
> **Status**: Pending — patch drafted below

---

## 1. The Bug

`chunks_for_source_line` (render.rs:161) returns **N hardcoded "chunks per TIR op"**
based on a `match &inst.op {}` lookup — but this number has no relation to what
`emit.rs` actually produces (which is **1 X86Chunk per TIR op**) or what
`disasm.rs` produces (which is **K DisasmLines per TIR op**, where K is the number of
x64 instructions emitted for that TIR op).

The renderer then calls `disasm.iter().skip(disasm_idx).take(chunks_for_line)`,
consuming the **wrong number of disasm lines** for every source line. This causes
the SOURCE/TIR/X86 three-column output to desynchronize after the first source line
whose TIR op emits >1 x86 chunks (e.g., `61 0E 07` → `mov rax, [r15+x]`, `add rax, 7`,
`mov [r15+x], rax` = 3 x86 instructions but the renderer takes 3 disasm lines
assuming the TIR op emitted 3 chunks).

## 2. Observed Symptom (from exp 002)

Line 124 is `61 0E 07` (ADD state[0x0E], 0x7) but its X86 column shows
`[0x01F0] jmp H_??  ; rel=-274, target=0x00FF` (with adjacent `ret`,
`mov rax, [r15+0x70]` lines). The TIR column says `add state[0x0E], 0x7` —
the X86 column is from a **different source line's** TIR ops, shifted by
exactly one buffered TIR-to-disasm mismatch.

## 3. Fix Strategy

Replace `chunks_for_source_line` with a function that:
1. Filters `chunks` to those where `chunk.tir_source_line == line.line_no`
2. For each such chunk, finds disasm lines whose `byte_offset` falls inside
   `[chunk.byte_offset, chunk.byte_offset + chunk.bytes.len())`
3. Returns the count

Then `render.rs` should iterate over the actual TIR ops in source order,
collecting both chunks and the disasm lines that fall in each chunk's byte range.
This stays correct regardless of how many x86 instructions emit per TIR op.

## 4. Patch Sketch

Replace line 41-54 of render.rs with:

```rust
let line_tirs: Vec<&TirInst> = tir.iter()
    .skip(tir_idx)
    .take_while(|t| t.source_line == line.line_no)
    .collect();
let advance_tir = line_tirs.len();

// Use chunks (one per TIR op) to slice disasm by byte_offset range
let mut disasm_lines: Vec<&DisasmLine> = Vec::new();
let mut consume_count = 0usize;
for chunk in chunks.iter() {
    if chunk.tir_source_line != line.line_no { continue; }
    let end = chunk.byte_offset + chunk.bytes.len() as u32;
    while disasm_idx + consume_count < disasm.len() {
        let d = &disasm[disasm_idx + consume_count];
        if d.byte_offset < chunk.byte_offset { continue; } // shouldn't happen but skip past
        if d.byte_offset >= end { break; }
        disasm_lines.push(d);
        consume_count += 1;
    }
}
let advance_disasm = consume_count;
```

Then `take(chunks_for_line)` becomes `take(advance_disasm)`.

## 5. Acceptance

- Line 124's X86 column becomes `mov rax, [r15+0x70]; add rax, 7; mov [r15+0x70], rax`
- All subsequent lines align: TIR column matches X86 column, no jmp/ret leak across lines
- Re-run `yoyo decode yoy0.ty` and diff output against `experiments/002/.../rust-decode-output.txt`
  (expected: only lines after the boundary shifts; no TIR/X86 mismatches)

## 6. Risk

Low — only the renderer changes; emit + fixup + pe_link untouched.
After rebuild, `link yoy0.ty` output hash must match the pre-fix hash byte-for-byte
(yoy0-rust/.../yoy0-v0.1-rust-attempt.exe = SHA `E4311DC2...`).
