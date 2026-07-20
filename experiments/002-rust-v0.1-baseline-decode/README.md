# Experiment 002 — yoy0-rust decodes v0.1 baseline (decode-only, no DDC yet)

> **Date**: 2026-07-15
> **Status**: Partial — yoy0-rust decoder runs but 3 known gaps block byte-equal DDC
> **Subject**: `F:\yoyo-org\yoy0\projects\yoy0.ty` (198-line raw 24-bit Iron-Rule Skeleton)
> **Authority**: This document + the captured decode output are the SOLE entry point

---

## 1. Hypothesis

`yoy0-rust/target/release/yoyo.exe` (the v0 Phase 4c verifier) running `decode yoy0.ty`
should reproduce the **same x64 bytes** that `yoy0-js/src/yoyo.js` would produce,
because both implementations target the same ISA.

## 2. Procedure

```bash
& "F:\yoyo-org\yoyo-rust\target\release\yoyo.exe" decode \
    "F:\yoyo-org\yoy0\projects\yoy0.ty" \
    > "F:\yoyo-org\experiments\002-rust-v0.1-baseline-decode\rust-decode-output.txt"
```

Captured output: `rust-decode-output.txt` (31460 bytes, 157 lines).

## 3. Observed Output

- **summary line**: `# summary: 96 source lines -> 93 TIR ops -> 720 x86 bytes`
- All HANDLER (0x40) labels render in SOURCE column
- All SET (0x30), ADD (0x61), JMP (0x70), RET (0xFF), RAW_BYTE (0xA0) decode correctly
- x86 column shows real `mov rax, ...; mov [r15+0x70], rax` for SET 0x0E
- x86 column shows real `mov rax, 0x07; add rax, 7; mov [r15+0x70], rax` for `61 0E 07` (state[0x0E] += 7)

### 3.1 Three Known Gaps Blocking Byte-Equal DDC

| # | Gap | Evidence | Phase |
|---|-----|----------|-------|
| 1 | **STR opcode (0x12) skipped** | "warn: line 27: opcode 0x12 not implemented (skipped)" × 3 (lines 27-29 = sentinel/error/compling strings in v0.1 baseline) | Phase 1 incomplete |
| 2 | **fixup pass mis-target** | x86 column shows `jmp H_?? ; rel=-274, target=0x00FF` for every `70 01` (jmp H_01) — H_01 is at offset 0x0063+ but emit patches target as 0x00FF | **Phase 2 root cause** |
| 3 | **disasm table incomplete** | Many bytes shown as `<unknown 0xC0>` (Rex prefix), `<unknown 0x49>`, etc. | Phase 0 disasm gap |

### 3.2 Slot dispatch is correct

- `state[0x0E]` → `mov [r15+0x70], rax` (4 bytes, disp8) — slot*8 = 0x70 ≤ 0x7F ✓
- `state[0x10]` → `mov [r15+0x0080], rax` (7 bytes, disp32) — slot*8 = 0x80 ≥ 0x80 ✓
- The Threshold=0x80 disp8/disp32 boundary is respected.

## 4. Verdict

yoy0-rust is **functionally working for the v0.1 baseline** (decode runs to completion),
but **Phase 2 root cause fixup** must happen **before** byte-equal DDC verification.

**Do NOT proceed** to exp 003 (Rust link v0.1 baseline) until gap #2 (fixup target)
is resolved — every jmp/call is broken.

## 5. Next Move

→ experiments/003-rust-fixup-phase2-root-cause

Goal: Make `yoy0-rust link v0.1.ty` produce a valid PE that runs and produces
an output.exe with H_01 jumps resolved correctly.
