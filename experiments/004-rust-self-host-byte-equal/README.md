# Sub-Exp 004 — yoy0-rust determinism + cross-impl byte-equal

> **Date**: 2026-07-15
> **Subject**: Trusting Trust byte-equal verification of yoy0-rust implementation
> **Status**: ⏳ IN PROGRESS

---

## 1. Scope

This sub-exp verifies that yoy0-rust (the Rust implementation of the yoyo
compiler) is **deterministic** and emits **byte-equivalent output** as the
asm implementation, for the same source input. This is Layer 1 of the
Trusting Trust self-host chain (Part 6 of PROMPT-v3.md).

We do NOT do **full M0→M1→M2→M3 self-host** in this sub-exp because it
requires a `yoy0.ty` source with a fully functional H_50 (file read) and
H_51 (file write) — that work belongs to Phase 4c/4d and is out of scope
here. See Section 4 (deferred work) below.

## 2. Layer 1 — yoy0-rust determinism

**Goal**: Same source file, yoy0-rust `link` called twice in succession
should produce byte-identical `.exe` files.

This is the weakest form of byte-equal but a necessary precondition for
any meaningful cross-impl DDC test (a non-deterministic compiler can't
have a meaningful hash).

## 3. Layer 2 — yoy0-rust vs yoy0-asm byte-equal

**Goal**: For the same small `.ty` source, yoy0-rust and yoy0-asm
produce byte-identical **x64 emit output** (excluding the Win64 PE
template, since yoy0-asm uses a different startup layout).

The Phase 4 "3-Chain DDC" spec (Part 6.2) compares `.text` bytes across all
three implementations, allowing differences in PE headers / startup blob.

## 4. Deferred to sub-005/sub-006 (full self-host)

Per PROMPT-v3.md Part 5.2 the full self-host chain:
```
M0 = yoy0.js (or yoy0-rust)
M0.compile(yoyo.ty v0.4-Win-24bit) → M1.exe
M1.compile(same yoyo.ty) → M2.exe
M2.compile(same yoyo.ty) → M3.exe
require SHA(M1) == SHA(M2) == SHA(M3)
```

This requires:
1. `yoyo.ty v0.4-Win-24bit` that includes working H_50 (libyoyo_open/read)
   and H_51 (libyoyo_close/write) implementation
2. yoy0.ty H_00 must parse CLI args (e.g., `argv[1]` = input.ky path)
3. yoy0.ty H_64 must write output.exe via H_51

Currently:
- H_50 is a stub (hardcodes `state[0xB]=4`) per Phase 5 simplification
- v0.1/v0.2 baselines don't do CLI parsing in H_00

This work needs Phase 4c libyoyo_* linker integration in yoyo.ty — a
3-day sub-effort, separated as `experiments/005-libyoyo-self-host`.
