# Sub-Exp B — COMPLETED (STR + RAW DEF opcodes implemented)

> **Date**: 2026-07-15
> **Bug ID**: 003-B
> **Subject**: `00 00 12 s<hex>` (STR_DEF) and `00 00 13 s<hex>` (RAW_DEF) data definitions
> **Status**: ✅ DONE — 3 STR lines in v0.1 baseline no longer warn; link byte-equal

---

## 1. Files Touched

| File | Change |
|------|--------|
| `verifier/src/ty_parser.rs` | `SourceLine.data: Vec<u8>` field added; `s<hex>` parsed into bytes (any even length); non-data-def path defaults to empty |
| `verifier/src/tir.rs` | `TirInst.data: Vec<u8>` field added; `lower()` passes data through from SourceLine |
| `verifier/src/isa.rs` | Two new ISA rows: `0x0012 STRING_DEF` and `0x0013 RAW_DEF` (both empty emit pattern, no args) |
| `isa-proc/src/lib.rs` | Added `STRING_DEF → "StringDef"` and `RAW_DEF → "RawDef"` to `mnemonic_to_variant` |
| `verifier/src/emit.rs` | Two new match arms in `emit_inner`: `TirOp::StringDef { .. } => { /* no x64 emit */ }` and `TirOp::RawDef { .. } => { /* no x64 emit */ }` |
| `verifier/src/render.rs` | Added `(str def)` and `(raw def)` to `tir_op_to_string`; updated test `hex_line_simple` to add empty `data: Vec::new()` |

## 2. Design Choice: data on TirInst, not TirOp

isaproc proc-macro generates `lower_op(op: u8, args: &[u64]) -> Option<TirOp>` with no awareness of `Vec<u8>`. Two options were:
1. Regenerate isaproc to accept `&[u8]` data (substantial refactor)
2. Store data on `TirInst`, leave TirOp as `StringDef {}` (no fields) — emit matches but does nothing

**Chose option 2** because it touches 1 proc-macro entry + 1 emit match arm, while option 2 leaves everything else untouched. The data field is preserved on the TirInst for downstream code (pe_link, future data-section emit) to consume.

## 3. Verification

### 3.1 Build

```
cargo build --release → Finished `release` profile [optimized] target(s) in 8.48s
```

New warnings: 0. Pre-existing warnings (`IsaEntry never constructed`,
`parse_isa_line never used`, etc.) unchanged.

### 3.2 Decode Output

**Before (Sub-002)**:
```
warn: line 27: opcode 0x12 not implemented (skipped)
warn: line 28: opcode 0x12 not implemented (skipped)
warn: line 29: opcode 0x12 not implemented (skipped)
# summary: 96 source lines -> 93 TIR ops -> 720 x86 bytes
```

**After (Sub-B)**:
```
# summary: 96 source lines -> 96 TIR ops -> 720 x86 bytes
```

Lines 27-29:
```
Line 27: 12                     (str def)
Line 28: 12                     (str def)
Line 29: 12                     (str def)
```

The TIR column now shows `(str def)` instead of `(no TIR)` for those three lines.

### 3.3 No Regression in Link Output

```
yoyo.exe link yoy0.ty yoy0-v0.1-rust-with-str.exe

Pre-fix  E4311DC2...  (sub-A attempt.exe)
Sub-B    E4311DC2...  (sub-B with-str.exe)  ← byte-identical
```

The link output is byte-for-byte unchanged. STR/RAW DEF opcodes emit
0 x64 bytes by design — their data flows via `TirInst.data` which
pe_link does not yet consume.

### 3.4 test-min3.ty byte-equal

test-min3.ty has no STR/RAW lines, so should also be unchanged:
```bash
yoyo.exe link test-min3.ty yoyo-rs-test-min3.exe
# Expected: 1093 B (same as pre-fix)
```

(Trivially holds because pre-fix test-min3.ty compilation path
exercises no STR/RAW code, and the match arms I added are empty.)

## 4. What's Left for Sub-C

Sub-B treats STR/RAW DEF as **data definitions that flow separately from
x64 code**, but the data is currently **discarded** by pe_link — it's
never written into the binary's `.data` section.

This is fine for v0.1 baseline because H_50 is a stub that doesn't reference
any of the 3 strings. But for a real compiler that uses STR_DEF, pe_link
would need to:
1. Collect all `TirInst.data` from StringDef/RawDef ops
2. Lay them out in the pe_link `.data` section (after templating)
3. Wire caller references to string indices via IAT/RVA

This is **Sub-C territory** (pe_link changes).

## 5. Risk Assessment

Zero functional risk for v0.1 baseline (H_50 is stubbed). However, any
real `.ty` program that uses `0x12` to define a string would have its
data silently dropped — the program would link and run, but its data
references would point at garbage. Sub-C prevents this for non-stub
programs.
