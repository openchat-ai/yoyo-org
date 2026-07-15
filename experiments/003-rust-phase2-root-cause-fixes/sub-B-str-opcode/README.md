# Sub-Exp B — STR (0x12) + RAW (0x13) opcode implementation

> **Date**: 2026-07-15
> **Subject**: `00 00 12 s<hex>` data-definition lines in v0.1 baseline (lines 27-29)
> **Status**: ⏳ IN PROGRESS — plan laid out below

---

## 1. The Gap

v0.1 baseline (`yoy0/projects/yoy0.ty`) has 3 STR data-definition lines:

```
27: 00 00 12 s73656e74696e656c3a2000              ; "sentine1: \0"
28: 00 00 12 s6572726f723a2000                    ; "error: \0"
29: 00 00 12 s636f6d70696c696e6720796f79302e747900  ; "compiling yoy0.ty\0"
```

When parsed by `ty_parser.rs` and emitted, the parser correctly identifies
`op=0x12` but skips arg parsing (line 71: `if op == 0x12 || op == 0x13`).
The data `s<hex>` token is **not parsed into bytes**.

Then `tir.rs:42-59 lower()` calls `isa::lower_op(0x12, &[])`. Since the ISA
table at `isa.rs` has no entry for `0x0012 STRING_DEF`, `lower_op` returns
`None` and `lower()` logs:

```
warn: line 27: opcode 0x12 not implemented (skipped)
```

`yoy0-rust` runs emit on only 93/96 TIR ops (skipping the 3 STR lines).

## 2. Goal

Implement `0x12` and `0x13` data-definition opcodes **without changing the
x64 bytes** generated for v0.1 baseline:
- Lines 27-29 emit no warnings
- `link yoy0.ty` output stays byte-equal `E4311DC2...` (since v0.1 baseline
  H_50 is a stub that doesn't actually use these strings)
- `lower_op(0x12, ...)` returns `Some(...)`
- `emit()` writes 0 bytes for `StringDef` / `RawDef` TIR ops
- `data: Vec<u8>` flows from parser → TIR → (skipped by emit) — but is
  preserved for downstream code that wants to use it

## 3. Approach (Option B from analysis: data on TirInst, not TirOp)

### 3.1 Why TirInst, not TirOp

isaproc currently generates `lower_op(op, args) -> Option<TirOp>` with
an `args: &[u64]` parameter. Adding `data: &[u8]` to this signature
requires regenerating isaproc. Simpler: store `data` on the `TirInst`
struct, not on the variant.

Since STR/RAW DEF emit 0 x64 bytes, they don't need a unique TirOp variant
at all. But `lower_op` must return `Some(_)` to suppress the "skipped"
warning. The variant can be a no-op like a new `TirOp::DataDef` that emit
matches but writes nothing.

### 3.2 Patches Required

**File 1: `verifier/src/ty_parser.rs`**

```rust
pub struct SourceLine {
    pub line_no: u32,
    pub op: u8,
    pub args: Vec<u64>,
    pub data: Vec<u8>,   // NEW: for 0x12/0x13 data-def lines
}
```

Modify the `if op == 0x12 || op == 0x13` branch to **parse `s<hex>` token
into `data: Vec<u8>`** (no length cap; hex digits parsed in pairs).

**File 2: `verifier/src/tir.rs`**

```rust
pub struct TirInst {
    pub source_line: u32,
    pub op: isa::TirOp,
    pub byte_offset: Option<u32>,
    pub data: Vec<u8>,   // NEW: passthrough from SourceLine.data
}

pub fn lower(source: &[SourceLine]) -> Vec<TirInst> {
    for line in source {
        ...
        out.push(TirInst {
            source_line: line.line_no,
            op,
            byte_offset: None,
            data: line.data.clone(),   // NEW
        });
    }
}
```

**File 3: `verifier/src/isa.rs`**

Add 2 isa table rows:
```
0x0012 STRING_DEF =>       ; data definition, no x64 bytes
0x0013 RAW_DEF   =>       ; data definition, no x64 bytes
```

**File 4: `isa-proc/src/lib.rs`**

Add `STRING_DEF => "StringDef"` and `RAW_DEF => "RawDef"` to
`mnemonic_to_variant`. (Existing logic handles no-args variants correctly:
emits just the variant name, `lower_op` returns `Some(TirOp::StringDef)`.)

**File 5: `verifier/src/emit.rs`**

Add 2 match arms in the giant `match &inst.op {}`:
```rust
TirOp::StringDef { .. } => { /* write 0 bytes */ }
TirOp::RawDef { .. }   => { /* write 0 bytes */ }
```

## 4. Acceptance

- `cargo build --release`: succeeds without new warnings
- `yoyo decode yoy0.ty`: no `warn: line XX: opcode 0x12 not implemented (skipped)` messages
- `yoyo link yoy0.ty yoy0-v0.1-rust-with-str.exe`:
  - SHA matches `E4311DC2...` (pre-fix hash) byte-for-byte
- `yoyo link test-min3.ty`: still 1093 B byte-equal to yoyo-asm/test-min3-rust.exe

## 5. Risk

Low. STR/RAW DEF emit 0 bytes, so the only way to introduce a regression
is if `lower()` change somehow alters TIR order or `byte_offset` record.
The `data: Vec<u8>` field is a passthrough that emit completely ignores.
