# Sub-Exp 004 — COMPLETED (Layer 1+2; Layer 2 cross-impl blocked)

> **Date**: 2026-07-15
> **Subject**: yoy0-rust determinism + cross-impl byte-equal
> **Status**: ✅ Layer 1 PASS, ⚠️ Layer 2 PARTIAL (single-impl only)

---

## 1. Layer 1 — yoy0-rust Determinism

**Question**: Does `yoy0-rust link <same source>` produce byte-identical output
across repeated runs?

### 1.1 Test Setup

```bash
# Run same `link` command 3 times for test-min3.ty
yoy0.exe link test-min3.ty → A1.exe, A2.exe, A3.exe
# Run same `link` command 2 times for yoy0.ty v0.1 baseline
yoy0exe link yoy0.ty → B1.exe, B2exe
```

### 1.2 Results

| File | SHA-256 | Identical? |
|------|---------|------------|
| A1 | `04055B3DAA37D35C66803FA349C14CAEE3E8E62BD49BE45EC7DFA6327C27571A` | ✓ |
| A2 | `04055B3DAA37D35C66803FA349C14CAEE3E8E62BD49BE45EC7DFA6327C27571A` | ✓ |
| A3 | `04055B3DAA37D35C66803FA349C14CAEE3E8E62BD49BE45EC7DFA6327C27571A` | ✓ |
| B1 | `8D62F92CC3908117FA2488CCD9C277AF9446B32CB48768E75A4CC80BCC900022` | ✓ |
| B2 | `8D62F92CC3908117FA2488CCD9C277AF9446B32CB48768E75A4CC80BCC900022` | ✓ |

**Verdict**: yoy0-rust is deterministic. Same source → same SHA-256 across runs.

This is a **necessary precondition** for any meaningful cross-impl byte-equal DDC
test (Part 6 of PROMPT-v3.md requires DDC to compare reproducible outputs).

## 2. Layer 2 — Cross-Impl Byte-Equal

**Question**: Does yoy0-rust emit the same x86 bytes as yoy0-js / yoy0-asm for the same source?

### 2.1 Available Reference Implementations

| Impl | Path | Status |
|------|------|--------|
| yoy0-rust | `yoyo-rust/target/release/yoyo.exe` | ✅ functional (sub-C) |
| yoy0-js/test-min3-js.exe | `yoyo-js/test-min3-js.exe` (100352 B) | ⚠️ **bundled interpreter** — wrong artifact |
| yoy0-asm.exe | `yoyo-asm/yoyo-asm.exe` (24064 B) | ⚠️ historical, mini-PE (no OptionalHdr) |

### 2.2 Why Layer 2 Cross-Impl Cannot Run Yet

**yoy0-js/test-min3-js.exe** (100352 B) is the **bundled** output that yoy0.js
produces — it contains yoy0.js as embedded interpreter bytecode + Win32
wrapper. It is **not** a peer for direct cross-impl byte-equal with our
yoy0-rust `yoyo.exe` (which produces a bare ~1.5 KB PE).

**yoy0-asm.exe** (24064 B) uses a **minimal** PE template (PE32+ OptionalHdr
= 0 bytes), and is dated 7/10 — predates the Sub-C rewrite of yoy0-rust's
PE builder. Win64 loader will not even map this binary.

Per the user's directive ("rust 领先开发，调试无误之后，再用 js 和 asm 验证"),
the cross-impl verification is **deferred to sub-005 (yoy0-js) and sub-006
(yoy0-asm)** as separate sub-experiments. Each requires bringing the
peer implementation to a compatible Win64 PE template first.

### 2.3 Single-Impl Byte-Equal (verified)

Within yoy0-rust, the **emitted x86 user code** is correct:

For test-min3.ty (`40 00 / FF` → H_00 RET):
- `.text[24..]` (= after 24-byte Win64 startup) = `C3 00 00 00 00 ...`
- `C3` is exactly `ret` ✓

For yoy0.ty v0.1 baseline:
- `.text[24..31]` = `48 B8 00 00 00 00 00 00 ...`
- `48 B8 00 00 00 00 00 00` = `mov rax, 0x0000000000000000` ✓
- (= first SET state[0x0E]=0 instruction at H_00 entry)

These user-code bytes are **deterministic** (Layer 1) and **semantically correct**
(verified by Sub-002 decode output).

## 3. Full Self-Host Chain — DEFERRED

PROMPT-v3.md Part 5.2 specifies:
```
M0 = yoy0.js (or yoy0-rust) compile(yoyo.ty v0.4-Win-24bit) → M1.exe
M1.compile(yoyo.ty) → M2.exe
M2.compile(yoyo.ty) → M3exe
require SHA(M1) == SHA(M2) == SHA(M3)
```

This **full self-host byte-equal** is **out of sub-004 scope**. Prerequisites:

1. `yoyo.ty v0.4-Win-24bit` with working H_50/H_51 via libyoyo_* syscalls
   (current v0.1/v0.2 baselines have H_50 stub hardcoding `state[0xB]=4`).
2. yoy0.ty H_00 must parse CLI args (currently no argv handling).
3. yoy0.ty H_01 scanner000 must write output.exe via H_51.

This is a separate sub-effort, ~3 days work. Filed as
`experiments/005-libyoyo-self-host` (future).

## 4. Acceptance Summary

| Layer | Goal | Status |
|-------|------|--------|
| 1 | yoy0-rust emit is deterministic (same source → same SHA) | ✅ PASS |
| 2a | yoy0-rust emit x86 user code is correct | ✅ PASS (verified via decode in Sub-002) |
| 2b | yoy0-rust == yoy0-js (test-min3 emit) | ⏸ DEFERRED to sub-005 |
| 2c | yoy0-rust == yoy0-asm (test-min3 emit) | ⏸ DEFERRED to sub-006 |
| 3 | M0→M1→M2 self-host byte-equal | ⏸ DEFERRED to `experiments/005-libyoyo-self-host` |

## 5. Files Created

- `experiments/004-rust-self-host-byte-equal/README.md` (this file's parent)
- `experiments/004-rust-self-host-byte-equal/rust-test-min3-emit.bin` (8 bytes: `C3 00 00 00 00 00 00 00`)
- `experiments/004-rust-self-host-byte-equal/rust-yoy0ty-emit.bin` (8 bytes: `48 B8 00 00 00 00 00 00`)

These `*.bin` files capture yoy0-rust's emitted x86 user code for two
canonical sources, ready for cross-impl byte-equal comparison in sub-005/006.
