# YOYO Safety Architecture

> YOYO's safety is built on **4 properties** (compile-time) and **12 decisions** (architectural), forming a defense-in-depth system against both Thompson attacks and runtime failures.

## The Big Picture

| Layer | What | When |
|-------|------|------|
| **Compile-time** | 4 safety properties (zero alloc, Result chain, self-test, budget) | While compiler runs |
| **Architectural** | 12 safety decisions (Type strategy, DDC, etc.) | Design-level |
| **Runtime** | Self-test on startup | When binary boots |
| **Verification** | DDC dual-chain | Per generation |

The 4 properties are **runtime guarantees**. The 12 decisions are **design-level commitments**. Together they cover compile-time and runtime.

---

## Part 1: The 4 Safety Properties

### 1. Zero Dynamic Allocation

**Rule**: YOYO's emit path **never calls** `Vec::new()`, `Box::new()`, `String::new()`, or any other heap-allocating constructor. All buffers are stack-allocated with compile-time sizes.

**Why**: OOM during emit is catastrophic (partial output). Allocator bugs are a security risk. Non-determinism makes DDC fail.

**Implementation**: `FixedBuf<const N: usize>` instead of `Vec<u8>`. Fixed arrays replace `HashMap`. The label table is `[(u8,u32); 256]`.

**Where applied**: `src/types.rs::FixedBuf`, `src/types.rs::LabelTable`.

**Cost**: Slightly larger binaries (FixedBuf has fixed overhead). Slightly more verbose code.

**Benefit**: No OOM, deterministic, faster in hot path.

### 2. Full Result Chain

**Rule**: Every public function returns `Result<T, IsaError>`. No `panic!()`, no `unwrap()`, no `expect()` in the emit path.

**Why**: Panics are security holes. A panic during emit can leave the compiler in an inconsistent state, producing partial or corrupted output.

**Implementation**:

```rust
pub enum IsaError {
    SlotOutOfRange { slot: u16 },
    ImmOutOfRange { value: u64, max: u64 },
    InvalidConditionCode { cc: u8 },
    InvalidRegister { reg: u8 },
    LabelOutOfRange { hh: u8 },
    BufferOverflow { needed: usize, available: usize },
    ArgCountMismatch { op: u8, expected: usize, got: usize },
    UndefinedName { name: String },
    DuplicateOpcode { op: u8 },
    BudgetExceeded { used: u64, max: u64 },
}

pub type IsaResult<T> = Result<T, IsaError>;
```

**Where applied**: All `pub fn` in `src/primitives.rs`, `src/emit.rs`, `src/emit_complex.rs`, `src/platform_*.rs`.

**Exception**: Test code may use `.unwrap()` because test failures should crash.

### 3. Self-Test on Startup

**Rule**: When yoyo starts (in any mode: decode, link, etc.), it runs a **self-test** that validates:

1. Memory integrity (CRC-32C of critical sections)
2. Primitive correctness (emit a known instruction, verify bytes)
3. ISA table consistency (every opcode has a mnemonic, every mnemonic has an opcode)
4. Budget initialization (counter is at 0)

**Why**: Self-test catches:
- **Memory corruption** between compile-time and runtime (e.g., `const` data modified by bug)
- **Instruction emit errors** (a primitive that emits wrong bytes)
- **ISA table corruption** (a missing or duplicate opcode)
- **Stuck loops** (the compiler hangs, can't recover)

Without self-test, a corrupted binary could produce wrong output silently. With self-test, the binary refuses to start.

**Implementation**:

```rust
// src/self_test.rs
pub fn run_self_test() -> Result<(), IsaError> {
    crc32c_check()?;
    primitive_correctness_check()?;
    isa_table_check()?;
    budget_init_check()?;
    Ok(())
}
```

**Where applied**: `src/self_test.rs`, called at start of `main()`.

**Cost**: ~50µs startup time. Negligible.

**Benefit**: Catches memory corruption before any user code runs.

### 4. Budget-Limited Execution

**Rule**: Compilation has a **budget**: maximum number of operations. If the budget is exhausted, compilation aborts with an error.

**Why**: Compilation can loop forever if:
- A recursive function in yoyo.ty doesn't have a base case
- A `.ty` file is malformed in a way that triggers a bug
- An attacker crafts a malicious `.ty` file to exhaust resources

A budget is a **circuit breaker** that prevents runaway compilation.

**Implementation**:

```rust
pub struct Budget {
    pub max: u64,
    pub current: AtomicU64,
}

impl Budget {
    pub fn consume(&self, n: u64) -> Result<(), IsaError> {
        let prev = self.current.fetch_add(n, Ordering::SeqCst);
        if prev + n > self.max {
            return Err(IsaError::BudgetExceeded {
                used: prev + n,
                max: self.max,
            });
        }
        Ok(())
    }
}
```

**Defaults**:
- Phase 0: 1M ops per primitive call
- Phase 1: 1B ops per .ty file
- Phase 2: 10B ops for self-host

**Override**: CLI flag `--budget=5000000000`.

### How the 4 Properties Interact

```
                ┌──────────────────────┐
                │   YOYO Compiler      │
                │  (yoyo.exe)  │
                └──────────┬───────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
       ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
       │ Zero    │    │ Full    │    │ Budget  │
       │ Alloc   │    │ Result  │    │ Limit   │
       └────┬────┘    └────┬────┘    └────┬────┘
            │              │              │
       No OOM         No panics     No hangs
            │              │              │
            └──────────────┼──────────────┘
                           │
                  ┌────────▼────────┐
                  │   Self-Test     │
                  │ (on startup)    │
                  └────────┬────────┘
                           │
                  Catches corruption
```

- **Zero alloc** prevents OOM in the hot path
- **Result chain** prevents panics in the hot path
- **Budget** prevents infinite loops
- **Self-test** catches memory corruption at startup

Together, they make YOYO **deterministic and reliable**.

### What the 4 Properties Do NOT Prevent

The four safety properties are **compile-time** guarantees. They don't prevent:

- **Logic bugs** (wrong algorithm, correct implementation) — caught by tests
- **Specification bugs** (compiler does what spec says, but spec is wrong) — caught by DDC
- **Hardware bugs** (CPU computes wrong answer) — out of scope
- **Side-channel attacks** (timing, power analysis) — out of scope
- **Compiler miscompilation** (the binary is wrong) — caught by DDC

The four properties are **necessary but not sufficient**. They're the **minimum** for a reliable compiler.

### Comparison with Other Compilers

| Project | Zero Alloc | Result Chain | Self-Test | Budget |
|---------|-----------|--------------|-----------|--------|
| **YOYO** | Yes | Yes | Yes | Yes |
| GCC | No (allocator) | Partial | No | No |
| Clang | No (allocator) | Yes | No | No |
| TinyCC | No (allocator) | No (panics) | No | No |
| CompCert | Yes (mostly) | Yes | Yes | No |

YOYO is **stricter** than typical compilers on these properties. This is intentional: YOYO is for safety-critical use, where determinism matters.

---

## Part 2: The 12 Safety Decisions

The 4 properties are runtime. The 12 decisions are **architectural** — they shape the design.

### The 12 Decisions Table

| # | Decision | Where | Attack / Failure Mode |
|---|----------|-------|----------------------|
| 1 | Full Result chain | `src/types.rs` | Panics, undefined behavior |
| 2 | Independent data-segment pass | `src/emit.rs` | Cross-section corruption |
| 3 | Startup blob as separate module | `src/startup.rs` | Init code injection |
| 4 | M3 unfixed as `#[cfg(test)]` | `src/m3_unfixed.rs` | Test verification only |
| 5 | Proc-macro as separate crate | `isa-proc/` | Compiler backdoor in main crate |
| 6 | Zero dynamic allocation | `src/types.rs::FixedBuf` | OOM, non-determinism |
| 7 | Explicit type strategy | `src/types.rs::Reg` | Type confusion, register abuse |
| 8 | Rust↔yoyo sync via manual + DDC | `src/ddc.rs` | Implementation drift |
| 9 | DDC dual-chain | `src/ddc.rs` | Compiler backdoor |
| 10 | Loop budget | `src/types.rs::Budget` | Infinite loop, DoS |
| 11 | Progress observer | `src/types.rs::Progress` | Hang detection |
| 12 | Memory CRC-32C self-test | `src/self_test.rs` | Runtime corruption |

Note: decisions 1, 6, 10, 12 correspond to the 4 properties above. The other 8 are additional architectural commitments.

### Decision 1: Full Result Chain

**Rule**: Every public function returns `Result<T, IsaError>`. No `panic!()`, no `unwrap()`, no `expect()` in the emit path.

**Why**: Panics are security holes:

```rust
// DON'T DO THIS
let slot = parse_slot(args[0]).unwrap();  // Panics if args[0] is invalid

// DO THIS
let slot = parse_slot(args[0])?;  // Returns Err on invalid input
```

If an attacker can craft a `.ty` file that triggers a panic, they can crash the compiler. If the panic is in a `#[no_std]` context or before output is finalized, this could be a denial-of-service.

Worse: a `panic!` in a thread can leave the compiler in an inconsistent state. Recovery is undefined.

**Where applied**: `src/types.rs`, all `pub fn` in the codebase.

### Decision 2: Independent Data-Segment Pass

**Rule**: The data segment is laid out in a **separate pass** from code emission. Code emission doesn't know about data offsets; a final pass fixes up the references.

**Why**: Mixing data layout with code emission creates ordering dependencies. A bug in data layout could inject malicious x64 bytes into the code segment.

**Implementation**:

```rust
pub fn emit(tir: &[TirInst], data: &[DataDef]) -> Result<(Vec<u8>, Vec<u8>), IsaError> {
    // Pass 1: emit code with placeholder data references
    let (code, code_offsets) = emit_code_with_placeholders(tir)?;

    // Pass 2: lay out data segment
    let (data_seg, data_offsets) = lay_out_data(data)?;

    // Pass 3: fix up code references to data
    let final_code = fixup_data_refs(code, &data_offsets, &code_offsets)?;

    Ok((final_code, data_seg))
}
```

**Trade-off**: 2x more passes over TIR. But the data segment is small (a few KB), so it's cheap.

### Decision 3: Startup Blob as Separate Module

**Rule**: The startup blob (code that runs before user code) lives in a **separate, hand-audited module**. It is NOT generated by the ISA table.

**Why**: The startup blob sets up R15 (state base), the stack, and other critical state. If it's generated by the ISA table, an attacker could modify the ISA to inject malicious init code.

**Implementation**:

```rust
// src/startup.rs (hand-audited, ~200 lines)
pub fn startup_blob_windows() -> &'static [u8] {
    static BLOB: [u8; 200] = [/* ... */];
    &BLOB
}
```

**Where applied**: `src/startup.rs`. The blob is part of the binary but not the TIR.

**Audit**: ~200 lines, separate file, easy to review.

### Decision 4: M3 Unfixed as `#[cfg(test)]`

**Rule**: The "M3 unfixed" emit (which produces placeholders for rel32) is **only used in tests**. Production code always emits the fixed version.

**Why**: The unfixed version is a debug tool. If it leaked into production, the binary would have wrong rel32 values and crash.

**Implementation**:

```rust
/// Unfixed emit: rel32 fields are 0x00000000 placeholders.
/// Only used for diff/alignment testing.
#[cfg(test)]
pub fn emit_unfixed(tir: &[TirInst]) -> Result<Vec<u8>, IsaError> {
    // ... implementation
}

/// Production emit: rel32 fields are computed.
pub fn emit(tir: &[TirInst]) -> Result<Vec<u8>, IsaError> {
    let bytes = emit_unfixed(tir)?;
    fixup_rel32(bytes, tir)
}
```

**Verification**: `cargo test` runs the unfixed version; `cargo build --release` does not.

### Decision 5: Proc-Macro as Separate Crate

**Rule**: The `isaproc` proc-macro lives in a **separate Rust crate** (`isa-proc/`), not in yoyo.

**Why**: Proc-macros can execute arbitrary code at compile time. If `isaproc` were in the main crate, a malicious `isaproc` could inject code into the compiler. Separating it forces an explicit dependency declaration.

**Where applied**: Workspace structure.

**Audit**: `isa-proc` is ~300 lines, all of it parseable AST manipulation. The dependency on `syn` and `quote` is explicit.

### Decision 6: Zero Dynamic Allocation

**Rule**: The emit path never calls `Vec::new()`, `Box::new()`, or other heap-allocating constructors. All buffers are stack-allocated with compile-time sizes.

See Property 1 above for full details.

### Decision 7: Explicit Type Strategy

**Rule**: All "types" in yoyo are **explicit, named Rust types** — not aliases for primitives. `Reg` is an enum, not `u8`. `StateSlot` is `u16`, not `usize`.

**Why**: Type confusion is a common bug. If `Reg` is `u8`, an attacker could pass any value and the compiler might emit invalid x64.

**Implementation**:

```rust
pub enum Reg {
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
}

pub type StateSlot = u16;       // 0-255, deliberately u16 not u32
pub type Offset = u32;          // Byte offset in section
pub type Imm = u64;             // 64-bit immediate value
```

**Audit**: Easy to verify "no u8 passed where Reg is expected" by reading function signatures.

### Decision 8: Rust↔yoyo Sync via Manual + DDC

**Rule**: The Rust yoyo and the JS `yoyo.js` are kept in sync **manually** + verified by DDC. There is no automatic codegen between them.

**Why**: Automatic codegen (e.g., a "spec language" that generates both) would be a single point of failure. If the spec is wrong, both implementations are wrong. Manual sync with DDC catches divergence.

**Workflow**:

```bash
# Manual sync: when changing instruction semantics, update BOTH:
# - yoyo-ide/src/yoyo.js (or yoyo-gen.js)
# - yoyo/src/isa.rs

# DDC verification:
node yoyo.js input.ty output_js.exe
yoyo link input.ty output_rs.exe
sha256sum output_js.exe output_rs.exe  # Must match
```

**Trade-off**: More work to keep two implementations in sync. But DDC catches drift automatically.

### Decision 9: DDC Dual-Chain

**Rule**: Every generation of the compiler is run through both `yoyo.js` and yoyo, and the SHA-256 of outputs is compared.

**Why**: A backdoor in one implementation is caught by the other. This is the **core defense** against Thompson's attack.

See `docs/02-ddc.md` for full details.

### Decision 10: Loop Budget

**Rule**: Compilation has a maximum operation count. If exceeded, compilation aborts with `BudgetExceeded` error.

See Property 4 above for full details.

### Decision 11: Progress Observer

**Rule**: Long-running emit operations report progress via an `AtomicU64` counter. The main thread can monitor this to detect hangs.

**Why**: A "spin loop" in the emit path is hard to detect without observability. The progress counter lets a watchdog kill the process if no progress is made.

**Implementation**:

```rust
pub struct Progress {
    counter: AtomicU64,
    last_update: AtomicU64,  // Timestamp
}

impl Progress {
    pub fn advance(&self, n: u64) {
        self.counter.fetch_add(n, Ordering::SeqCst);
        self.last_update.store(now_ms(), Ordering::SeqCst);
    }

    pub fn is_stuck(&self, threshold_ms: u64) -> bool {
        let elapsed = now_ms() - self.last_update.load(Ordering::SeqCst);
        elapsed > threshold_ms
    }
}
```

**Watchdog** (separate process or thread):

```rust
loop {
    if progress.is_stuck(30_000) {  // 30 seconds no progress
        eprintln!("yoyo: stuck, killing");
        std::process::exit(1);
    }
    sleep(1_000);
}
```

### Decision 12: Memory CRC-32C Self-Test

**Rule**: On startup, yoyo computes CRC-32C of critical memory sections (ISA table, primitive implementations) and verifies against a known-good hash.

**Why**: Memory corruption between compile-time and runtime (e.g., `const` data modified by bug) would silently produce wrong output. The CRC catches this at startup.

**Implementation**:

```rust
// src/self_test.rs
const ISA_TABLE_CRC: u32 = 0xDEADBEEF;  // Computed at build time
const PRIMITIVES_CRC: u32 = 0xCAFEBABE;

pub fn run_self_test() -> Result<(), IsaError> {
    let isa_crc = crc32c::compute(ISA_TABLE_BYTES);
    if isa_crc != ISA_TABLE_CRC {
        return Err(IsaError::SelfTestFailed { test: "isa_table" });
    }

    let prim_crc = crc32c::compute(PRIMITIVES_BYTES);
    if prim_crc != PRIMITIVES_CRC {
        return Err(IsaError::SelfTestFailed { test: "primitives" });
    }

    Ok(())
}
```

**Cost**: ~50µs startup time. Negligible.

### How the 12 Decisions Layer

```
┌─────────────────────────────────────────────┐
│  Layer 1: Trust Anchor (yoyo.js, 162 lines) │
│  (audited once, golden hash)                │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  Layer 2: Implementation Diversity          │
│  (Rust + JS, manually synced, DDC verified) │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  Layer 3: ISA Transparency                  │
│  (38 lines, single source of truth)         │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  Layer 4: Compile-Time Guarantees           │
│  (Zero alloc, Result chain, type safety)    │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  Layer 5: Runtime Detection                 │
│  (Self-test, budget, progress observer)     │
└─────────────────────────────────────────────┘
```

Each layer assumes the layer above could be compromised. The 12 decisions populate these layers.

### What the 12 Decisions Do NOT Cover

- **Hardware bugs** (CPU computes wrong answer)
- **Source bugs in yoyo.ty** (intentional or accidental)
- **Side-channel attacks** (timing, power)
- **Human error** (auditor misses something)
- **Algorithm bugs** (compiler logic is wrong but correct per spec)

These are accepted risks. DDC catches some of them. Tests catch others. The irreducible trust anchor (yoyo.js 162 lines) covers the rest.

### Why 12, Not 10 or 20

The 12 decisions are the **minimum complete set** for YOYO's threat model:

| Number | Trade-off |
|--------|-----------|
| < 12 | Critical surfaces unprotected |
| 12 | Sweet spot: covers all known attack surfaces |
| > 12 | Diminishing returns, harder to audit |

Each decision is **load-bearing**: removing any one creates a Thompson-class attack surface.

### The Connection to Phase Implementation

| Decision | Phase | File |
|----------|-------|------|
| 1. Result chain | 0 | `src/types.rs` |
| 2. Independent data-segment | 1 | `src/emit.rs` |
| 3. Startup blob module | 1 | `src/startup.rs` |
| 4. M3 unfixed cfg(test) | 1 | `src/emit.rs` |
| 5. Proc-macro separate | 0 | `isa-proc/` |
| 6. Zero alloc | 0 | `src/types.rs` |
| 7. Type strategy | 0 | `src/types.rs` |
| 8. Rust↔yoyo sync | 2 | workflow |
| 9. DDC dual-chain | 2 | `src/ddc.rs` |
| 10. Loop budget | 0 | `src/types.rs` |
| 11. Progress observer | 0 | `src/types.rs` |
| 12. CRC self-test | 1 | `src/self_test.rs` |

All 12 are defined in Phase 0-1. They form the **architectural invariants** of yoyo.

---

## Summary

YOYO's safety is **two layers**:

**Runtime guarantees (4 properties)**:
1. Zero dynamic allocation
2. Full Result chain
3. Self-test on startup
4. Budget-limited execution

**Architectural decisions (12 commitments)**:
1-12 listed above, covering 4 layers of defense

Together, they make YOYO **deterministic, reliable, and trustworthy**. The cost is ~10% performance. The benefit is total determinism and verifiability.

For YOYO's use case (security-critical OS development, embedded systems, audit-able toolchains), this trade is **excellent**.