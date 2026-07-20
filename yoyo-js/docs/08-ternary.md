# YOYO Ternary Data Model (Trit)

> YOYO uses a ternary (base-3) data model where every state slot holds a value in {0, 1, 2}. This is the **data interpretation convention**, not the ISA — but it shapes how yoyo programs are written.

## What is a Trit?

A **trit** is a single ternary digit. Three possible values: 0, 1, 2.

| Code | Balanced | Default Decision Meaning |
|------|----------|--------------------------|
| `0` | -1 | Sell / Negative / Oppose |
| `1` | 0 | Hold / Neutral / Wait |
| `2` | +1 | Buy / Positive / Support |

The "balanced" view (-1, 0, +1) is the mathematical interpretation. The "code" view (0, 1, 2) is how it's stored.

**YOYO state slots are u64**, so a trit value is stored as `0`, `1`, or `2` in a u64. The balanced interpretation is `code - 1` = {-1, 0, +1}.

## Why Ternary?

YOYO was originally designed for **signal aggregation** — combining multiple "votes" or "signals" into a single decision. Ternary is the natural representation for many real-world signals:

| Domain | Codes | Meaning |
|--------|-------|---------|
| **Stock trading** | Sell / Hold / Buy | -1 / 0 / +1 |
| **Voting** | Against / Abstain / For | -1 / 0 / +1 |
| **Customer feedback** | Negative / Neutral / Positive | -1 / 0 / +1 |
| **A/B testing** | Loses / Tie / Wins | -1 / 0 / +1 |
| **Sentiment analysis** | Bearish / Neutral / Bullish | -1 / 0 / +1 |
| **Multi-criteria decision** | Reject / Defer / Accept | -1 / 0 / +1 |

Binary (-1, +1) loses the "neutral" state. Higher bases (quaternary, etc.) need more complex handling. Ternary is **the minimum useful base** for signal aggregation.

## The Decision Engine

`yoyo-ide/projects/ternary_signal.ty` implements 5 handlers that perform ternary decision aggregation:

### H_20: Trit Vote Sum
```asm
40 20                                ; HANDLER H_20
  30 50 00                           ; SET state[0x50] = 0    ; sum = 0
  30 51 00                           ; SET state[0x51] = 0    ; i = 0
  30 52 07                           ; SET state[0x52] = 7    ; n = 7 votes

40 21                                ; HANDLER H_21 (loop)
  65 51 52                           ; CMP state[0x51], state[0x52]
  71 24                              ; JE H_24 (exit)
  
  ; Load vote[i] (where i is state[0x51])
  80 53 51 00                        ; LDB state[0x53] = mem[state[0x51] + 0]
  
  ; Add to sum
  68 50 53                           ; ADDV state[0x50], state[0x53]
  
  66 51                              ; INC state[0x51]
  70 21                              ; JMP H_21

40 24                                ; HANDLER H_24 (exit)
  FF                                 ; RET
```

Sum of 7 trit votes, stored in `state[0x50]`. Each vote is 0, 1, or 2.

### H_30: Decision from Sum
```asm
40 30                                ; HANDLER H_30
  30 53 04                           ; SET state[0x53] = 4    ; threshold = 4
  
  65 50 53                           ; CMP state[0x50], state[0x53]
  71 33                              ; JE H_33 (neutral)
  73 31                              ; JL H_31 (negative)
  70 32                              ; JMP H_32 (positive)

40 31                                ; HANDLER H_31 (negative)
  30 50 00                           ; SET state[0x50] = 0    ; result = 0
  FF                                 ; RET

40 32                                ; HANDLER H_32 (positive)
  30 50 02                           ; SET state[0x50] = 2    ; result = 2
  FF                                 ; RET

40 33                                ; HANDLER H_33 (neutral)
  30 50 01                           ; SET state[0x50] = 1    ; result = 1
  FF                                 ; RET
```

If `sum < 4` → 0 (negative)
If `sum = 4` → 1 (neutral)
If `sum > 4` → 2 (positive)

### H_50: Single Vote Accumulator (alternative)
```asm
40 50                                ; HANDLER H_50
  30 50 00                           ; SET state[0x50] = 0
  30 51 00                           ; SET state[0x51] = 0
  30 52 100                          ; SET state[0x52] = 100 (n)
  ...
```

Similar to H_20 but reads votes from a different layout (e.g., file-backed).

### H_31 / H_32: Force Set
Sometimes a manual override is needed:
```asm
40 31                                ; HANDLER H_31
  30 50 00                           ; SET state[0x50] = 0
  FF

40 32                                ; HANDLER H_32
  30 50 02                           ; SET state[0x50] = 2
  FF
```

## Trit vs ISA: Clear Separation

A common confusion: **Trit is not part of the YOYO ISA.**

| Layer | Concerns |
|-------|----------|
| **ISA** (`src/isa.rs`) | How to emit x64 bytes for each opcode |
| **Trit** (data model) | How to interpret values in state slots |

The 38 ISA instructions are **agnostic** to what data they manipulate. Whether a state slot holds a binary 0/1, ternary 0/1/2, or arbitrary u64 — the ISA doesn't care.

This separation is **intentional and load-bearing**:

1. The ISA is **portable** — works for any data interpretation
2. The data model is **application-specific** — yoyo programs choose how to interpret state
3. Adding new data models (binary, quaternary, decimal) doesn't change the ISA

## Trit in Rust Types

The Rust yoyo **does not need a `Trit` type**. State slots are `u64`. The application (yoyo program) is responsible for ensuring values stay in {0, 1, 2}.

```rust
// In yoyo (Rust):
pub type StateSlot = u64;

// In yoyo-ide (JS, where yoyo programs live):
// yoyo.ty code uses trit semantics, but the compiler doesn't enforce it
```

This is **deliberate**: enforcing trit semantics would require type information at the ISA level. YOYO keeps the ISA untyped (pure u64). Applications add their own type discipline.

## Trit Decision Patterns

Beyond the 5 handlers in `ternary_signal.ty`, several other patterns are common:

### Weighted Voting

```asm
; Each vote has a weight 0/1/2 (3 levels)
; Sum = vote[0] * weight[0] + vote[1] * weight[1] + ...
; Decision: sum > threshold ?
40 60                                ; HANDLER H_60 (weighted)
  30 50 00                           ; sum = 0
  30 51 00                           ; i = 0
  30 52 10                           ; n = 10 votes

40 61                                ; HANDLER H_61 (loop)
  65 51 52
  71 64                              ; JE exit
  
  ; Load vote[i] (1 byte)
  80 53 51 00
  ; Load weight[i] (1 byte)
  80 54 51 100                       ; weight[i] at offset 100
  ; Multiply
  63 53 54                           ; IMUL state[0x53] *= weight[i]
  ; Add to sum
  68 50 53
  
  66 51
  70 61

40 64                                ; exit
  FF
```

### Trit-based Counting

```asm
; Count positive (2) votes, negative (0) votes
; Result: positive_count, negative_count, neutral_count
40 70
  30 50 00                           ; pos_count = 0
  30 51 00                           ; neg_count = 0
  30 52 00                           ; neu_count = 0
  30 53 00                           ; i = 0
  30 54 10                           ; n = 10

40 71                                ; HANDLER H_71 (loop)
  65 53 54
  71 74                              ; JE exit
  
  80 55 53 00                        ; vote = mem[i]
  
  65 55 02                           ; CMP vote, 2
  71 73                              ; JE pos_increment
  65 55 00                           ; CMP vote, 0
  71 72                              ; JE neg_increment
  66 52                              ; INC neu_count
  70 71

40 72                                ; neg_increment
  66 51
  70 71

40 73                                ; pos_increment
  66 50
  70 71

40 74                                ; exit
  FF
```

## Why This Matters

YOYO's ternary focus distinguishes it from generic VMs. Most VMs use:

- **Untyped u64** (Java, Lisp) — flexible but no domain meaning
- **Typed binary** (C, Rust) — typed but loses "neutral" state
- **Booleans** (most languages) — only 2 states

Ternary is **a deliberate data model for signal aggregation**. YOYO's use case is not "general-purpose language" — it's "decision aggregation engine".

## Connection to Other YOYO Programs

Several yoyo programs use trit semantics:

| Program | Trit Use |
|---------|----------|
| `ternary_signal.ty` | Direct: 5 handlers, basic decision |
| `stock_gui.ty` | Trading signals: sell/hold/buy per stock |
| `ternary_watchlist.ty` | Multi-symbol aggregation |
| `signal_log.ty` | Persistent log of ternary decisions |
| `gui_signal.ty` | GUI version of signal aggregation |

These programs are **the actual use cases** that drove YOYO's design. The 38 ISA instructions are the minimum needed to express these patterns efficiently.

## Anti-Patterns

❌ **Don't add a `Trit` type to Rust** — ISA is untyped u64
❌ **Don't enforce trit semantics in emit** — applications do that
❌ **Don't use ternary for general-purpose computation** — it's specialized
❌ **Don't expand beyond ternary** — quaternary/quinary are more complex without benefit

✅ **Use ternary for signal aggregation** — it's the natural fit
✅ **Document trit semantics in the .ty file** — comments matter
✅ **Use H_20 / H_30 as building blocks** — they're the canonical decision pattern

## Trit in Phase Implementation

| Phase | Trit Relevance |
|-------|----------------|
| Phase 0 | None — Rust types are u64 |
| Phase 1 | None — ISA is u64 |
| Phase 2 | yoyo-blob.ty uses trit patterns; compression preserves them |
| Phase 3 | Trit-valued state slots benefit from named slots (`sell_vote`, etc.) |
| Phase 4 | Platform-agnostic — works on Win32, Linux, bare-metal |
| Phase 5 | Bare-metal can still do trit aggregation |
| Phase 6 | Document trit in `docs/zh/04-ternary.md` and `docs/en/04-ternary.md` |

## Summary

The ternary data model is YOYO's **application domain**, not part of the ISA. The 38 ISA instructions support it naturally because they're untyped u64 operations. The `ternary_signal.ty` and related programs use trit semantics for **decision aggregation** — the primary YOYO use case.

Trit is a **design choice** that shapes what yoyo programs look like, not a compiler feature. The compiler doesn't know about trit; only the application code does.

This separation is the YOYO architecture's strength: **clean ISA, free application semantics**.

---

## Why YOYO Stays u64 (Not a "Real Ternary" Language)

A natural question: should YOYO be a strict ternary language with native `Trit` type, trit arithmetic, and compiler-enforced trit semantics? **Answer: No.** Six reasons:

### 1. The Compiler Itself Isn't Ternary

`yoyo-blob.ty` uses u64 for:
- String table indices, IAT thunk addresses, handler IDs, byte offsets, file sizes, state machine indices

**None are trit values.** If YOYO were a real ternary language, the compiler would have to be written in something else — **the compiler couldn't self-host**.

### 2. 38 Instructions Are Already Enough

Adding trit-specific instructions (trit_add, trit_sub, trit_mul, trit_packed_load, etc.) duplicates what u64 ops already do. **No code size reduction, just type checks.**

### 3. Trit Packing Is Paper Advantage

"21 trits per u64" sounds great, but:
- Needs 21-trit encoding/decoding primitives
- 12 slots × 21 trits = 252 trits; YOYO programs rarely use >50
- **Not needed in practice**

### 4. Type Safety Doesn't Catch Real Bugs

```asm
30 i 0
66 i           ; INC i (now 1)
65 i 3         ; CMP i, 3
71 exit        ; off-by-one: should be CMP i, 2
```

This is a **logic bug**. No type system catches it. The bugs trit type **would** catch (out-of-range values) are rare and caught by tests.

### 5. Audit Surface Growth

Real ternary would add ~22 instructions, ~10 primitives, ~8 safety decisions — **50% more code**. DDC verification time doubles, manual audit takes 1 day instead of half a day.

### 6. ISA Is Already Frozen

After Phase 1, the 38 instructions in `src/isa.rs` are frozen. Adding trit-specific instructions violates "frozen after Phase 1".

### What We Do Instead: 4-Layer Convention

1. **Convention in comments**: Document trit semantics in file headers
2. **Type-annotated comments**: `; TYPED: vote (trit 0/1/2)`
3. **Optional runtime checks**: 3 instructions per check
4. **External type checker (Phase 7+)**: Standalone `yoyo-typecheck` tool

**YOYO is u64 first, trit when convenient.** Not the other way around.

The "real ternary" approach kills self-hosting, doubles audit, and catches rare bugs. The convention approach preserves YOYO's core value: **simplicity, auditability, self-hosting**.