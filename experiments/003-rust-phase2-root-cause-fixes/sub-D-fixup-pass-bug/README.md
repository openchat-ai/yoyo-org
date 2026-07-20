# Sub-Exp D — INVESTIGATION COMPLETE (no fixup bug; cosmetics only)

> **Date**: 2026-07-15
> **Subject**: Phase 2 root-cause fixup investigation
> **Verdict**: ✅ NO BUG IN FIXUP PASS — Phase 2 root cause is somewhere else

---

## 1. Initial Suspicion

After Sub-A, decode output showed:
- Line 51 `41 50` (call H_50): `[0x00C9] call H_?? ; rel=20, target=0x00E2`
- Line 53 `41 01` (call H_01): `[0x00DC] call H_?? ; rel=30, target=0x00FF`
- Line 150 `70 01` (jmp H_01): `[0x0246] jmp H_?? ; rel=-332, target=0x00FF`

The `H_??` and the `target=0x00FF` pattern looked suspicious. Initial hypothesis:
fixup pass 2 in `emit.rs:294-302` was writing wrong rel32 values.

## 2. Investigation

### 2.1 Fixup code review (`emit.rs:294-302`)

```rust
if do_fixup {
    for p in &pending {
        let target = handler_offsets[p.hh as usize];
        let rel32 = target as i32 - (p.inst_start as i32 + p.inst_len as i32);
        let rel32_off = p.inst_start as usize + if p.inst_len == 5 { 1 } else { 2 };
        buf.write_i32_at(rel32_off, rel32).unwrap();
    }
}
```

Algorithm: `rel32 = handler_offset[hh] - (inst_start + inst_len)`.
For call/jmp (inst_len=5): rel32_off = inst_start + 1 (skip E9 byte).
For jcc (inst_len=6): rel32_off = inst_start + 2 (skip 0F + cc byte).

This is **standard x86 rel32 patch logic** and looks correct.

### 2.2 Handler offset verification

Decoded lines:
- Line 59 `40 50` (H_50 LABEL): byte_offset recorded but no disasm line emitted (labels don't emit bytes)
- Line 60 `30 0A 00` SET state[0x0A]: byte_offset = `0x00E2` ← H_50's first instruction
- Line 67 `40 01` (H_01 LABEL): no disasm line
- Line 69 `65 0C 0D` CMP state[0x0C], state[0x0D]: byte_offset = `0x00FF` ← H_01's first instruction

So `handler_offsets[0x50] = 0x00E2` and `handler_offsets[0x01] = 0x00FF`.

### 2.3 Target verification

For line 51 `call H_50` at byte_offset 0x00C9:
- rel32 = handler_offsets[0x50] - (0x00C9 + 5) = 0x00E2 - 0x00CE = **0x14 = 20**
- Decoder reads: `rel=20` ✓
- Decoder target: `0x00C9 + 5 + 20 = 0x00E2` ✓ (= H_50 entry)

For line 53 `call H_01` at byte_offset 0x00DC:
- rel32 = 0x00FF - (0x00DC + 5) = 0x00FF - 0x00E1 = **0x1E = 30**
- Decoder reads: `rel=30` ✓
- Decoder target: `0x00DC + 5 + 30 = 0x00FF` ✓ (= H_01 entry)

For line 150 `jmp H_01` at byte_offset 0x0246:
- rel32 = 0x00FF - (0x0246 + 5) = 0x00FF - 0x024B = **-0x014C = -332**
- Decoder reads: `rel=-332` ✓
- Decoder target: `0x0246 + 5 - 332 = 0x00FF` ✓ (= H_01 entry)

**All three targets match!** The `??` after `H_` is a display issue, not a fixup bug.

## 3. Root cause of "H_??" appearance

`disasm.rs:233-243` (`jmp_rel32`) and `disasm.rs:245-258` (`jcc_rel32`):
- They compute `target = offset + inst_len + rel32`
- They emit `format!("jmp H_?? ; rel={}, target=0x{:04X}", rel, target)`
- They never look up `handler_offsets` to resolve target → handler hh

The fixup pass wrote **correct rel32** values. The decoder **correctly computes target**. The output `H_??` is purely a cosmetic gap — there's no table to look up "target offset 0x00FF → which hh".

## 4. Conclusion: NO ACTION REQUIRED for Phase 2 fixup

- ✅ Sub-A (renderer realignment) — done, commit `61e0023`
- ✅ Fixup pass 2 — verified correct, no bug
- 🟡 Disasm display — cosmetic improvement possible (resolve target→hh for "H_01") but NOT a Phase 2 root cause

**Phase 2 root cause is NOT the fixup pass.** The 78KB gen1/gen2 mismatch from historical exp1 likely involved:

| Suspect | Status |
|---------|--------|
| pe_link OUTPUT_DATA_NEED (data segment size) | **uninvestigated** — pe_link emits 1605 B but the historical mismatch was about gen1 (250 KB) vs gen2 (328 KB), suggesting data-segment size issue, NOT code-segment rel32 fixup |
| pe_link pe.template (Win64 ABI bytes) | pe_link output doesn't run on Win64 (exp 002 noted) — that's a sub-C problem, not sub-D |
| Disasm display (only "H_??" labels) | cosmetic, no functional impact |

## 5. Recommended next moves

Given fixup is fine, the Phase 2 actual fixup burden is **already solved** (this sub-exp was a no-op). The real remaining work in exp 003 is:

| Sub-exp | Subject | Status |
|---------|---------|--------|
| 003-B | STR opcode (0x12) + data.blob (0x13) emit | TODO — exp 002 warns at lines 27-29 |
| 003-C | pe_link template (Win64 ABIs, link output runs) | TODO — exp 002 link output can't run |

Sub-exp D found nothing actionable. Recommend: skip to 003-B (STR opcode) since it's the smallest concrete remaining
gap, and v0.1 baseline is already designed to not NEED STR (H_50 is stub).
