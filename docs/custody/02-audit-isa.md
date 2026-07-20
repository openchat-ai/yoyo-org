# ⚠️ STATUS: TEMPLATE — NOT YET SIGNED ⚠️

> **This document is an unsigned template.**
>
> **Do not treat the content below as a valid attestation.**
> All `[Author]`, `[YYYY-MM-DD]`, `[GPG key ID]`, `[HASH]`, etc. are placeholders
> that have NOT been filled in with real values.
>
> Real audit and GPG signing are pending. This file is in the repo only
> to document what the *final* signed version will look like.
>
> See branch `wip/mark-custody-as-template` for tracking.
>
> ---
>
> The content below this banner is **placeholder content**, not actual
> attestation. Do NOT cite it as evidence of any audit or verification.

---
# ISA Table Audit

**Auditor**: [你的名字]
**Date**: [YYYY-MM-DD]
**File**: `src/isa.rs`
**Instructions**: 38
**GPG key**: [待你生成 GPG 后填入密钥 ID]

---

## Audit Statement

I, [你的名字], have personally read all 38 instructions in `src/isa.rs` on [YYYY-MM-DD]. This audit was conducted without AI assistance. I read the ISA table directly, instruction by instruction, understanding what each one does.

## What I Looked For

- [ ] Instructions that don't match their documented behavior
- [ ] Surprising capabilities (e.g., hidden network, hidden I/O)
- [ ] Instructions that could be a backdoor (e.g., raw byte emit with no audit trail)
- [ ] Inconsistencies with my mental model of YOYO
- [ ] Naming that hides intent
- [ ] Parameters that could be misused

## The 38 Instructions

Use this section to summarize each instruction.

### Data Movement (4)
- `0x30 SET slot imm` — [your understanding]
- `0x60 GET dst src` — [your understanding]
- `0x84 MEMCPY_DATA dd off sz` — [your understanding]
- `0x85 MEMCPY_STATE dd ss sz` — [your understanding]

### Arithmetic (9)
- `0x61 ADD slot imm` — [your understanding]
- `0x62 SUB slot imm` — [your understanding]
- `0x63 IMUL dst src` — [your understanding]
- `0x66 INC slot` — [your understanding]
- `0x67 DEC slot` — [your understanding]
- `0x68 ADDV dst src` — [your understanding]
- `0x69 SUBV dst src` — [your understanding]
- ... and any others

### Comparison (1)
- `0x65 CMP a b` — [your understanding]

### Branches (11)
- `0x40 HANDLER hh` — [your understanding]
- `0x41 CALL hh` — [your understanding]
- `0x70 JMP hh` — [your understanding]
- `0x71 JE hh` — [your understanding]
- `0x72-0x7A, 0x82, 0x83` (conditional jumps) — [your understanding]

### Memory (3)
- `0x80 LDB dd ss oo` — [your understanding]
- ... and others

### Syscalls (3)
- `0x20 ALLOC slot size` — [your understanding]
- `0x50 LOAD_FILE slot str_idx` — [your understanding]
- `0x51 WRITE_FILE slot str_idx sz` — [your understanding]

### Handlers (2)
- `0x40 HANDLER hh`
- `0x41 CALL hh`

### Escape (2)
- `0xA0 RAW_BYTE byte` — [your understanding]
- `0xA1 RAW_BYTES bytes` — [your understanding]

### Other
- `0xFF RET`
- `0x12 STR` (data def)
- `0x13 RAW` (data def)
- `0x00 NOP`

## Findings

### Critical Issues (blockers)

_None found._ [OR: list critical issues]

### Surprising Capabilities (worth understanding)

- [e.g., "0xA1 RAW_BYTES can emit any x64 sequence. This is by design — it lets yoyo programs do anything x64 can do, including potentially malicious operations. I accept this risk because (a) it's explicit in the code, (b) it can be grep'd for in yoyo-blob.ty audits, (c) without it, the ISA cannot anticipate all future x64 instructions."]

### Code Quality Observations (not blockers)

[List any style / documentation / clarity issues]

## Decision

**I trust this 38-instruction ISA as the contract for what YOYO programs can do.**

This decision is based on:
- [your reasoning]

I understand that:
- I am staking my personal reputation on this audit
- Adding new instructions requires re-audit
- A backdoor in the ISA could affect every YOYO program

## Signature

Signed: [你的名字]
Date: [YYYY-MM-DD]
GPG key: [待你生成 GPG 后填入密钥 ID]

```
[Your GPG signature goes here]
```

To verify:
```bash
$ gpg --verify 02-audit-isa.md.sig 02-audit-isa.md
gpg: Good signature from "[你的名字] <[你的邮箱]>"
```

---

## Re-Audit Schedule

This audit should be re-done if:
- [ ] New instruction added to src/isa.rs (should not happen after Phase 1)
- [ ] Instruction semantics change
- [ ] I lose confidence in my original audit

Re-audit date: [next planned re-audit]
