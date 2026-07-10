# yoyo-asm (x64 ground truth)

> **PROJECT 4 of 4** in the [yoyo-org](https://example.com/yoyo-org) monorepo.
> **Status**: PLANNED (Phase 4d). Not yet implemented.
> See [v3 Appendix B](../docs/PROMPT-v3.md#appendix-b-yoyo-asm-third-implementation) for the full specification.

## What this project will be

A complete YOYO compiler written in **pure x86-64 assembly**, ~500 lines, hand-audited. Its purpose is to be the **ground-truth peer** in [3-chain DDC](../docs/PROMPT-v3.md#part-6-ddc-verification-3-chain).

## Why assembly (over a 4th high-level language)

- **No compiler between source and execution** — what you read IS what runs
- **No optimizations** to hide intent — every instruction is exactly as written
- **No library calls** to abuse — only direct syscalls
- **Smallest surface** — 500 lines of x64 you can read in one day

To backdoor yoyo-asm, the attacker must modify text that a human reads as x64 assembly. **The hardest hiding place of any implementation.**

## Planned Architecture (4 layers)

| Layer | Lines | Purpose |
|-------|-------|---------|
| Layer 1: Startup + syscalls | ~50 | Set up R15 (state base), parse args, open files |
| Layer 2: 13 primitives | ~130 | Emit single x64 sequences |
| Layer 3: 38 instruction emit | ~370 | Compose primitives per ISA opcode |
| Layer 4: Main loop | ~100 | Read source line, parse opcode, dispatch |
| **Total** | **~500** | |

## Trust Model Position

| Implementation | Lines | Hiding Difficulty | Toolchain |
|----------------|-------|-------------------|-----------|
| yoyo.js | 162 | Easy (JS dynamic) | Node.js v8 (~millions) |
| yoyo (Rust) | ~3,000 | Medium (Rust compiled) | rustc + LLVM (~millions) |
| **yoyo-asm** | **~500** | **Hard (every byte visible)** | **nasm (~100,000)** |

nasm is the smallest toolchain. 100K lines of nasm is much more auditable than millions of lines of LLVM.

## Implementation Phases

| Phase | Target | Effort |
|-------|--------|--------|
| 1 | Linux (cleaner syscall, ELF format) | 1-2 months |
| 2 | Windows (Win32 syscalls) | 1 month |
| 3 | Triple-chain DDC integration | 2 weeks |

## Anti-Patterns

- **Don't** use libc — adds millions of lines of dependencies
- **Don't** use high-level macros that hide emitted bytes
- **Don't** accept third-party assembler optimizations
- **Don't** use yoyo-asm for production — it's for verification
- **Don't** optimize for speed — Audit > speed

## Reference

Full specification: v3 Part 14 / Appendix B.

