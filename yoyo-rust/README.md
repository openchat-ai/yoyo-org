# yoyo (Rust verifier + stdlib)

> This is **PROJECT 3 of 4** in the [yoyo-org](https://example.com/yoyo-org) monorepo. **Part 4 (Verification)** and **Part 5 (Standard Library)** of the [complete v3 specification](docs/PROMPT-v3.md).
>
> See [PROMPT-v3.md Part 1 § 4-Project Architecture](docs/PROMPT-v3.md#part-1-4-project-architecture) for the full project layout.

## What this project is

A pure-Rust implementation of the **YOYO compiler verifier** and **libyoyo standard library**, written from scratch (no shared code with [yoyo-js](../yoyo-js/) or [yoyo-asm](../yoyo-asm/)).

This project has **two roles**:

1. **Verifier (Entity 4)**: A complete Rust re-implementation of the YOYO compiler's emit layer, used as one of the 3 peers in [3-chain DDC](docs/PROMPT-v3.md#part-6-ddc-verification-3-chain) verification. It compiles `.ty` source to `.text` bytes — same algorithm as [`yoyo.js`](../yoyo-js/src/yoyo.js), but independently written.

2. **Standard Library (Entity 5)**: [libyoyo](libyoyo/), the platform-abstraction layer (`libyoyo-win32.dll`, `libyoyo-linux.so`, `libyoyo-baremetal.a`). All platform syscalls go through this.

## What this project is NOT

- **NOT** a yoyo compiler rewrite that alone produces binaries (use [yoyo-js](../yoyo-js/) for `.ty → binary`).
- **NOT** an ARM / RISC-V / WASM backend. The x86-64 emit is hand-written for the patterns `yoyo-js/src/encode-x64.js` produces. Multi-arch is Phase X2.
- **NOT** a standalone product. It is one peer in the 3-chain DDC — useful ONLY in combination with [yoyo-js](../yoyo-js/) and [yoyo-asm](../yoyo-asm/).

## Capabilities

### 4.1 Three-Column Decode (SOURCE / TIR / X86)

For the 38 instructions in [ISA table](docs/PROMPT-v3.md#41-24-bit-instruction-encoding) (per Part 4):

```bash
cargo build --release
target/release/yoyo decode path/to/file.ty
```

Parses a `.ty` file into source lines, lowers each line to TIR (Typed Intermediate Representation), emits the x86 bytes, and prints the three-column view.

### 4.2 Byte Diff Mode

Compare the `.text` section of two yoyo-produced binaries:

```bash
target/release/yoyo diff a.exe b.exe
# diff: a.exe vs b.exe
# a.size = 32667, b.size = 32667
# 1 byte differences found:
offset    a           b
55        0x00      0xFF
```

The startup blob is **auto-detected** (by scanning for the `mov r14, rax; call H_00` pattern on Windows, `jmp H_00` on Linux) and skipped because platform runtime bytes are allowed to differ. Only the user-code section (code + data) must match for DDC verification.

### 4.3 Diff with Source Annotation (`--source=`)

When given a `.ty` source file, each byte difference is annotated with the `.ty` line that produced it:

```bash
target/release/yoyo diff a.exe b.exe --source=../yoyo/projects/yoyo.ty
# 1 byte differences found:
line        offset    a           b           context
Line 9      18        0x00      0xFF        Line 9: 30
```

This is the actual debugging tool for self-hosting: when `gen1` and `gen2` disagree, you immediately see **which yoyo.ty source line emits the differing byte**.

### 4.4 Disassembly

```bash
target/release/yoyo disasm a.exe
```

Disassembles the binary's `.text` back to mnemonics for human inspection.

### 4.5 Relocation-Safety Scanner (`scan-relocs`)

Detects "trap bytes" — places where a naive E8/E9 scanner would mis-relocate. Adds a linear x64 decoder for the exact subset of instructions yoyo emits:

```bash
target/release/yoyo scan-relocs build/yoyo.exe
# instructions decoded: 11975
# genuine rel32 relocation sites: 585
# naive-relocator trap bytes (E8/E9 in immediates/disps): 27
```

Used by [yoyo-js](../yoyo-js/) to validate that its `relocateSlice` only touches real relocation sites, not data bytes that happen to look like opcode prefixes.

## libyoyo (Standard Library)

The [libyoyo/](libyoyo/) subdirectory implements the platform-abstraction layer — every yoyo-compiled binary that does file I/O or memory allocation calls into libyoyo:

| Library | Platform |
|---------|----------|
| `libyoyo-win32.dll` | Windows (Visual C++ calling convention) |
| `libyoyo-linux.so` | Linux (glibc / direct syscalls) |
| `libyoyo-baremetal.a` | Bare-metal (ATA PIO, VGA text mode) |

API names are standardized in [v3 Part 7.6](docs/PROMPT-v3.md#76-libyoyo-api-names-standardized-in-v3): `libyoyo_alloc`, `libyoyo_open`, `libyoyo_read`, `libyoyo_write`, etc.

## Build

```bash
cd yoyo-rust           # this project
cargo build --release  # builds verifier + libyoyo workspace
```

## Tests

```bash
cargo test                                    # all tests
cargo test primitives                        # Phase 0
cargo test isa_table                         # Phase 1
cargo test ddc                               # Phase 2
cargo test platform                          # Phase 4
cargo test baremetal                         # Phase 5
cargo test -- --budget=5000000000            # override budget
```

## 3-Chain DDC Verification

The verifier's primary role is **3-chain DDC** (Part 6 of the v3 spec):

```bash
# All three implementations produce the SAME .text byte stream
node ../yoyo-js/src/yoyo.js ../yoyo/projects/yoyo.ty /tmp/yoyo_js.exe
./target/release/yoyo link ../yoyo/projects/yoyo.ty /tmp/yoyo_rust.exe
../yoyo-asm/yoyo-asm ../yoyo/projects/yoyo.ty /tmp/yoyo_asm.exe

# Verify code + data sections match (platform runtime bytes excluded)
sha256sum /tmp/yoyo_*.exe
```

## QEMU Bare-Metal Test

```bash
./target/release/yoyo link --target=baremetal kernel.ty kernel.elf
qemu-system-x86_64 -kernel kernel.elf -nographic -serial mon:stdio
```

## Anti-Patterns

❌ **Don't** treat this verifier as a standalone compiler — it's one peer, not the compiler.  
❌ **Don't** add new emit logic here without running the full 3-chain DDC verification.  
❌ **Don't** add new platform syscalls — extend [libyoyo API](docs/PROMPT-v3.md#76-libyoyo-api-names-standardized-in-v3) only after audit.

## Note on the project name

This project was originally named `yoyo-decoder`. It was renamed to `yoyo` (v2 era). In v3 the monorepo uses `yoyo-rust` to disambiguate from the canonical `yoyo/` project that holds `projects/yoyo.ty`. See [v3 Part 1](docs/PROMPT-v3.md#part-1-4-project-architecture) for full naming.

---

*For the complete spec covering all 4 projects, see `docs/PROMPT-v3.md` (the **single source of truth**) in the monorepo root.*
