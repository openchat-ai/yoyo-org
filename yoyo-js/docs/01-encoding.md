# YOYO Instruction Encoding

> YOYO uses a **24-bit instruction encoding** with two modes: single-segment (flat opcode) and multi-segment (12-bit CPU_TYPE + 12-bit OPCODE).

## Total Width: 24 bits

Why 24 bits and not 32 or 16?
- **16 bits** (65,536 slots) is tight for cross-architecture expansion
- **32 bits** wastes byte alignment — 24 fits in exactly 3 bytes
- **24 bits** = 16,777,216 slots, byte-aligned, future-proof

## Mode 1: Single-Segment (Default)

```
[24-bit OPCODE]
```

All 24 bits encode the instruction directly. No architecture prefix. Used when only one target architecture (e.g., x64 only).

```
byte[0]: OPCODE[23:16]
byte[1]: OPCODE[15:8]
byte[2]: OPCODE[7:0]
```

Range: 0x000000 – 0xFFFFFF (16,777,216 instructions)

## Mode 2: Multi-Segment (Future)

```
[12-bit CPU_TYPE][12-bit OPCODE] = 24 bits total
```

The split is **symmetric (12+12)** — chosen over asymmetric splits like 8+16 because:

1. **Byte alignment**: three bytes with one nibble-shuffle, simple to encode/decode
2. **Symmetric**: equal weight to architecture identity and instruction identity
3. **Theme alignment**: matches the "12M" plan name in `PROMPT-YOYO-REWRITE-12M.md`
4. **Capacity**: 4096 architectures × 4096 instructions per architecture = 16,777,216 total

### Byte Layout

```
byte[0]: CPU_TYPE[11:4]              // upper 8 bits of CPU_TYPE
byte[1]: CPU_TYPE[3:0] | OPCODE[11:8]  // lower 4 bits of CPU_TYPE + upper 4 bits of OPCODE
byte[2]: OPCODE[7:0]                  // lower 8 bits of OPCODE
```

### Decoding Pseudocode

```rust
fn decode(bytes: [u8; 3]) -> (u16, u16) {
    let cpu_type = ((bytes[0] as u16) << 4) | ((bytes[1] as u16) >> 4);
    let opcode = (((bytes[1] & 0x0F) as u16) << 8) | (bytes[2] as u16);
    (cpu_type, opcode)
}

fn encode(cpu_type: u16, opcode: u16) -> [u8; 3] {
    [
        (cpu_type >> 4) as u8,
        (((cpu_type & 0x0F) as u8) << 4) | ((opcode >> 8) as u8),
        (opcode & 0xFF) as u8,
    ]
}
```

### Reserved CPU_TYPE Values

| Value | Meaning |
|-------|---------|
| 0x000 | x86-64 (default) |
| 0x001 | AArch64 (ARM64) |
| 0x002 | RISC-V 64 |
| 0x003–0x00F | Reserved for common ISAs |
| 0x010–0x0FF | Reserved for vendor ISAs |
| 0x100–0xFFF | Reserved for future use |

## Mode Selection

The mode is chosen at **ISA table parse time**, not at runtime. The mode is fixed for a given compilation session:

- Default: Single-Segment (no CPU_TYPE, simpler decode)
- Cross-architecture builds: Multi-Segment (target_arch set in build config)

The compiler output `.ty` source files are mode-agnostic — they use the same 24-bit opcode in both modes. The ISA table parser handles both modes.

## Current Opcode Allocation (Phase 0–6)

All 38 active instructions fit in the **low byte** (0x00–0xFF). The upper 16 bits are unused.

| Opcode (hex) | Mnemonic | Args | Phase |
|--------------|----------|------|-------|
| 0x00 | NOP | — | 1 |
| 0x10 | DATA | str/raw | 1 |
| 0x12 | STR | string | 1 |
| 0x13 | RAW | bytes | 1 |
| 0x20 | ALLOC | slot size | 1 (syscall) |
| 0x30 | SET | slot imm | 1 |
| 0x40 | HANDLER | hh | 1 |
| 0x41 | CALL | hh | 1 |
| 0x50 | LOAD_FILE | slot str_idx | 1 (syscall) |
| 0x51 | WRITE_FILE | slot str_idx sz | 1 (syscall) |
| 0x60 | GET | dst src | 1 |
| 0x61 | ADD | slot imm | 1 |
| 0x62 | SUB | slot imm | 1 |
| 0x63 | IMUL | dst src | 1 |
| 0x65 | CMP | a b | 1 |
| 0x66 | INC | slot | 1 |
| 0x67 | DEC | slot | 1 |
| 0x68 | ADDV | dst src | 1 |
| 0x69 | SUBV | dst src | 1 |
| 0x70 | JMP | hh | 1 |
| 0x71 | JE | hh | 1 |
| 0x72 | JNE | hh | 1 |
| 0x73 | JL | hh | 1 |
| 0x74 | JGE | hh | 1 |
| 0x75 | JLE | hh | 1 |
| 0x76 | JG | hh | 1 |
| 0x77 | JB | hh | 1 |
| 0x78 | JAE | hh | 1 |
| 0x79 | JBE | hh | 1 |
| 0x7A | JA | hh | 1 |
| 0x80 | LDB | dd ss oo | 1 |
| 0x82 | JL | hh | 1 (alias for 0x73) |
| 0x83 | JG | hh | 1 (alias for 0x76) |
| 0x84 | MEMCPY_DATA | dd off sz | 1 |
| 0x85 | MEMCPY_STATE | dd ss sz | 1 |
| 0xA0 | RAW_BYTE | byte | 1 (escape) |
| 0xA1 | RAW_BYTES | bytes | 1 (escape) |
| 0xFF | RET | — | 1 |

**Total: 38 instructions** (including 4 reserved DATA/STR slots).

## Why the Low Byte Is Enough

For Phase 0–6 (single-architecture builds), all 38 instructions fit in 8 bits (256 slots). The full 24-bit space is reserved for:

- Phase 4+ multi-architecture (CPU_TYPE prefix)
- Phase 5+ baremetal extensions (interrupt handling, page table manipulation)
- Future extensions (e.g., SIMD, crypto instructions)

We do **not** split the low byte into sub-spaces prematurely. When the ISA grows beyond 256 instructions, the multi-segment mode handles it via the upper 16 bits.

## Escape Hatches: 0xA0 and 0xA1

Two opcodes are **escape hatches** — they emit raw x64 bytes verbatim:

- `0xA0 RAW_BYTE byte` — emits 1 byte
- `0xA1 RAW_BYTES bytes...` — emits multiple bytes (until next instruction boundary)

These exist because **the ISA table cannot anticipate every x64 instruction**. For example, writing to VGA memory `mov [0xB8000], 0x48` requires the literal byte sequence `48 C7 06 48 00 00 00` (mov rsi, 0x48; mov [rsi], ...). The ISA cannot express this — so `0xA1` lets you emit any byte sequence.

This is by design: **the ISA is intentionally incomplete** so that escape hatches force complex/rare operations to be explicit. Auditors can grep for `0xA1` and inspect each occurrence.

## Encoding in `.ty` Files

In `.ty` source files, opcodes are written as 2-digit hex (low byte only):

```
30 50 00    ; SET state[0x50] = 0
```

The upper 16 bits are implicitly zero in single-segment mode. In multi-segment mode, the CPU_TYPE is set globally at the build configuration level.

## Encoding in the ISA Table (`src/isa.rs`)

In the ISA table, opcodes are written with full 24-bit notation:

```
0x0030 SET slot imm => movabs rax imm store_state slot rax
0x0A01 RAW_BYTES bytes => [bytes]
```

The proc-macro `isaproc` parses these and generates:

- The `TirOp` enum (carries the full opcode as `u32`)
- `opcode_from_u8(op: u8)` lookup (returns the matching `TirOp`)
- `isaproc::lower_op(op, args)` dispatcher

## Byte Alignment Guarantee

24 bits = 3 bytes. No padding, no bit-packing wasted on byte boundaries. **All fields are byte-aligned.**

## Future Expansion Paths

| Need | Expansion |
|------|-----------|
| More instructions in single-arch | Use full 16-bit OPCODE (65,536 slots per arch) |
| Multiple architectures | Switch to multi-segment mode |
| Beyond 16,777,216 total slots | Bump to 32-bit encoding (4 bytes) — breaks byte alignment |
| Sub-byte instruction packing | Not supported (would break x64 emission) |

## Comparison with Other Encodings

| Project | Width | Mode | Alignment |
|---------|-------|------|-----------|
| **YOYO** | 24 bits | Single/Multi | Byte |
| x86-64 | 1–15 bytes | Variable | Byte |
| ARM64 | 4 bytes | Fixed | Byte |
| RISC-V | 2–4 bytes (compressed: 2) | Variable | Byte |
| WebAssembly | 1 byte + LEB128 | Variable | Byte |
| JVM | 1 byte (255) + 2-byte ext. | Variable | Byte |

YOYO's 24-bit fixed-width is **larger than typical ISAs but simpler to parse** — the proc-macro doesn't need variable-length decoding logic.

## Rationale

The 24-bit fixed-width encoding with byte-aligned fields gives YOYO:

1. **Simplicity** — fixed width, no variable-length parsing
2. **Auditability** — each instruction's byte layout is unambiguous
3. **Cross-architecture readiness** — multi-segment mode for the future
4. **Byte alignment** — no bit-packing, matches x64 emission naturally

Trade-off: instructions are larger than minimal (x86 averages ~3 bytes per instruction; YOYO is 3 bytes per opcode). This is acceptable because **YOYO's value is auditability, not density**.