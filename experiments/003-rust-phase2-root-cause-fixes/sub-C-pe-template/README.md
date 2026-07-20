# Sub-Exp C — pe_link Win64 template rewrite (Phase 2 ROOT CAUSE)

> **Date**: 2026-07-15
> **Bug ID**: 003-C (Phase 2 root cause)
> **Subject**: `yoy0-rust/verifier/src/pe_link.rs::link` produces invalid Win64 PE
> **Status**: ⏳ IN PROGRESS — plan + investigation below

---

## 1. The Bug

After sub-A + sub-B, `yoy0-rust link yoy0.ty` produces a 1605-byte PE that
**Win64 loader refuses to execute**:

```
$ yoy0-rs-direct.exe
指定的 executable 不是有效的应用程序
(...not a valid Win32 application...)
```

But `yoy0-asm/yoyo-asm.asm` 7/10 produces a valid 24064-byte PE that runs.

## 2. What's broken (preliminary investigation)

The current `pe_link.rs::link` builds the PE template by hand. From
exp-002 binary dump:

```
size: 1605 = 0x645
first 96 bytes: MZ header + DOS stub + PE signature
                + Optional Header (Machine=0x8664=AMD64 ✓)
section table: .text at file offset 0x400 (4160 bytes from file start)
              VirtualSize = 0x74 (116), SizeOfRawData = 0x1000
              VirtualAddress = 0x1000
              PointerToRawData = 0x400
```

**Problem**: the actual file is 1605 bytes. `.text` section's
PointerToRawData=0x400 means content starts at file offset 1024. With
VSize=0x74, the section is 116 bytes but the file ends at 1605 — section
content overflows into garbage.

But more importantly: the **Startup code may not call H_00 correctly**:
Looking at the first 96 bytes from offset 0x400:

```
49 89 47 70 48 83 C0 07 49 89 47 70 ...
```

That's `mov [r15+0x70], rax; add rax, 7; mov [r15+0x70], rax` — looks
like SET state[0x0E]=7 emit, **not** startup code.

Where is the actual `sub rsp, 8 / call H_00 / add rsp, 8 / ret` startup?
It's likely missing or malformed.

## 3. Required Win64 PE Template (this sub-exp target)

Per PROMPT-v3.md Part 7 (Platform Abstraction) and exp1's
yoy0-asm.asm, the minimum Win64 PE template must have:

### 3.1 DOS Header (64 bytes)
- `e_magic = 0x5A4D` ("MZ")
- `e_lfanew = 0x80` (PE signature at file offset 0x80)
- Filled with 0 otherwise

### 3.2 DOS Stub (0x80 - 0x80 = empty or "..." padding)
- 32-byte padding between DOS header end (0x40) and PE signature (0x80)

### 3.3 PE Signature (4 bytes)
- `"PE\0\0"` at file offset 0x80

### 3.4 COFF File Header (20 bytes)
- `Machine = 0x8664` (AMD64)
- `NumberOfSections = 1`
- `TimeDateStamp = 0`
- `PointerToSymbolTable = 0`
- `NumberOfSymbols = 0`
- `SizeOfOptionalHeader = 240` (PE32+ for x64)
- `Characteristics = 0x2002` (EXECUTABLE_IMAGE | DLL_BITS_32)

### 3.5 Optional Header (240 bytes, PE32+)
Critical fields:
- `Magic = 0x20B` (PE32+)
- `AddressOfEntryPoint = 0x1000 + startup_call_rel32_byte_pos` (offset within .text)
- `ImageBase = 0x140000000` (Win64 default)
- `SectionAlignment = 0x1000`
- `FileAlignment = 0x200`
- `SizeOfImage = 0x2000` (.text = 0x1000 + ~0x1000 bytes = 2 pages)
- `SizeOfHeaders = 0x400` (one FileAlignment block for headers)
- `Subsystem = 3` (CONSOLE)
- `NumberOfRvaAndSizes = 16` (typical)

### 3.6 Section Table (40 bytes for .text)
- `Name = ".text\0\0\0"`
- `VirtualSize = <actual x64 code size>`
- `VirtualAddress = 0x1000`
- `SizeOfRawData = <aligned code size>`
- `PointerToRawData = 0x200` (after headers, FileAlignment boundary)
- `Characteristics = 0x60000020` (CODE | EXECUTE | READ)

### 3.7 .text Section Content

First 14 bytes = **Win64 startup code** (call H_00 + return):
```
48 83 EC 08         ; sub rsp, 8
E8 XX XX XX XX      ; call H_00   (rel32 to H_00 entry in yoyo.ty emit)
48 83 C4 08         ; add rsp, 8
C3                  ; ret
```
Where the call rel32 = (H_00_offset_within_text) - (call_end_offset_within_text)

Plus the actual yoyo.ty compiled x64 code following.

### 3.8 File Layout

```
[0x000 - 0x1FF]  PE Headers (DOS + COFF + Optional + Section Table = 0x400 aligned)
[0x200 - 0xXXX]  .text section (startup + yoyo code) aligned to FileAlignment
```

Total size: roughly SizeOfImage = max(VirtualAddress+VirtualSize) rounded up to SectionAlignment.

## 4. Plan

This is a substantial rewrite. To prevent regressions, split into phases:

### Phase C.1 — Valid Win64 PE skeleton
- Replace `pe_link.rs::link` with hand-assembled valid Win64 PE
- First `sub rsp, 8; call H_00; add rsp, 8; ret` startup
- Empty H_00 stub (or 1 byte C3 if H_00 has no body)

**Verification**: link test-min3.ty (1-line `40 00 FF` — H_00 = RET) and run binary; exit code 0 expected.

### Phase C.2 — Real startup binding
- Patch the `call H_00` rel32 to point at the actual H_00 entry in the compiled code
- Test with yoy0.ty v0.1 baseline — H_00 has multiple instructions, should run

### Phase C.3 — Match yoy0.js output exactly (byte-equal target)
- Use the EXP1 protocol from experiments/01-...: 3 implementations of same source, all byte-equal
- Compare against yoy0-js generated yoyo.exe (not yet built by us)
- Compare against yoy0-asm generated yoyo.exe (`yoyo-asm/yoyo-asm.exe`, 24064 B, 7/14)

This sub-exp will likely land C.1 + C.2 only; C.3 is exp 005 (js) territory.

## 5. Acceptance

- `yoyo-rust link test-min3.ty` produces a PE that **runs and exits 0**
- `yoyo-rust link yoy0.ty` produces a PE that **runs and exits 0** (or in v0.1's stub case, runs without crashing)
- Link output is **byte-equal E4311DC2...** (v0.1 baseline, no regression in H_50 stub path)
  - WAIT: This byte-equal was for the BROKEN 1605 B PE. **The new valid PE will have a different hash** (different startup sequence). That's the point.
  - The link output must RUN. Different hash is fine and expected.
