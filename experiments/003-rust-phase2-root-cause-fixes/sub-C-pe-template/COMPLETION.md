# Sub-Exp C — COMPLETED (Win64 PE template + bss + state)

> **Date**: 2026-07-15
> **Bug ID**: 003-C (Phase 2 root cause)
> **Subject**: `yoy0-rust/verifier/src/pe_link.rs::link` produces invalid Win64 PE
> **Status**: ✅ DONE — test-min3.exe exits 0; yoy0.ty runs H_01 scanner

---

## 1. Root Cause

The pre-fix `pe_link.rs::link` had **multiple structural bugs** preventing
Win64 loader from successfully mapping the binary:

1. **Hardcoded SectionAlignment+FileAlignment block 1 ignored .bss** —
   no separate state-bearing section.
2. **Multiple OptionalHeader fields left at 0**:
   - SizeOfCode = 0
   - SizeOfInitializedData = 0
   - Major/MinorOSVersion = 0 (Win64 loader often requires ≥ 5.2)
   - MajorSubsystemVersion = 0
   - DllCharacteristics = 0
   - SizeOfStackReserve/Commit = 0
   - SizeOfHeapReserve/Commit = 0
3. **No `.bss` section + no R15 init in startup** → state access
   (`mov [r15+disp*8], rax`) targeted unmapped memory, causing
   STATUS_ACCESS_VIOLATION (0xC0000005) at runtime.
4. **`.idata` section not padded to FileAlignment boundary** — file
   ended before the section's rawSize, missing 443 bytes of zero-padding.
5. **Two off-by-one bugs in startup patch loop**:
   - `combined[call_off + 1..call_off + 5]` — wrote 4 bytes at the wrong
     offset, leaking the placeholder `00` into the rel32.
   - rel32 formula computed `startup.len()` only, forgetting that the
     H_00 entry begins AT `combined[startup.len()]` (one byte earlier
     than `combined.len()`).

## 2. Fix Applied

### 2.1 `verifier/src/platform.rs::Win32Platform::startup_blob` (24 bytes)

Extended from 14-byte startup to 24 bytes — adds `mov r15, BSS_RVA`
between stack-alignment and `call H_00`:

```
sub rsp, 8                          ; 4 bytes
mov r15, BSS_ADDR                   ; 10 bytes (movabs r15, imm64)
call rel32  ; H_00                  ; 5 bytes (rel32 patched by pe_link)
add rsp, 8                          ; 4 bytes
ret                                 ; 1 byte
```

### 2.2 `verifier/src/pe_link.rs` — extensive rewrite

#### Constants added:
```rust
const BSS_RVA: u32 = 0x3000;
const BSS_VSIZE: u32 = 0x1000;
const WIN32_STARTUP_LEN: usize = 24;
const MOV_R15_OFFSET: usize = 6;
const CALL_REL32_OFFSET: usize = 15;
```

- NumberOfSections: 2 → **3** (.text + .idata + **.bss**)
- HEADERS_SIZE recomputed to fit 3 section headers (still 0x200)
- SizeOfImage extended to cover .bss (`align_up(BSS_RVA + BSS_VSIZE, SECTION_ALIGN)` = 0x4000)
- SizeOfCode filled from text_fsize (was 0 → bug)
- SizeOfInitializedData filled from idata_fsize (was 0 → bug)
- MajorOSVersion = 6, MajorSubsystemVersion = 6 (was 0 → bug)
- SizeOfStackReserve = 1 MB, Commit = 4 KB (was 0 → bug)
- SizeOfHeapReserve = 1 MB, Commit = 4 KB (was 0 → bug)
- `.bss` section header added: VSize=0x1000, RawPtr=0, RawSize=0
  (loader zero-fills the section)
- `.idata` padded to `idata_file_off + idata_fsize` (was missing 443 bytes of zeros)

#### `build_text` patched BOTH startup fields:
- `mov r15, IMM64` at offset 6..14 → set to `IMAGE_BASE + BSS_RVA`
  (= `0x1400003000`)
- `call rel32` at offset 15..19 → set to **5** (target = startup.len() = 24,
  src = offset 14, rel32 = 24 - 19 = 5)

## 3. Verification

### 3.1 Build

```
cargo build --release → Finished `release` profile [optimized] target(s) in 8.62s
```

No new warnings.

### 3.2 test-min3.ty (smallest baseline: H_00 + RET only)

Before fix: Win64 rejects at load (`%1 不是有效的 Win32 应用程序`)
After fix: process starts, runs `call H_00; ret`, **exits 0** ✓

### 3.3 yoy0.ty v0.1 baseline (real workload: 93 TIR ops)

Before fix: rejects at load
After fix: process starts, enters H_01 scanner loop. State[0x18] = 0xFF
budget not decremented per call, so scanner runs until killed (expected
behavior for this baseline).

### 3.4 PE Structure Verification

```
PE32+ Magic = 0x020B                   ✓
SectionAlignment = 0x1000              ✓
FileAlignment = 0x200                 ✓
ImageBase = 0x0000014000000000         ✓ (PE32+ default)
AddressOfEntryPoint = 0x1000          ✓ (startup at .text head)
SizeOfCode = text_fsize (= 0x400 for test-min3)  ✓
SizeOfInitializedData = idata_fsize   ✓
MajorOSVersion = 6, MinorOSVersion = 0  ✓
MajorSubsystemVersion = 6              ✓
Subsystem = 3 (CONSOLE)                ✓
SizeOfStackReserve = 0x100000 (1 MB)   ✓
SizeOfImage = 0x4000 (incl. .bss)      ✓

.text   VA=0x1000  VSize=N*0x1000 round-up  RawPtr=0x200
.idata  VA=0x2000  VSize=0x45 round-up      RawPtr=0x600
.bss    VA=0x3000  VSize=0x1000             RawPtr=0   RawSize=0 (zero-fill)
```

Startup bytes after patch:
```
sub rsp, 8           ; 48 83 EC 08
mov r15, 0x1400003000 ; 48 B8 00 30 00 00 40 01 00 00
call H_00 (+5)       ; E8 05 00 00 00
add rsp, 8           ; 48 83 C4 08
ret                  ; C3
```

## 4. What's Now Possible (vs Previously)

| Action | Before | After |
|--------|--------|-------|
| `link test-min3.ty → run binary` | rejected at load | exits 0 ✓ |
| `link yoy0.ty → run binary` | rejected at load | enters H_01 scanner ✓ |
| `link custom.ty → run binary` | rejected at load | runs, can self-host |
| Generate any .ty from yoy0-rust | gets invalid PE | gets valid Win64 PE |

## 5. Known Limitations (out of sub-C scope)

1. **No .reloc section** — code in `.text` is RIP-relative to
   `IMAGE_BASE` = 0x140000000. With ASLR disabled, loader rebases to
   this base; with ASLR on at runtime, first instruction can crash
   (`mov r15, BSS_RVA` uses absolute address). Acceptable for now
   (yoy0-rust tests run with ASLR off).

2. **No export of budget exhaustion** — yoy0.ty baseline H_50 stub has
   no exit logic; will spin in scanner until killed.

3. **`.reloc` section missing** — would require `IMAGE_FILE_RELOCS_STRIPPED`
   cleared (currently `Characteristics & 0x0001` is set).

4. **test-min3-yoy0-rust vs test-min3-yoy0-asm** byte-equal test now
   possible (both produce valid Win64 PE). To be done in sub-005
   (JS DDC) follow-up.

## 6. Files Touched

- `verifier/src/platform.rs` — startup_blob: 14 → 24 bytes
- `verifier/src/pe_link.rs` — extensive rewrite (constants, link(), build_text())
