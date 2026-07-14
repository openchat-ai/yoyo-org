# YOYO Experiment 2 Progress (2026-07-13)

## Phase 2 (Self-Host Compression) — partial

### Goal
gen1 ≡ gen2 ≡ gen3 ≡ M3_asm (3-chain DDC byte-equality on yoyo.ty v0.2).

### Achieved

| # | Item | Status |
|---|------|--------|
| 1 | Static audit of 1525 lines (yoy0.ty, yoyo.ty, yoyo.js, backends, etc.) | ✅ |
| 2 | DDC semantic equivalence (test-min3.ty — H_00 → C3 RET) | ✅ |
| 3 | yoy-rust verifier compiles 0.1 source to output.exe (Windows) | ✅ |
| 4 | yoy-asm.asm source updated: parser writes args byte-by-byte, calc_size correctly returns disp32 for slot ≥ 16 | ✅ |
| 5 | StubPlatform::emit_loadfile / emit_alloc / emit_writefile emit byte-aligned stubs (no panic) | ✅ commit 69b56ef |
| 6 | ISA table includes `=>` emit pattern for ALLOC / LOADFILE / WRITEFILE (was missing, caused lower_op to skip them) | ✅ commit 69b56ef |
| 7 | yoy-rust workspace `panic = "abort"` profile fixed (was breaking stable Rust build) | ✅ commit 69b56ef |
| 8 | StubPlatform stub bytes match yoy-asm 1 stub bytes (8 bytes: 2 disp8 stores) | ✅ |
| 9 | **Tiny PE linker** written (`link-obj.py`): NASM COFF .obj → PE32+ .exe with kernel32 import table | ✅ commits 5dc9408, 475221b |
| 10 | ImageBase = 0x140000000, SizeOfHeaders = 0x400, characteristics = 0x22 — match modern EXE conventions | ✅ |

### Blocked / Outstanding

| # | Item | Status | Root cause |
|---|------|--------|------------|
| B1 | yoy-asm.exe can't be rebuilt from current yoy-asm.asm | ❌ | Tiny PE linker produces 245KB exe that hangs (relocations still not perfect — passes ImageBase / IAT layout, but `call [ExitProcess]` calls hang) |
| B2 | yoy-asm.exe in repo is 24064 bytes from 7/13 — predates parser-fix code in 612509f | ❌ | Would need either working PE linker or pre-built yoy-asm.exe from a system with MSVC link.exe |
| B3 | yoy-asm v0.2 .text 0x126D vs yoy-rust .text 0x1400 layout size diff | ❌ | Layout mismatch due to calc_size drift when emitting disp32 |
| B4 | yoy-asm.calc_size.s_set correctly returns 17 for slot ≥ 16, but pass2.emit_store_state always writes disp8 | ❌ | Stale code path, would require re-running yoy-asm with new fix |

### DDC v0.2 Result

| impl | bytes emitted for SET state_18=0 | correct? |
|------|---------------------------------|----------|
| yoy-asm (v1, build/yoyo-asm.exe from 7/10) | 14 bytes: `48 B8 00 00 00 00 00 00 00 00` + `49 89 47 00` (disp8 byte=0) | ❌ writes to slot 0, not slot 18 |
| yoy-asm (current yoy-asm.asm logic, post-612509f) | would be 17 bytes: `48 B8 ...` + `49 89 87 80 00 00 00` (disp32 for slot 18) | ✅ if rebuilt |
| yoy-rust (StubPlatform, disp32 always) | 17 bytes: `48 B8 ...` + `49 89 87 80 00 00 00` | ✅ |
| yoy-rust (StubPlatform, disp8 always — alternative) | 14 bytes: `48 B8 ...` + `49 89 47 00` (disp8 byte=0) | matches v1 |

DDC byte-equality achievable via **Option A** (rebuild yoy-asm with fixed linker) or **Option B** (revert yoy-rust to disp8 always). Path A is preferred per `decisions/`:

```
"matches incorrect behavior" is the worst outcome — propagates bugs forever
```

### Tiny PE Linker Status (link-obj.py)

Working:
- Parse COFF AMD64 file header, section headers (3-section layout: .text, .bss, .data)
- Parse symbol table including 4-byte-aligned short names and strtab long names
- Read ILT, IAT, hint/name entries (MS COFF format with size prefix)
- Allocate virtual addresses (0x1000, 0x2000, ...) with section alignment
- Build PE32+ optional header (240 bytes) with modern conventions
- Build image-base-relative relocations (REL32 type 4)
- Construct IMAGE_IMPORT_DESCRIPTOR + IAT entries for declared externs
- Compute SizeOfHeaders, SizeOfImage, NumberOfRvaAndSizes

Issues:
- Some cases hit IndexError (parser boundary issues)
- Generated .exe hangs at runtime (likely unresolved `call [rip+rel32]` targets)

### Decision Pending

Path A requires MSVC link.exe / GoLink / similar on this machine. None installed. Tiny PE linker (link-obj.py) is unfinished (B1) and isn't a substitute.

Path B is the pragmatic Phase 2 exit, but `decisions/` anti-patterns catalog calls it "the worst outcome".

**Recommendation**: defer Phase 2 to Phase 4c (libyoyo migration). When H_50 / H_51 / H_20 become libyoyo_* calls, all these hand-coded x64 emitters in yoy-asm and yoy-rust go away, and the byte-match comes for free.

### Files Touched in this Session

```
yoyo-asm/yoyo-asm.asm       (latest source, parser-fix + calc_size fixes)
yoyo-asm/yoyo-asm.exe       (24064 bytes, predates latest fixes)
yoyo-asm/yoyo-asm-test.*    (test artifacts, deleted)
yoyo-rust/verifier/src/isa.rs        (added => emit patterns for ALLOC/LOADFILE/WRITEFILE)
yoyo-rust/verifier/src/platform.rs   (StubPlatform::emit_loadfile stub impl)
yoyo-rust/Cargo.toml                 (added panic = "abort" for libyoyo build)
yoyo-rust/libyoyo/Cargo.toml         (mirror)
yoyo-rust/verifier/Cargo.toml        (commented out libyoyo dep, unused)
link-obj.py              (WIP PE linker)
```

### Commits in this Session

```
69b56ef wip(yoy-rust): StubPlatform emit_loadfile/alloc stub + ISA emit patterns
5dc9408 wip: tiny PE linker for NASM .obj -> .exe (WIP, can't import runtime)
475221b wip: PE linker improvements (ImageBase=0x140000000, SizeOfHeaders, extern detection)
```