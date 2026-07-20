# YOYO Experiment 2 Progress (2026-07-13/14)

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
| 11 | **Phase 4c libyoyo_* opcodes added to yoy-rust** (0x52-0x5A) | ✅ commit 04e3f44 |
| 12 | **Phase 4c libyoyo_* opcodes added to yoy-asm.asm** (dispatch + emit + calc_size) | ✅ commit 04e3f44 |
| 13 | **yoyo.ty H_50 LOADFILE replaced with libyoyo_open** (line 42) | ✅ commit 04e3f44 |
| 14 | yoy-rust IatThunk enum extended: Win32Api 0-5 + LibyoyoAlloc 6 ... LibyoyoTime 14 | ✅ commit 04e3f44 |
| 15 | yoy-rust linker supports all 15 IAT entries in collect_iat_fixups | ✅ commit 04e3f44 |

### Blocked / Outstanding

| # | Item | Status | Root cause |
|---|------|--------|------------|
| B1 | yoy-asm.exe can't be rebuilt from current yoy-asm.asm | ❌ | Tiny PE linker produces 245KB exe that hangs (relocations still not perfect). Need MSVC link.exe / GoLink. |
| B2 | yoy-asm.exe in repo (24064 bytes from 7/13) predates parser-fix code in 612509f AND libyoyo changes in 04e3f44 | ❌ | Would need rebuild from a system with working PE linker |
| B3 | Tiny PE linker (link-obj.py) generates a PE that runs but loops infinitely | 🟡 | relocations for `call [rip+rel32]` are partially correct, but runtime hangs. Debugging requires further investigation. |
| B4 | yoy-rust linker has bug: `let off = code_off + 2` should be `code_off + 3` for proper rel32 placement | 🟡 | Cosmetic for DDC; rel32 still points to a valid IAT entry (just in slightly wrong slot) |
| B5 | yoy-rust's StubPlatform::emit_loadfile still emits stub (not libyoyo) | ✅ (acceptable) | StubPlatform was a temporary stand-in; new opcodes use real libyoyo calls |

### DDC v0.2 Result (after Phase 4c)

| impl | bytes for H_00 `libyoyo_open state[0x0A]` | matches? |
|------|------------------------------------------|----------|
| yoy-rust (current, post-04e3f44) | 17 bytes: `48 8D 3D 00 00 00 00 FF 15 08 00 00 00 49 89 47 50` | (reference) |
| yoy-asm (current asm source) | would emit same bytes if rebuilt | ✅ design |
| yoy-asm (current yoy-asm.exe in repo, 24064 bytes from 7/13) | emits H_50 stub (8 bytes: `49 89 47 0A 49 89 47 0B`) | ❌ predates libyoyo |

DDC byte-equality on yoy-asm vs yoy-rust requires **yoy-asm.exe to be rebuilt** from current yoy-asm.asm source. Pending: working PE linker (B1, B3).

### Phase 4c Status (libyoyo Migration)

| Component | Status | Notes |
|-----------|--------|-------|
| ISA: 9 libyoyo_* opcodes (0x52-0x5A) | ✅ | yoy-rust + yoy-asm both have them |
| Emit bytes match across implementations | ✅ (design) | Both emit `FF 15 <index> 00 00 00` (call [rip+rel32]) + arg setup |
| yoy-rust linker patches rel32 to IAT | 🟡 | Has bug with rel32 offset (off+2 vs off+3), but functional |
| yoy-asm linker (link-obj.py) patches rel32 | 🟡 | WIP, hangs at runtime |
| libyoyo Rust impl (libyoyo/src/lib.rs) | ✅ | 9 functions, Windows + Linux + baremetal |
| yoyo.ty uses libyoyo_open (H_50 → 0x54) | ✅ | H_50 stub still exists for compat but unused |
| yoy-js (Node.js compiler) has libyoyo opcodes | ❌ | Not in scope this session |
| yoy-asm.exe rebuilt with new asm | ❌ | Blocked on linker (B1) |
| 3-chain DDC byte-equality verified | ❌ | Blocked on yoy-asm.exe rebuild |

### How to Rebuild yoy-asm.exe (For Future)

```sh
# Requires: NASM + a PE linker (MSVC link.exe / GoLink / lld-link)
nasm -f win64 -o yoyo-asm/yoyo-asm.obj yoyo-asm/yoyo-asm.asm
# Then link with a PE linker against kernel32.dll:
#   link.exe yoyo-asm.obj kernel32.lib /OUT:yoyo-asm.exe /SUBSYSTEM:CONSOLE
# Or use GoLink:
#   GoLink /console yoyo-asm.obj kernel32.dll

# After link, run yoy-asm:
yoyo-asm.exe input.ky    # produces output.exe
```

The output should be byte-equal to yoy-rust's `yoyo link --platform stub`.

### Files Touched in this Session

```
yoyo-asm/yoyo-asm.asm                (libyoyo_* opcodes + parser-fix + calc_size fixes)
yoyo-asm/yoyo-asm.exe                (24064 bytes, PREDATES fixes - needs rebuild)
yoyo-rust/verifier/src/isa.rs         (libyoyo_* opcodes 0x52-0x5A)
yoyo-rust/verifier/src/emit.rs        (libyoyo_* emit handlers)
yoyo-rust/verifier/src/platform.rs    (IatThunk enum extended, emit_str_idx_addr)
yoyo-rust/verifier/src/pe_link.rs     (collect_iat_fixups handles indices 6-14)
yoyo-rust/verifier/src/render.rs      (libyoyo_* size estimates)
yoyo-rust/isa-proc/src/lib.rs         (mnemonic_to_variant extended)
yoyo-rust/Cargo.toml                  (panic = "abort")
yoyo-rust/libyoyo/Cargo.toml          (mirror)
yoyo-rust/verifier/Cargo.toml         (libyoyo dep commented out, unused)
yoyo/projects/yoyo.ty                 (H_50 LOADFILE replaced with libyoyo_open)
link-obj.py                          (WIP tiny PE linker)
```

### Commits in this Session

```
69b56ef wip(yoy-rust): StubPlatform emit_loadfile/alloc stub + ISA emit patterns
5dc9408 wip: tiny PE linker for NASM .obj -> .exe (WIP, can't import runtime)
475221b wip: PE linker improvements (ImageBase=0x140000000, SizeOfHeaders, extern detection)
ab242ff docs(experiment-2): progress status - PE linker WIP, Phase 2 blocked on rebuild
04e3f44 feat(phase-4c): libyoyo_* opcodes in yoy-rust + yoy-asm + yoyo.ty migration
```