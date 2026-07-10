# yoyo-js

> **PROJECT 2 of 4** in the [yoyo-org](https://example.com/yoyo-org) monorepo. **Part 1 (Application Layer)** of the [complete v3 specification](../docs/PROMPT-v3.md#part-1-4-project-architecture).
>
> See [PROMPT-v3.md Part 1 § 4-Project Architecture](../docs/PROMPT-v3.md#part-1-4-project-architecture) for the full project layout.

## What this project is

The **YOYO compiler written in JavaScript** — specifically the **M0 trust anchor seed** plus the application-layer build path.

This project has **two roles**:

1. **Seed Compiler (Entity 2)**: `src/yoyo.js` (159 lines, audited once) is the **JavaScript implementation** of the YOYO compiler. It is the **trust anchor** of the whole system — humans read all 159 lines and golden-hash the result.

2. **Source Generator (Entity 3)**: `src/yoyo-gen.js` (2144 lines) is a **rarely-run source generator** that produces `projects/yoyo.ty` (the canonical source). Bootstrap calls it twice to verify it's deterministic; after Decision #13 lockdown, it is archived to `scripts/yoyo-gen-archived.mjs`. See [v3 Part 5.6](../docs/PROMPT-v3.md#56-revised--yoyo-genjs-is-a-rarely-run-source-generator).

## What this project is NOT

- **NOT** the only compiler. The full YOYO system has **3 peers** ([yoyo-js](../yoyo-js/) + [yoyo-rust](../yoyo-rust/) + [yoyo-asm](../yoyo-asm/)) verified by [3-chain DDC](../docs/PROMPT-v3.md#part-6-ddc-verification-3-chain).
- **NOT** a runtime utility library — it produces binaries, doesn't depend on one.
- **NOT** continuously edited. After the [v3 lockdown protocol](../docs/PROMPT-v3.md#94-decision-13-yoyo-ty-lockdown-v3-new) takes effect, `projects/yoyo.ty` is sha256-pinned and changes require a documented 8-step ceremony.

## Repository Layout

```
yoyo-js/
├── src/
│   ├── yoyo.js                # 159-line M0 seed compiler (the actual YOYO compiler)
│   ├── yoyo-gen.js            # 2144-line source generator; writes projects/yoyo.ty
│   │                          #   (rarely-run: bootstrap calls it 2× for determinism;
│   │                          #    after lockdown, archived as yoyo-gen-archived)
│   ├── platform/              # JS portion of platform-emit (encode-x64, pe, elf, ...)
│   └── backends/               # per-platform emit cores (linux-emit-core.js, ...)
├── projects/
│   ├── yoyo.ty               # canonical source (sha256-locked, Decision #13)
│   ├── ternary_signal.ty      # decision-aggregation example
│   ├── stock_gui.ty           # trading-signal example
│   ├── signal_log.ty
│   └── gui_signal.ty
├── scripts/                    # bootstrap, DDC verify, evolution check
├── tests/                       # .ty test cases
├── tools/                       # build/test helpers
├── docs/                        # JS-specific notes (format, emit rules)
│   ├── emit-rules.md
│   ├── FORMAT.md
│   └── TRIT.md
└── package.json
```

## The 159-Line Seed Compiler (`src/yoyo.js`)

```bash
wc -l src/yoyo.js
# 159 src/yoyo.js
```

This file is **frozen** once audited. It is the actual YOYO compiler — reads `.ty` source and emits `.text` x64 bytes. It does NOT include:
- IAT plumbing (delegated to `platform/pe-builder.js`)
- ELF plumbing (delegated to `platform/elf-builder.js`)
- x64 opcode encoding (delegated to `platform/encode-x64.js`)

Those live in `platform/` and are independently auditable.

## yoyo-gen.js: The Source Generator (`src/yoyo-gen.js`)

```bash
wc -l src/yoyo-gen.js
# 2144 src/yoyo-gen.js
```

`yoyo-gen.js` is **not a compiler** — it's a **source generator** that programmatically builds `projects/yoyo.ty`. It's called rarely:
- **Bootstrap** (`scripts/bootstrap-check.ps1:8 + :12`): twice for determinism check
- **Lockdown** (Decision #13): archived as `scripts/yoyo-gen-archived.mjs`
- **Regular compile**: never (yoyo.js reads already-emitted yoyo.ty)

The 2-call bootstrap determinism check is DDC applied **to the generator itself** — proves yoyo-gen.js is non-time-dependent before yoyo.ty even exists.

```bash
# Regular flow: yoyo.js reads projects/yoyo.ty -> emits .exe
node src/yoyo.js projects/yoyo.ty build/yoyo.exe

# Regeneration (rare, Part 9.4): yoyo-gen writes projects/yoyo.ty
node src/yoyo-gen.js --target=win
```

## Build

```bash
npm install
# Boot M1 from M0 (yoyo.js seed)
node src/yoyo.js projects/yoyo.ty build/yoyo.exe
```

The output (`build/yoyo.exe`) is **yoyo.exe compiled by yoyo.js from yoyo.ty**. This is **M1**.

## Self-Hosting

```bash
# Run the full chain M1 → M2 → M3 → M3_rust → M3_asm
cp projects/yoyo.ty input.ky
./build/yoyo.exe                        # generates output.exe (= M2)
./output.exe                           # (= M3)
cd ../yoyo-rust
./target/release/yoyo link ../yoyo/projects/yoyo.ty build/M3_rust.exe
cd ../yoyo-asm
./yoyo-asm ../yoyo/projects/yoyo.ty build/M3_asm.exe
```

All 5 outputs (M1, M2, M3, M3_rust, M3_asm) must have **byte-equal `.text` and `.data` sections**. This is 3-chain DDC verification.

See [v3 Part 5.5](../docs/PROMPT-v3.md#55-3-chain-ddc-verification-across-the-chain) for the full procedure.

## The Lockdown Protocol (Decision #13)

After the chain is verified and **frozen**, `projects/yoyo.ty` is **immutable**. Any change requires the 8-step protocol in [v3 Part 9.4](../docs/PROMPT-v3.md#94-decision-13-yoyo-ty-lockdown-v3-new):

1. Edit `src/yoyo-gen.js` (or compressed `scripts/yoyo-gen-active.mjs` post-Phase 4a) with new emit logic
2. Run it → regenerate `yoyo.ty` (**twice** for determinism check via `bootstrap-check.ps1`)
3. Run `scripts/verify-yoyo-ty.mjs` (must pass with new hash)
4. Run `scripts/verify-selfhost.ps1` (4-round byte-equal)
5. Run [yoyo-rust](../yoyo-rust/) DDC verifier — all 3 chains must match
6. Update `tests/yoyo.ty.lock` with new sha256
7. Move `scripts/yoyo-gen-active.mjs` to `scripts/yoyo-gen-archived.mjs` (or rename `yoyo-gen.js` → `yoyo-gen-archived.js` directly)
8. Commit both files + lock file atomically

Any change outside this protocol = **lock broken**, all downstream artifacts invalidated.

## Anti-Patterns

❌ **Don't** edit `projects/yoyo.ty` directly — it's generated and locked  
❌ **Don't** invoke `scripts/yoyo-gen-archived.mjs` — it's a frozen historical record  
❌ **Don't** modify `src/yoyo.js` after golden-hash — it's the trust anchor  
❌ **Don't** add platform-specific bytes here — they live in `platform/`

---

*For the complete spec covering all 4 projects, see [`../docs/PROMPT-v3.md`](../docs/PROMPT-v3.md) (the **single source of truth**) in the monorepo root.*
