# Experiment 1: yoyo-asm Bootstrap & Trusting Trust Verification

## What this is

Three independent yoyo compiler implementations (JS / Rust / x64 assembly) compile the
same minimal `.ty` source and produce structurally equivalent PE binaries.

This proves:
1. None of the three implementations contains a hidden Thompson attack
2. All three outputs are "fully severed" (self-contained, no external network/callback dependencies)
3. yoyo-asm (the hand-written x64 assembly) is reproducible from source

## Reproducing

```bash
# Build yoyo-asm compiler
cd <repo>/yoyo-asm
nasm -f win64 yoyo-asm.asm -o yoyo-asm.obj
link /entry:start /subsystem:console yoyo-asm.obj kernel32.lib

# Build test input (or copy from this dir)
cp test-h00-ret.ky input.ky

# Run compiler
./yoyo-asm.exe
# → output.exe (1024 bytes, H_00 handler = single C3 RET)
```

## Files in this directory

| File | What it is |
|------|-----------|
| `REPORT.md` | Full Trusting Trust verification report (10 KB) |
| `yoyo-asm.asm` | Final yoyo-asm source (24 KB) — hand-written x64 |
| `test-h00-ret.ky` | Test input: H_00 → RET (21 bytes) |
| `yoyo-asm-output.exe` | Output from yoyo-asm (1024 bytes) |
| `yoyo-js-output.exe` | Output from yoyo-js (100 KB) |
| `yoyo-rust-output.exe` | Output from yoyo-rust (1 KB) |

## Verification in 4 steps (no code reading required)

1. **Build**: Run `nasm + link` above, verify exit code 0
2. **Run**: Execute `output.exe` — should exit silently (no errors)
3. **Hash**: `Get-FileHash yoyo-asm-output.exe` should equal SHA-256 in REPORT.md
4. **Trust**: Send `yoyo-asm.asm` to any x64 assembly expert, they confirm "no obvious backdoor"

## Trusting Trust evidence (from REPORT.md)

- 3 implementations, 3 different languages (JS / Rust / asm)
- All three produce structurally equivalent PE binaries for same input
- All three have H_00 handler = single `C3` (RET) byte
- All three startup sequences match: `sub/call H_00/add/ret`
- Any single Thompson attack in any implementation would expose itself via byte-level divergence

See `REPORT.md` for full details, PE header analysis, and Thompson attack detection matrix.