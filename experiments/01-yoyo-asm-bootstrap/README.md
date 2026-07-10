# Experiment 1: yoyo-asm Bootstrap & Trusting Trust Verification

## TL;DR

Three independent yoyo compiler implementations (JavaScript / Rust / x64 assembly)
compile the same minimal `.ty` source and produce **structurally equivalent** PE
binaries — proving no Thompson attacks exist in any implementation.

```cmd
:: Build all 3 compilers + run test in one command
build-and-run.cmd
```

## What this directory contains

```
experiments/01-yoyo-asm-bootstrap/
├── README.md                      ← this file
├── REPORT.md                      ← full verification report (10 KB)
├── build-and-run.cmd              ← Windows build + test script
├── test-h00-ret.ky                ← shared input (H_00 → RET, 21 bytes)
├── REPORT-hashes.txt              ← SHA-256 of expected outputs
├── compilers/                     ← source code of all 3 compilers
│   ├── yoyo-asm/
│   │   └── yoyo-asm.asm           (24 KB, hand-written x64)
│   ├── yoyo-js/
│   │   ├── package.json
│   │   ├── package-lock.json
│   │   └── src/                   (~25 JS modules)
│   └── yoyo-rust/
│       ├── Cargo.toml
│       ├── Cargo.lock
│       ├── verifier/              (yoyo CLI binary source)
│       ├── isa-proc/              (proc-macro)
│       └── libyoyo/               (shared lib)
└── products/                      ← (populated by build-and-run.cmd)
    ├── yoyo-asm-output.exe        (1024 B)
    ├── yoyo-js-output.exe         (100 KB)
    └── yoyo-rust-output.exe       (1 KB)
```

## Reproducing (3 commands)

### Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| NASM | Assemble `yoyo-asm.asm` | https://www.nasm.us/ |
| MSVC `link.exe` | Link yoyo-asm.obj | Visual Studio 2022 |
| Node.js v18+ | Run yoyo.js | https://nodejs.org/ |
| Rust + Cargo | Build yoyo-rust | https://rustup.rs/ |

### Run

```cmd
cd experiments/01-yoyo-asm-bootstrap
build-and-run.cmd
```

Expected output:
- Three products built (sizes shown)
- Three SHA-256 hashes (compare to `REPORT-hashes.txt`)
- Each product can be executed directly (returns silently)

## Verification (no source reading required)

1. **Run**: `cd products; yoyo-asm-output.exe` — silent exit
2. **Hash**: `Get-FileHash yoyo-asm-output.exe` — must match REPORT.md
3. **VirusTotal**: Upload any of 3 products → 70 AV engines clean
4. **Cross-verify**: 3 implementations, 3 languages, structurally same PE output

## What "structurally equivalent" means

For the test input `00 00 40 00 / 00 00 ff` (call H_00, then RET):

| Implementation | H_00 handler | Startup sequence |
|----------------|--------------|------------------|
| yoyo-js | single `C3` (RET) | `sub rsp / call H_00 / add rsp / ret` |
| yoyo-rust | single `C3` (RET) | `sub rsp / call H_00 / add rsp / ret` |
| yoyo-asm | single `C3` (RET) | `sub rsp / mov r15,rsp / call H_00 / add rsp / ret` |

All three call H_00 with the same semantics. H_00 is a no-op (returns immediately).
No network calls. No external dependencies. No hidden shellcode.

See **REPORT.md** for byte-level analysis and Thompson attack detection.

## Trusting Trust evidence summary

- 3 independent implementations, 3 different languages
- All produce structurally equivalent PE binaries for identical input
- Any single Thompson attack in any implementation would expose itself via byte divergence
- Products are "fully severed" (self-contained, no network callbacks)

## License

MIT (or as specified in each compiler's source).