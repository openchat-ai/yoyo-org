# yoyo (canonical language)

> **PROJECT 1 of 4** in the [yoyo-org](https://example.com/yoyo-org) monorepo.
> Holds the canonical, locked-at-compile-time YOYO language source.
> See [v3 Part 1](./docs/PROMPT-v3.md#part-1-4-project-architecture) for full 4-project architecture.

## What this directory is

This is the **canonical YOYO language project**. It contains ONLY:

- `projects/yoyo.ty` — the canonical YOYO compiler source (locked via Decision #13, sha256-pinned)
- `isa/` — the 38-instruction ISA table (single source of truth for opcode semantics)
- `format/` — `.ty` and `.tyo` file format specifications
- `api/` — libyoyo API surface specification (functions, signatures, conventions)

The **content** of this project is consumed by the three implementation projects:
- [yoyo-js](../yoyo-js/) — JS compiler (162-line seed)
- [yoyo-rust](../yoyo-rust/) — Rust verifier + libyoyo stdlib
- [yoyo-asm](../yoyo-asm/) — x64 ground truth

## Lifecycle

| Stage | Status |
|-------|--------|
| Content authoring | Draft `projects/yoyo.ty` |
| Freeze | `yoyo.ty` sha256-pinned, DDC verification locked (3-chain byte-equal) |
| Post-freeze | **Immutable** — any change requires the 8-step lock protocol (v3 Part 9.4) |

## Versioning

The canonical `yoyo.ty` is versioned by sha256 hash, recorded in `tests/yoyo.ty.lock` (project root, generated after Phase 2 freeze).

```bash
# Pin a new version (only during emit-logic upgrades)
node ../yoyo-js/src/yoyo-gen-active.mjs > projects/yoyo.ty  # generate
sha256sum projects/yoyo.ty                                        # compute hash
echo "<hash>  projects/yoyo.ty" > tests/yoyo.ty.lock            # commit
```
