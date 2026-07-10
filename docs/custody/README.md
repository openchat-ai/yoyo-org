# docs/custody/ — Your Personal Trust Record

> This folder contains **the 6 files that only you can create**. They form the public trust record of YOYO. After you fill these in, sign with GPG, and push to GitHub, YOYO is officially "trustworthy by your signature".

## Your Identity

- **Name**: [你的名字]
- **Email**: [你的邮箱]
- **GPG key ID**: [待你生成 GPG 后填入密钥 ID]

## The 6 Files

| # | File | Purpose | Time to create |
|---|------|---------|-----------------|
| 1 | `01-audit-yoyo-js.md` | Your audit of the 162-line seed compiler | 30 min |
| 2 | `02-audit-isa.md` | Your audit of the 38-instruction ISA table | 30 min |
| 3 | `03-GOLDEN_HASH.txt` | SHA-256 of yoyo.js, your pinned trust root | 1 min |
| 4 | `04-SELF_HOST_VERIFIED.md` | Sign-off on M0≡M1≡M2≡M3 chain | 5 min |
| 5 | `05-DDC_VERIFIED.md` | Sign-off on DDC verification (JS ≡ Rust) | 5 min |
| 6 | `06-FROZEN.md` | Sign-off on freezing the compiler | 5 min |

**Total time**: ~1.5 hours of focused work.

## Chinese Versions (Private)

For your own reference, Chinese versions are kept in the same folder with `.zh.md` or `.zh.txt` suffix:

- `README.zh.md` — Chinese version of this README
- `01-audit-yoyo-js.zh.md` — Chinese audit template
- `02-audit-isa.zh.md` — Chinese ISA audit template
- `03-GOLDEN_HASH.zh.txt` — Chinese golden hash template
- `04-SELF_HOST_VERIFIED.zh.md` — Chinese self-host template
- `05-DDC_VERIFIED.zh.md` — Chinese DDC template
- `06-FROZEN.zh.md` — Chinese freeze template

**The Chinese versions are `.gitignore`d** — they will NOT be pushed to GitHub. They are for your private reference only.

## Workflow

```
1. Fill in each file (replace [待你生成 GPG 后填入密钥 ID] etc. with your real data)
2. Sign each .md/.txt with `gpg --sign --detach-sign <file>`
3. Commit with GPG: `git add docs/custody/ && git commit -S -m "Sign off on YOYO trust chain"`
4. Push: `git push origin main`
5. Verify on GitHub that signatures show as "Verified"
```

## Why a Special Folder?

This folder is **yours alone**. No one else (developer, AI, contractor) should write to it. If you see commits in this folder from anyone but you, **investigate**.

The folder structure signals: "this is the human's trust record, not generated code".

## How to Verify (For Others)

Anyone can verify your trust claim by:

```bash
# Clone the repo
$ git clone https://github.com/你的用户名/yoyo
$ cd yoyo

# Check your GPG key
$ gpg --list-keys 你的GPG密钥ID

# Verify each signature
$ gpg --verify docs/custody/03-GOLDEN_HASH.txt.sig docs/custody/03-GOLDEN_HASH.txt
$ gpg --verify docs/custody/04-SELF_HOST_VERIFIED.md.sig docs/custody/04-SELF_HOST_VERIFIED.md
$ gpg --verify docs/custody/05-DDC_VERIFIED.md.sig docs/custody/05-DDC_VERIFIED.md
$ gpg --verify docs/custody/06-FROZEN.md.sig docs/custody/06-FROZEN.md

# All should say: "Good signature from [你的名字] <[你的邮箱]>"
```

## If You Lose Your GPG Key

You cannot re-sign. You must:

1. Generate a new GPG key
2. Create new sign-off files with the new key
3. Announce the key transition
4. Old signatures still verify (against the old public key), but you no longer control that key

**Keep your GPG key safe.** Consider an offline backup.

## What's in Each File

Each file is a **template with placeholders**. Replace them with your real data:

- `[待你生成 GPG 后填入密钥 ID]` — your GPG key ID (after you generate it)
- `[M0_HASH]`, `[M1_HASH]`, etc. — actual SHA-256 hashes (compute when signing)
- `[your notes]`, `[your reasoning]` — fill in during audit
- `[OR: list critical issues]` — replace with actual findings

## Order of Operations

The files have dependencies:

```
01-audit-yoyo-js.md   ← can do anytime
02-audit-isa.md       ← can do anytime
03-GOLDEN_HASH.txt    ← depends on 01 (audit must pass)
04-SELF_HOST_VERIFIED ← depends on 02 (audit must pass) + verification
05-DDC_VERIFIED       ← depends on 02 + DDC verification
06-FROZEN             ← depends on 03, 04, 05 (all must be signed)
```

**Don't freeze until everything is signed and verified.**

## The Empty Files Mean "Not Yet Trusted"

If `docs/custody/` has placeholder text, YOYO is **not yet trustworthy**. Trust comes from the moment you sign `06-FROZEN.md`.

The architecture makes YOYO auditable. The signatures make YOYO trustworthy. **The signatures are yours to give.**

## Summary

| Step | Action | Time |
|------|--------|------|
| 1 | Fill in 01-audit-yoyo-js.md | 30 min |
| 2 | Fill in 02-audit-isa.md | 30 min |
| 3 | Run self-hosting verify, fill in 03 + 04 | 10 min |
| 4 | Run DDC verify, fill in 05 | 5 min |
| 5 | Sign all 6 files with GPG | 5 min |
| 6 | Fill in 06-FROZEN.md, sign | 5 min |
| 7 | Commit + push to GitHub | 5 min |
| **Total** | — | **~1.5 hours** |

**After step 7, YOYO is trustworthy. Your signature makes it so.**
