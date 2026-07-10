# yoyo-org — PRE-AUDIT WORK IN PROGRESS

> **⚠️ NOTHING IN THIS REPOSITORY IS OFFICIAL OR "FROZEN" ⚠️**

## Current State

This repository is in **pre-audit, pre-signature work-in-progress** state.
The `main` branch is intentionally empty of code or claims.

## Why?

The PROMPT-v3 trust model relies on:
- `docs/custody/03-GOLDEN_HASH.txt` — cryptographic trust root
- `docs/custody/06-FROZEN.md` — freeze declaration
- `docs/custody/01-05-audit*.md` — signed audit attestations

None of these have been signed. Earlier pushes contained **placeholder
templates** (with `[Author]`, `[YYYY-MM-DD]`, `[HASH_OF_YOYO_JS]` etc.)
that looked like completed attestations but were never filled in or signed.

This is misleading. Anyone reading those files would think YOYO is audited
and frozen when it is not. So the `main` branch has been reset to this
notice.

## Where is the actual code?

The code lives on the **`wip/mark-custody-as-template`** branch, in
working-but-unsigned state. PR #1 documents the transition plan.

```
main                       = empty (this notice)
wip/mark-custody-as-template = code + TEMPLATE-marked custody docs
```

## DO NOT MERGE PR #1 UNTIL

1. ✅ User has personally audited `yoyo-js/src/yoyo.js` (162 lines)
2. ✅ GPG keypair generated
3. ✅ Real SHA-256 hashes computed for all trust anchors
4. ✅ All custody docs filled with real values
5. ✅ All docs GPG-signed (`gpg --detach-sign --armor`)
6. ✅ `yoyo.ty` locked with sha256 in `03-GOLDEN_HASH.txt`
7. ✅ `06-FROZEN.md` signed with explicit freeze declaration

## Until then

`main` stays empty. Anyone cloning this repo gets only this notice.
The Trusting Trust promise is: when code finally lands on `main`,
**every claim is cryptographically anchored** by a real signature.

---

## How to follow progress

```bash
git clone https://github.com/openchat-ai/yoyo-org.git
cd yoyo-org
git checkout wip/mark-custody-as-template
# Read the code, read PR #1
# Decide whether to participate in the audit process
```

PR #1: https://github.com/openchat-ai/yoyo-org/pull/1