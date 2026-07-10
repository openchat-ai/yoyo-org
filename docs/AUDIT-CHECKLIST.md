# YOYO Audit Checklist (Simplified Plan)

> Selected approach: yoyo-asm (ground truth) + yoyo.js (secondary), skip yoyo-rust full audit
> Total work: 5-8 hours

## Why skip yoyo-rust

yoyo-rust's 4581 lines and yoyo-asm's 1260 lines do the same thing (Trusting Trust verification).
By "minimum auditable" principle:
- yoyo-asm = ground truth (hand-written x64, hardest place to hide backdoor)
- yoyo.js = 157 lines (simplest implementation)
- yoyo-rust verified via DDC (consistency, not code review)

## Audit Checklist

### Phase 1a: Audit yoyo.ty (198 lines)
- [ ] Read entire file
- [ ] Compute SHA-256: `Get-FileHash yoyo/projects/yoyo.ty -Algorithm SHA256`
- [ ] Verify no suspicious strings, no network calls, no hidden syscalls
- [ ] Fill into 03-GOLDEN_HASH.txt

### Phase 1b: Audit yoyo-asm (1260 lines) - GROUND TRUTH
- [ ] Read entire file `yoyo-asm/yoyo-asm.asm`
- [ ] Verify ISA table correct (38 opcodes)
- [ ] Verify emit functions have no hidden shellcode
- [ ] Verify IAT/imports only reference necessary kernel32 functions
- [ ] Record key offsets

### Phase 1c: Audit yoyo.js (157 lines)
- [ ] Read entire file `yoyo-js/src/yoyo.js`
- [ ] Verify parse function has no self-modifying logic
- [ ] Verify compile function has no backdoor

### Phase 2: DDC Verification (Automatic)
- [ ] Compile yoyo.ty with yoyo-js, record SHA-256
- [ ] Compile yoyo.ty with yoyo-asm, record SHA-256
- [ ] Compare two outputs (DDC)

### Phase 3: GPG Setup
- [ ] Install Gpg4win: https://gpg4win.org/
- [ ] `gpg --full-generate-key` (RSA 4096, real name and email)
- [ ] Record key ID: `gpg --list-secret-keys --keyid-format=long`
- [ ] Export public key: `gpg --armor --export <key-id> > pubkey.asc`

### Phase 4: Fill Custody Docs
- [ ] Replace [Author] with your real name
- [ ] Replace [YYYY-MM-DD] with real date
- [ ] Replace [GPG key ID] with your key ID
- [ ] Replace [HASH_OF_YOYO_JS] with real SHA-256
- [ ] Replace [HASH_OF_YOYO_TY] with real SHA-256
- [ ] Delete all TEMPLATE banners

### Phase 5: GPG Sign
- [ ] `gpg --armor --detach-sign 03-GOLDEN_HASH.txt`
- [ ] Same for each custody md file
- [ ] Verify: `gpg --verify 03-GOLDEN_HASH.txt.asc 03-GOLDEN_HASH.txt`

### Phase 6: Commit + PR
- [ ] On wip branch commit all signature files
- [ ] `git push origin wip/mark-custody-as-template`
- [ ] Open PR: wip to main
- [ ] **Do not merge PR** until all verification complete

## Verification Commands (Run Anytime)

```powershell
# Verify yoyo.ty hash
$h = (Get-FileHash yoyo\projects\yoyo.ty -Algorithm SHA256).Hash
Write-Output "yoyo.ty: $h"

# Verify yoyo.js hash
$h = (Get-FileHash yoyo-js\src\yoyo.js -Algorithm SHA256).Hash
Write-Output "yoyo.js: $h"

# DDC: yoyo-js compiles yoyo.ty
node yoyo-js\src\yoyo.js yoyo\projects\yoyo.ty output-ty-js.exe --target=win
Get-FileHash output-ty-js.exe -Algorithm SHA256

# DDC: yoyo-asm compiles yoyo.ty (after copying yoyo.ty to input.ky)
cd yoyo-asm
.\yoyo-asm.exe
Get-FileHash output.exe -Algorithm SHA256

# GPG verification
gpg --verify docs\custody\03-GOLDEN_HASH.txt.asc docs\custody\03-GOLDEN_HASH.txt
```

## Definition of Done

- [ ] yoyo.ty SHA-256 written to 03-GOLDEN_HASH.txt
- [ ] All custody docs have real date/name/key ID
- [ ] Each custody doc has .asc signature file
- [ ] `gpg --verify` returns "Good signature" for each file
- [ ] yoyo-js and yoyo-asm outputs DDC-verified
- [ ] PR opened but not merged

Only when ALL above are checked, can PR be merged.