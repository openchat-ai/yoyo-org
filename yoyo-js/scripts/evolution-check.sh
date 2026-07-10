#!/usr/bin/env bash
# Evolution track CI gate: M1 lowering + M2 byte-match + optional bootstrap.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== evolution-check ==="

echo "[M1] tir-check"
node scripts/tir-check.js projects/yoyo.ty

echo "[M2] compare-backends (x64 vs tir-x64)"
node scripts/compare-backends.js

DIFFS=$(node -e "
const fs=require('fs');
const a=fs.readFileSync('build/compare-a.elf');
const b=fs.readFileSync('build/compare-b.elf');
let d=0;
for(let i=0;i<Math.min(a.length,b.length);i++) if(a[i]!==b[i]) d++;
console.log(d);
")
if [[ "$DIFFS" != "0" ]]; then
  echo "[M2] FAIL: $DIFFS byte diffs"
  exit 1
fi
echo "[M2] PASS: 0 byte diffs"

if [[ "${RUN_BOOTSTRAP:-0}" == "1" ]]; then
  echo "[M3] bootstrap-native.sh 3 (TIR_BOOTSTRAP=${TIR_BOOTSTRAP:-0})"
  bash scripts/bootstrap-native.sh 3 || {
    echo "[M3] FAIL (expected until scan path replaced)"
    exit 1
  }
  echo "[M3] PASS"
fi

echo "evolution-check: PASS"
