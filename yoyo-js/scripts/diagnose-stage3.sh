#!/usr/bin/env bash
# Stage 3 diagnostic wrapper — runs bootstrap then writes report.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d /tmp/yoyo-stage3-diag-XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

GEN2="$TMP_DIR/gen2.elf"
GEN3="$TMP_DIR/gen3.elf"
GEN1="$ROOT_DIR/build/yoyo"

echo "=== diagnose-stage3 ==="

# Build gen1
# yoyo-gen.js deleted; yoyo.ty now hand-authored
node src/yoyo.js --target=linux projects/yoyo.ty build/yoyo

# Run stage 3 bootstrap (capture artifacts even on FAIL)
set +e
bash scripts/bootstrap-native.sh 3
BS_CODE=$?
set -e

# Bootstrap writes to temp; copy from last run if available
if [[ -f "$ROOT_DIR/output" ]]; then
  cp "$ROOT_DIR/output" "$GEN2" 2>/dev/null || true
fi

# Re-run gen2->gen3 manually to capture both artifacts
if [[ -x "$GEN1" ]]; then
  rm -f "$ROOT_DIR/input.ky" "$ROOT_DIR/output"
  cp projects/yoyo.ty "$ROOT_DIR/input.ky"
  "$GEN1" && cp "$ROOT_DIR/output" "$GEN2" 2>/dev/null || true
  if [[ -f "$GEN2" ]]; then
    chmod +x "$GEN2"
    rm -f "$ROOT_DIR/input.ky" "$ROOT_DIR/output"
    cp projects/yoyo.ty "$ROOT_DIR/input.ky"
    "$GEN2" && cp "$ROOT_DIR/output" "$GEN3" 2>/dev/null || true
  fi
fi

ARGS=(--gen1 "$GEN1")
[[ -f "$GEN2" ]] && ARGS+=(--gen2 "$GEN2")
[[ -f "$GEN3" ]] && ARGS+=(--gen3 "$GEN3")

node scripts/diagnose-stage3.js "${ARGS[@]}"

exit "$BS_CODE"
