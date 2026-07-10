#!/usr/bin/env bash
# Linux 三阶段自举验证：
#   [1] node yoyo-gen.js  -> projects/yoyo.ty
#   [2] node yoyo.js      -> build/yoyo.exe   (gen 1, ~87KB)
#   [3] yoyo.exe          -> gen2.exe         (gen 2, ~51KB, via Wine)
#   [4] gen2.exe          -> gen3.exe         (gen 3, 应与 gen2 字节级一致)
#   [5] gen3.exe          -> gen4.exe         (gen 4, 应与 gen3 字节级一致)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAGES="${1:-4}"
TIMEOUT_SEC="${2:-60}"
TMP_DIR="$(mktemp -d /tmp/yoyo-selfhost-XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

run_pe_compiler() {
  local compiler="$1"
  local input_ty="$2"
  local workdir="$3"
  local label="$4"

  rm -f "$workdir/input.ky" "$workdir/output.exe"
  cp "$input_ty" "$workdir/input.ky"
  cp "$compiler" "$workdir/compiler.exe"

  echo "[*] $label: $WINE compiler.exe"
  set +e
  (
    cd "$workdir"
    timeout --foreground "${TIMEOUT_SEC}s" "$WINE" ./compiler.exe
  )
  local code=$?
  set -e

  if [[ $code -eq 124 ]]; then
    echo "[!] $label 超时"
    exit 1
  fi
  if [[ ! -f "$workdir/output.exe" ]]; then
    echo "[!] $label 未生成 output.exe (exit=$code)"
    exit 1
  fi
}

echo "=== yoyo Linux 自举 ==="
echo "临时目录: $TMP_DIR"
echo

echo "[stage 1/5] 生成 yoyo.ty"
# yoyo-gen.js deleted; yoyo.ty now hand-authored
echo "  yoyo.ty: $(wc -c < projects/yoyo.ty) bytes"

echo "[stage 1/5] Node 主机编译 -> build/yoyo.exe (gen 1)"
node src/yoyo.js projects/yoyo.ty build/yoyo.exe >/dev/null
GEN1_SIZE="$(wc -c < build/yoyo.exe)"
echo "  gen1 (yoyo.exe): $GEN1_SIZE bytes"

if command -v wine64 >/dev/null 2>&1; then
  WINE=wine64
elif command -v wine >/dev/null 2>&1; then
  WINE=wine
else
  echo
  echo "[!] stage 2+ 需要 Wine 运行 Windows PE。安装后重试："
  echo "    sudo apt install wine64"
  echo
  echo "stage 1 已完成。手动继续："
  echo "  cp projects/yoyo.ty input.ky"
  echo "  wine build/yoyo.exe    # 生成 output.exe"
  exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "[!] 需要 coreutils 的 timeout 命令"
  exit 1
fi

WORK="$TMP_DIR/work"
mkdir -p "$WORK"

echo "[stage 2/5] gen1 自举编译 -> gen2"
run_pe_compiler build/yoyo.exe projects/yoyo.ty "$WORK" "gen1"
cp "$WORK/output.exe" "$TMP_DIR/gen2.exe"
GEN2_SIZE="$(wc -c < "$TMP_DIR/gen2.exe")"
echo "  gen2: $GEN2_SIZE bytes"

if [[ "$STAGES" -lt 3 ]]; then
  echo
  echo "bootstrap-selfhost: stage 2 PASS"
  exit 0
fi

echo "[stage 3/5] gen2 自举编译 -> gen3"
run_pe_compiler "$TMP_DIR/gen2.exe" projects/yoyo.ty "$WORK" "gen2"
cp "$WORK/output.exe" "$TMP_DIR/gen3.exe"
GEN3_SIZE="$(wc -c < "$TMP_DIR/gen3.exe")"
echo "  gen3: $GEN3_SIZE bytes"

cmp -s "$TMP_DIR/gen2.exe" "$TMP_DIR/gen3.exe"
echo "  gen2 vs gen3: PASS (byte-identical)"

if [[ "$STAGES" -lt 4 ]]; then
  echo
  echo "bootstrap-selfhost: stage 3 PASS"
  exit 0
fi

echo "[stage 4/5] gen3 自举编译 -> gen4"
run_pe_compiler "$TMP_DIR/gen3.exe" projects/yoyo.ty "$WORK" "gen3"
cp "$WORK/output.exe" "$TMP_DIR/gen4.exe"
GEN4_SIZE="$(wc -c < "$TMP_DIR/gen4.exe")"
echo "  gen4: $GEN4_SIZE bytes"

cmp -s "$TMP_DIR/gen3.exe" "$TMP_DIR/gen4.exe"
echo "  gen3 vs gen4: PASS (byte-identical)"

echo
echo "=== 自举摘要 ==="
echo "gen1 (Node 主机):  $GEN1_SIZE bytes"
echo "gen2 (自托管):     $GEN2_SIZE bytes"
echo "gen3:              $GEN3_SIZE bytes"
echo "gen4:              $GEN4_SIZE bytes"
echo
echo "bootstrap-selfhost: PASS (3-stage convergence verified)"
