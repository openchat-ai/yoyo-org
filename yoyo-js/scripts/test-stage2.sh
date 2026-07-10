#!/usr/bin/env bash
# Run yoyo.exe (Windows PE) on Linux via Wine.
# yoyo.exe ignores CLI args; it always reads ./input.ky and writes ./output.exe.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EXE="${1:-$ROOT_DIR/build/yoyo.exe}"
INPUT_TY="${2:-$ROOT_DIR/projects/yoyo.ty}"
TIMEOUT_SEC="${3:-30}"
WORKDIR="${4:-}"

if [[ ! -f "$EXE" ]]; then
  echo "[!] 编译器不存在: $EXE"
  echo "    先运行: node src/yoyo.js projects/yoyo.ty build/yoyo.exe (yoyo.ty 现在 hand-authored)"
  exit 1
fi

if [[ ! -f "$INPUT_TY" ]]; then
  echo "[!] 源文件不存在: $INPUT_TY"
  exit 1
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d /tmp/yoyo-stage2-XXXXXX)"
  CLEANUP_WORKDIR=1
else
  mkdir -p "$WORKDIR"
  CLEANUP_WORKDIR=0
fi

cleanup() {
  if [[ $CLEANUP_WORKDIR -eq 1 ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

if command -v wine64 >/dev/null 2>&1; then
  WINE=wine64
elif command -v wine >/dev/null 2>&1; then
  WINE=wine
else
  echo "[!] 未找到 wine/wine64。Linux 上运行 yoyo.exe 需要 Wine："
  echo "    sudo apt install wine64    # Debian/Ubuntu"
  echo "    sudo dnf install wine      # Fedora"
  exit 1
fi

cp "$INPUT_TY" "$WORKDIR/input.ky"
cp "$EXE" "$WORKDIR/compiler.exe"

echo "[*] 工作目录: $WORKDIR"
echo "[*] 输入: $INPUT_TY -> input.ky ($(wc -c < "$WORKDIR/input.ky") bytes)"
echo "[*] 编译器: $EXE"
echo "[*] 运行: $WINE compiler.exe (超时 ${TIMEOUT_SEC}s)"

set +e
if command -v timeout >/dev/null 2>&1; then
  (
    cd "$WORKDIR"
    timeout --foreground "${TIMEOUT_SEC}s" "$WINE" ./compiler.exe
  )
  EXIT_CODE=$?
else
  (
    cd "$WORKDIR"
    "$WINE" ./compiler.exe
  )
  EXIT_CODE=$?
fi
set -e

if [[ $EXIT_CODE -eq 124 ]]; then
  echo "[!] 超时 (${TIMEOUT_SEC}s)。若 input.ky 不存在，yoyo.exe 会空转挂死。"
  exit 1
fi

if [[ ! -f "$WORKDIR/output.exe" ]]; then
  echo "[!] 未生成 output.exe (wine exit=$EXIT_CODE)"
  exit 1
fi

OUT_SIZE="$(wc -c < "$WORKDIR/output.exe")"
echo "[✓] output.exe: $OUT_SIZE bytes (wine exit=$EXIT_CODE)"
echo "$WORKDIR/output.exe"
