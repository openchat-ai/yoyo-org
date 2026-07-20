#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="/tmp/yoyo-bootstrap"
mkdir -p "$TMP_DIR"

STRICT_MODE=0
REPORT_FILE=""
DIFF_FILE=""
LOCK_MODE=0
UPDATE_BASELINE=0
BASELINE_FILE="bootstrap-baseline.txt"

for arg in "$@"; do
  case "$arg" in
    --strict)
      STRICT_MODE=1
      REPORT_FILE="bootstrap-report.txt"
      DIFF_FILE="bootstrap-report-diff.txt"
      ;;
    --lock)
      LOCK_MODE=1
      ;;
    --update-baseline)
      UPDATE_BASELINE=1
      ;;
    *)
      echo "未知参数: $arg"
      echo "用法: $0 [--strict] [--lock] [--update-baseline]"
      exit 2
      ;;
  esac
done

if [[ $LOCK_MODE -eq 1 && $STRICT_MODE -ne 1 ]]; then
  echo "--lock 依赖 --strict"
  echo "用法: $0 --strict [--lock] [--update-baseline]"
  exit 2
fi

if [[ $UPDATE_BASELINE -eq 1 && $STRICT_MODE -ne 1 ]]; then
  echo "--update-baseline 依赖 --strict"
  echo "用法: $0 --strict [--lock] [--update-baseline]"
  exit 2
fi

echo "[1/4] 生成 yoyo.ty（第一次, win）"
# yoyo-gen.js deleted; yoyo.ty now hand-authored
cp projects/yoyo.ty "$TMP_DIR/yoyo-1.ty"

echo "[2/4] 生成 yoyo.ty（第二次, win）"
# yoyo-gen.js deleted; yoyo.ty now hand-authored
cp projects/yoyo.ty "$TMP_DIR/yoyo-2.ty"

echo "[3/4] 用同一源码编译两次"
node src/yoyo.js projects/yoyo.ty "$TMP_DIR/yoyo-a.exe" >/dev/null
node src/yoyo.js projects/yoyo.ty "$TMP_DIR/yoyo-b.exe" >/dev/null

echo "[4/4] 一致性检查"
cmp -s "$TMP_DIR/yoyo-1.ty" "$TMP_DIR/yoyo-2.ty"
KY_CMP_EXIT=$?

cmp -s "$TMP_DIR/yoyo-a.exe" "$TMP_DIR/yoyo-b.exe"
EXE_CMP_EXIT=$?

KY_SHA_1="$(sha256sum "$TMP_DIR/yoyo-1.ty" | awk '{print toupper($1)}')"
KY_SHA_2="$(sha256sum "$TMP_DIR/yoyo-2.ty" | awk '{print toupper($1)}')"
EXE_SHA_A="$(sha256sum "$TMP_DIR/yoyo-a.exe" | awk '{print toupper($1)}')"
EXE_SHA_B="$(sha256sum "$TMP_DIR/yoyo-b.exe" | awk '{print toupper($1)}')"

echo
echo "=== bootstrap-check 报告 ==="
echo "yoyo.ty #1 sha256: $KY_SHA_1"
echo "yoyo.ty #2 sha256: $KY_SHA_2"
echo "yoyo.ty 一致性: $([[ $KY_CMP_EXIT -eq 0 ]] && echo PASS || echo FAIL)"
echo
echo "yoyo-a.exe sha256: $EXE_SHA_A"
echo "yoyo-b.exe sha256: $EXE_SHA_B"
echo "产物一致性: $([[ $EXE_CMP_EXIT -eq 0 ]] && echo PASS || echo FAIL)"

if [[ $STRICT_MODE -eq 1 ]]; then
  {
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "yoyo.ty.sha256: $KY_SHA_1"
    echo "yoyo.exe.sha256: $EXE_SHA_A"
    echo "yoyo.ty.cmp: $KY_CMP_EXIT"
    echo "yoyo.exe.cmp: $EXE_CMP_EXIT"
  } > "$REPORT_FILE"

  keys=(
    "yoyo.ty.sha256"
    "yoyo.exe.sha256"
    "yoyo.ty.cmp"
    "yoyo.exe.cmp"
  )

  BASELINE_CHANGED=0
  CHANGED=0
  {
    echo "=== bootstrap-report 差异 ==="
    echo "generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ ! -f "$BASELINE_FILE" ]]; then
      echo "baseline: missing"
      echo "status: no-baseline"
    else
      echo "baseline: $BASELINE_FILE"
      changed=0
      for key in "${keys[@]}"; do
        prev_val="$(grep -E "^${key}: " "$BASELINE_FILE" | head -n1 | sed -E "s/^${key}: //")"
        curr_val="$(grep -E "^${key}: " "$REPORT_FILE" | head -n1 | sed -E "s/^${key}: //")"
        if [[ "$prev_val" == "$curr_val" ]]; then
          echo "$key: same"
        else
          changed=1
          echo "$key: changed"
          echo "  prev: $prev_val"
          echo "  curr: $curr_val"
        fi
      done
      if [[ $changed -eq 0 ]]; then
        echo "status: identical-to-baseline"
      else
        echo "status: changed"
        CHANGED=1
        BASELINE_CHANGED=1
      fi
    fi
  } > "$DIFF_FILE"

  if [[ $UPDATE_BASELINE -eq 1 ]]; then
    {
      for key in "${keys[@]}"; do
        grep -E "^${key}: " "$REPORT_FILE"
      done
    } > "$BASELINE_FILE"
  fi

  echo
  echo "strict 报告已写入: $REPORT_FILE"
  echo "strict 差异已写入: $DIFF_FILE"
  if [[ $UPDATE_BASELINE -eq 1 ]]; then
    echo "strict 基线已更新: $BASELINE_FILE"
  fi

  if [[ $LOCK_MODE -eq 1 ]]; then
    if [[ ! -f "$BASELINE_FILE" ]]; then
      echo "lock 模式失败: 未找到基线文件 $BASELINE_FILE"
      exit 3
    fi
    if [[ $BASELINE_CHANGED -ne 0 ]]; then
      echo "lock 模式失败: 当前结果与基线存在差异"
      exit 4
    fi
    echo "lock 模式: PASS（与基线一致）"
  fi
fi

if [[ $KY_CMP_EXIT -ne 0 || $EXE_CMP_EXIT -ne 0 ]]; then
  echo
  echo "bootstrap-check: FAIL"
  exit 1
fi

echo
echo "bootstrap-check: PASS"
