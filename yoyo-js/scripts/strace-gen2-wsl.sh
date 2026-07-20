#!/usr/bin/env bash
set -euo pipefail
cd /mnt/f/yoyo-ide
cp projects/yoyo.ty input.ky
echo "[1] starting gen2.elf with strace"
strace -f -o /tmp/gen2x.strace ./gen2.elf &
PID=$!
echo "[2] PID=$PID"
sleep 3
echo "[3] strace lines=$(wc -l </tmp/gen2x.strace 2>/dev/null || echo 'N/A')"
echo "[4] last lines:"
tail -10 /tmp/gen2x.strace 2>/dev/null || echo '(no strace file yet)'
echo "[5] /proc/PID/stat:"
cat /proc/$PID/stat 2>/dev/null || echo '(not found)'
echo "[6] killing"
kill $PID 2>/dev/null; sleep 1; kill -9 $PID 2>/dev/null
echo "[7] done"
