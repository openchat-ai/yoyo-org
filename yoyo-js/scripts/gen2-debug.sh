#!/usr/bin/env bash
set -euo pipefail
cd /mnt/f/yoyo-ide
cp projects/yoyo.ty input.ky
./gen2.elf &
PID=$!
sleep 2
echo "=== syscall ==="
cat /proc/$PID/syscall 2>/dev/null || echo "N/A"
echo "=== wchan ==="
cat /proc/$PID/wchan 2>/dev/null || echo "N/A"
echo "=== regs ==="
gdb -batch -ex "attach $PID" -ex "info registers rip rsp r15 rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14" -ex "x/20i \$rip-10" -ex "detach" 2>&1
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "done"
