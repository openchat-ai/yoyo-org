#!/usr/bin/env bash
set -euo pipefail
cd /mnt/f/yoyo-ide
./gen2.elf &
PID=$!
sleep 2
echo "PID=$PID"
cat /proc/$PID/wchan 2>/dev/null || echo "wchan=N/A"
cat /proc/$PID/stat 2>/dev/null | awk '{print "state="$3}'
# Use gdb to get RIP
gdb -batch -ex "attach $PID" -ex "bt 3" -ex "info registers rip rsp" -ex "x/10i \$rip" -ex "detach" 2>&1 || true
kill $PID 2>/dev/null
wait $PID 2>/dev/null
echo "done"
