#!/bin/bash
set -e
echo '=== 0. prepare ==='
cp projects/yoyo.ty input.ky
echo "input.ky: $(wc -c < input.ky) bytes"
echo ''
echo '=== 1. M1 (gen1.elf) -> M2 (output.exe) ==='
timeout 30 ./build/gen1.elf
echo "exit: $?"
ls -la output.exe 2>/dev/null || echo 'NO OUTPUT'
echo ''
echo '=== 2. M2 (gen2) -> M3 ==='
if [ -f output.exe ]; then
  mv output.exe gen2.elf
  chmod +x gen2.elf
  echo "gen2.elf: $(wc -c < gen2.elf) bytes"
  timeout 30 ./gen2.elf
  echo "exit: $?"
  ls -la output.exe 2>/dev/null || echo 'NO OUTPUT'
fi
echo ''
echo '=== 3. M3 (gen3) -> M4 ==='
if [ -f output.exe ]; then
  mv output.exe gen3.elf
  chmod +x gen3.elf
  echo "gen3.elf: $(wc -c < gen3.elf) bytes"
  timeout 30 ./gen3.elf
  echo "exit: $?"
  ls -la output.exe 2>/dev/null || echo 'NO OUTPUT'
fi
echo ''
echo '=== FINAL FILES ==='
ls -la gen*.elf 2>/dev/null || echo 'no gen*'
ls -la output.exe 2>/dev/null || echo 'no output'