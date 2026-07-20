#!/bin/bash
cp projects/yoyo.ty input.ky
echo '=== M1 ==='
timeout 20 ./build/gen1-final.elf; echo "exit="$?
if [ -f output ]; then
  mv output gen2-final.elf; chmod +x gen2-final.elf
  echo "gen2: $(wc -c < gen2-final.elf)"
fi
echo '=== M2 ==='
if [ -f gen2-final.elf ]; then
  timeout 20 ./gen2-final.elf; echo "exit="$?
  if [ -f output ]; then
    mv output gen3-final.elf; chmod +x gen3-final.elf
    echo "gen3: $(wc -c < gen3-final.elf)"
  fi
fi
echo '=== M3 ==='
if [ -f gen3-final.elf ]; then
  timeout 20 ./gen3-final.elf; echo "exit="$?
  if [ -f output ]; then
    mv output gen4-final.elf
    echo "gen4: $(wc -c < gen4-final.elf)"
  fi
fi
echo '=== HASHES ==='
md5sum gen2-final.elf gen3-final.elf gen4-final.elf 2>/dev/null || true