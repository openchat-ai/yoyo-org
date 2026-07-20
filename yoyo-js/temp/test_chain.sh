#!/bin/bash
rm -f output gen2v6.elf gen3v6.elf gen4v6.elf
cp projects/yoyo.ty input.ky
echo '=== M1 ==='
timeout 15 ./build/gen1v6.elf
echo 'exit='$?
if [ -f output ]; then
  mv output gen2v6.elf
  chmod +x gen2v6.elf
  echo 'gen2:' $(wc -c < gen2v6.elf)
else
  echo 'NO output'
fi
echo '=== M2 ==='
if [ -f gen2v6.elf ]; then
  timeout 15 ./gen2v6.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen3v6.elf
    chmod +x gen3v6.elf
    echo 'gen3:' $(wc -c < gen3v6.elf)
  else
    echo 'NO output'
  fi
fi
echo '=== M3 ==='
if [ -f gen3v6.elf ]; then
  timeout 15 ./gen3v6.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen4v6.elf
    chmod +x gen4v6.elf
    echo 'gen4:' $(wc -c < gen4v6.elf)
  else
    echo 'NO output'
  fi
fi
echo '=== HASHES ==='
md5sum gen2v6.elf gen3v6.elf gen4v6.elf 2>/dev/null || echo '(some missing)'