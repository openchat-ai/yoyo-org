#!/bin/bash
rm -f output gen2v7.elf gen3v7.elf
cp projects/yoyo.ty input.ky
echo '=== M1 ==='
timeout 15 ./build/gen1v7.elf
echo 'exit='$?
if [ -f output ]; then
  mv output gen2v7.elf
  chmod +x gen2v7.elf
  echo 'gen2:' $(wc -c < gen2v7.elf)
else
  echo 'NO output'
fi
echo '=== M2 ==='
if [ -f gen2v7.elf ]; then
  timeout 15 ./gen2v7.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen3v7.elf
    chmod +x gen3v7.elf
    echo 'gen3:' $(wc -c < gen3v7.elf)
  else
    echo 'NO output'
  fi
fi
echo '=== M3 ==='
if [ -f gen3v7.elf ]; then
  timeout 15 ./gen3v7.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen4v7.elf
    chmod +x gen4v7.elf
    echo 'gen4:' $(wc -c < gen4v7.elf)
  else
    echo 'NO output'
  fi
fi
echo '=== HASHES ==='
md5sum gen2v7.elf gen3v7.elf gen4v7.elf 2>/dev/null || echo '(some missing)'