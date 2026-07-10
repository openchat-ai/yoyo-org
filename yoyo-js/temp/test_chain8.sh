#!/bin/bash
rm -f output gen2v8.elf gen3v8.elf
cp projects/yoyo.ty input.ky
echo '=== M1 ==='
timeout 15 ./build/gen1v8.elf
echo 'exit='$?
if [ -f output ]; then
  mv output gen2v8.elf; chmod +x gen2v8.elf
  echo 'gen2:' $(wc -c < gen2v8.elf)
fi
echo '=== M2 ==='
if [ -f gen2v8.elf ]; then
  timeout 15 ./gen2v8.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen3v8.elf; chmod +x gen3v8.elf
    echo 'gen3:' $(wc -c < gen3v8.elf)
  else
    echo 'NO output'
  fi
fi
echo '=== M3 ==='
if [ -f gen3v8.elf ]; then
  timeout 15 ./gen3v8.elf
  echo 'exit='$?
  if [ -f output ]; then
    mv output gen4v8.elf; chmod +x gen4v8.elf
    echo 'gen4:' $(wc -c < gen4v8.elf)
  fi
fi
echo '=== HASHES ==='
md5sum gen2v8.elf gen3v8.elf gen4v8.elf 2>/dev/null