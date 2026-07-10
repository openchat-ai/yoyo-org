#!/usr/bin/env python3
import sys
f1 = open('build/gen1.elf', 'rb').read()
f2 = open('gen2.elf', 'rb').read()

# Compare template blobs at data section file offset 0x9000 + 0x4000 = 0xD000
tpl_off = 0xD000
tpl_sz = 0xD000
t1 = f1[tpl_off:tpl_off+tpl_sz]
t2 = f2[tpl_off:tpl_off+tpl_sz]
print('Template size:', len(t1))
print('gen2 size:', len(f2))
if t1 == t2:
    print('Template blobs: IDENTICAL')
else:
    diffs = sum(1 for i in range(tpl_sz) if t1[i] != t2[i])
    print('Template blobs: DIFFERENT in', diffs, 'bytes')
    for i in range(tpl_sz):
        if t1[i] != t2[i]:
            print('  First diff at', hex(i), 'gen1=', hex(t1[i]), 'gen2=', hex(t2[i]))
            break

# Also compare the ENTIRE binaries
print()
if len(f1) == len(f2):
    print('Both are', len(f1), 'bytes')
    total_diffs = sum(1 for i in range(len(f1)) if f1[i] != f2[i])
    print('Total differences:', total_diffs)
else:
    print('Sizes differ: gen1=', len(f1), 'gen2=', len(f2))