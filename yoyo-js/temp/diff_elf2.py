#!/usr/bin/env python3
import sys

f1 = open('build/gen1.elf', 'rb').read()
f2 = open('gen2.elf', 'rb').read()

# Compare code section (0x1000-0x9000)
code_start = 0x1000
code_end = 0x9000

# Find first and last diff in code section
diffs_code = [i for i in range(code_start, min(len(f1), len(f2), code_end)) if f1[i] != f2[i]]
print('Code section diffs:', len(diffs_code))
if diffs_code:
    print('  first:', hex(diffs_code[0]), 'last:', hex(diffs_code[-1]))

# Group contiguous diffs
regions = []
if diffs_code:
    start = diffs_code[0]
    prev = diffs_code[0]
    for d in diffs_code[1:]:
        if d - prev > 16:
            regions.append((start, prev))
            start = d
        prev = d
    regions.append((start, prev))
    print('Diff regions:', len(regions))
    for r in regions[:15]:
        sz = r[1] - r[0] + 1
        print('  %s-%s (%d bytes):' % (hex(r[0]), hex(r[1]), sz))
        d1 = f1[r[0]:r[1]+1].hex()
        d2 = f2[r[0]:r[1]+1].hex()
        print('    gen1:', d1[:80])
        print('    gen2:', d2[:80])

# Check for 0F 8C/0F 8F (jl/jg x64 encoding) - sentinel
print()
print('0F 8C (jl) occurrences:')
for i in range(code_start, min(len(f1), code_end-1)):
    if f1[i] == 0x0F and f1[i+1] == 0x8C:
        print('  gen1 at', hex(i))
    if f2[i] == 0x0F and f2[i+1] == 0x8C:
        print('  gen2 at', hex(i))
print('0F 8F (jg) occurrences:')
for i in range(code_start, min(len(f2), code_end-1)):
    if f2[i] == 0x0F and f2[i+1] == 0x8F:
        print('  gen2 at', hex(i))

# Check handler table area in data section
data_start = 0x9000
print()
print('Data section diff count:', sum(1 for i in range(data_start, min(len(f1), len(f2))) if f1[i] != f2[i]))
print('Data section first diff:', hex(next((i for i in range(data_start, min(len(f1), len(f2))) if f1[i] != f2[i]), 0)))