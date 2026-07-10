#!/usr/bin/env python3
import sys
f1 = open('build/gen1.elf', 'rb').read()
f2 = open('gen2.elf', 'rb').read()
print('sizes:', len(f1), len(f2))

diffs = []
for i in range(min(len(f1), len(f2))):
    if f1[i] != f2[i]:
        diffs.append(i)
print('total differing bytes:', len(diffs))
if diffs:
    print('first diff at:', hex(diffs[0]))
    print('last diff at:', hex(diffs[-1]))
    regions = []
    start = diffs[0]
    prev = diffs[0]
    for d in diffs[1:]:
        if d - prev > 16:
            regions.append((start, prev))
            start = d
        prev = d
    regions.append((start, prev))
    print('diff regions:', len(regions))
    for r in regions[:20]:
        sz = r[1] - r[0] + 1
        print('  %s-%s (%d bytes)' % (hex(r[0]), hex(r[1]), sz))