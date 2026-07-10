#!/usr/bin/env python3
import struct
f1 = open('build/gen1.elf', 'rb').read()
f2 = open('gen2.elf', 'rb').read()

# Data section starts at 0x9000
d1 = f1[0x9000:]
d2 = f2[0x9000:]

# Find first 10 differences
diffs = [(i, d1[i], d2[i]) for i in range(min(len(d1), len(d2))) if d1[i] != d2[i]]
print('Data section diffs:', len(diffs))
print('First 10 diffs:')
for i, (pos, v1, v2) in enumerate(diffs[:10]):
    print(f'  +{pos:04x} (0x{0x9000+pos:04x}): gen1=0x{v1:02x} gen2=0x{v2:02x}')

# The handler table is at the beginning of the data section
# It should be 256 entries of u32 offsets
print('\nHandler table (first 32 entries):')
print('idx    gen1.elf   gen2.elf')
for i in range(32):
    off1 = struct.unpack_from('<I', d1, i*4)[0]
    off2 = struct.unpack_from('<I', d2, i*4)[0]
    marker = ' ***' if off1 != off2 else ''
    print(f'  {i:2d}    0x{off1:06x}  0x{off2:06x}{marker}')

# Also check the blob area at known offsets
print('\nBlob area (0x4000-0x5000):')
blob_diffs = [(i, d1[i], d2[i]) for i in range(0x4000, min(len(d1), len(d2), 0x5000)) if d1[i] != d2[i]]
print(f'  {len(blob_diffs)} differing bytes')