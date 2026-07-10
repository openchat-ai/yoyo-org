#!/usr/bin/env python3
import struct
f1 = open('build/gen1.elf', 'rb').read()
f2 = open('gen2.elf', 'rb').read()

# Check template blob: first handler table in data section
# Data section starts at file offset 0x9000
# The handler table is an array of 256 u32 LE offsets at the beginning of data
# But gen2 might not have it populated

# Compare string table at data offset 0
def peek_str(data, off):
    s = ''
    while off < len(data):
        b = data[off]
        if b == 0: break
        if 32 <= b < 127: s += chr(b)
        else: s += f'\\x{b:02x}'
        off += 1
    return s

print('=== gen1.elf strings ===')
s1 = f1[0x9000:0x9100]
print('First 256 bytes:', s1[:64].hex())
print('String count:', struct.unpack_from('<I', s1, 0)[0])
for i in range(4):
    off = 4
    for j in range(i):
        if off+4 > len(s1): break
        slen = struct.unpack_from('<I', s1, off)[0]
        off += 4
        if slen > 0:
            s = peek_str(s1, off)
            print(f'  str[{j}] = "{s}" ({slen} bytes)')
            off += slen + 1

print()
print('=== gen2.elf strings ===')
s2 = f2[0x9000:0x9100]
print('First 256 bytes:', s2[:64].hex())
print('String count:', struct.unpack_from('<I', s2, 0)[0])
for i in range(4):
    off = 4
    for j in range(i):
        if off+4 > len(s2): break
        slen = struct.unpack_from('<I', s2, off)[0]
        off += 4
        if slen > 0:
            s = peek_str(s2, off)
            print(f'  str[{j}] = "{s}" ({slen} bytes)')
            off += slen + 1

# Check if template blob exists at data offset 0x4000
print()
print('Template blob at 0xD000 (file offset 0x9000+0x4000):')
t1 = f1[0x9000+0x4000:0x9000+0x4000+64]
t2 = f2[0x9000+0x4000:0x9000+0x4000+64]
print('  gen1:', t1[:32].hex())
print('  gen2:', t2[:32].hex())
if t1[:4] == b'\x7fELF':
    print('  gen1: ELF magic OK')
if t2[:4] == b'\x7fELF':
    print('  gen2: ELF magic OK')
if t1[:4] != t2[:4]:
    print('  *** DIFFERENT! ***')

# Compare sizeOfCode / entry point
if t1[:4] == b'\x7fELF' and t2[:4] == b'\x7fELF':
    entry1 = struct.unpack_from('<I', t1, 0x18)[0]
    entry2 = struct.unpack_from('<I', t2, 0x18)[0]
    phoff1 = struct.unpack_from('<I', t1, 0x20)[0]
    phoff2 = struct.unpack_from('<I', t2, 0x20)[0]
    print(f'  entry: gen1=0x{entry1:x} gen2=0x{entry2:x}')
    print(f'  phoff: gen1=0x{phoff1:x} gen2=0x{phoff2:x}')