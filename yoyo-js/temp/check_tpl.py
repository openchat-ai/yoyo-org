#!/usr/bin/env python3
import struct
f = open('build/gen1.elf', 'rb').read()
# Find the 84 02 4000 instruction in the text to get template blob size
# Search for: 0x84 (memcpy opcode) followed by 0x02 (dst=state_02) and 0x00 0x40 (src offset = 0x4000)
code = f[0x1000:0x9000]
for i in range(len(code) - 10):
    if code[i] == 0x84:
        # Try to decode: 0x84 ss dd ll (where ll is 2-byte size)
        dst = code[i+1] & 0x7
        src_off = struct.unpack_from('<H', code, i+2)[0]
        sz = struct.unpack_from('<H', code, i+4)[0]
        if dst == 2 and src_off == 0x4000:
            print(f'Found memcpy at code offset 0x{i:x}: 84 {code[i+1]:02x} {src_off:04x} {sz:04x}')
            print(f'  Template blob size = 0x{sz:x} = {sz} bytes')

# Read the template blob from the data section (file offset 0x9000 + 0x4000)
tpl_start = 0x9000 + 0x4000
tpl_size = sz if 'sz' in dir() else 0xD000
print(f'\nReading template blob at file offset 0x{tpl_start:x}, size 0x{tpl_size:x}')
tpl = f[tpl_start:tpl_start+tpl_size]
print(f'  First 16 bytes: {tpl[:16].hex()}')
print(f'  Is ELF: {tpl[:4] == b"\\x7fELF"}')

# Check the gen2.elf output
print('\n=== gen2.elf output ===')
try:
    g2 = open('gen2.elf', 'rb').read()
    print(f'  Size: {len(g2)} bytes')
    print(f'  First 16 bytes: {g2[:16].hex()}')
    print(f'  Is ELF: {g2[:4] == b"\\x7fELF"}')
    
    # Compare with template blob
    if len(g2) >= tpl_size:
        if g2[:tpl_size] == tpl:
            print('  gen2.elf == template blob (first', tpl_size, 'bytes)')
        else:
            diff_count = sum(1 for i in range(min(len(g2), tpl_size)) if g2[i] != tpl[i])
            print(f'  gen2.elf differs from template blob in {diff_count} bytes')
except FileNotFoundError:
    print('  gen2.elf not found')