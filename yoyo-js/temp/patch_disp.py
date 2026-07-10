#!/usr/bin/env python3
import sys
f = bytearray(open('gen2v6.elf', 'rb').read())
# JMP at offset 0x101C, displacement at 0x101D-0x1020
# Target = end_of_JMP + disp = 0x1021 + disp
# We want target = 0x1085 (H_00 entry)
# disp = 0x1085 - 0x1021 = 0x64
new_val = 0x64
f[0x101D:0x1021] = new_val.to_bytes(4, 'little')
with open('gen2v6h64.elf', 'wb') as out:
    out.write(f)
print('Patched: disp=0x64')