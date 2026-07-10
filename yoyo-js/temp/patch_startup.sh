#!/bin/bash
# Hardcode the startup JMP displacement in gen2v6.elf
# The startup JMP is at offset 0x101C (e9 + 4 bytes displacement)
# We want it to jump to code_offset 0x85 = 133
# JMP target = end_of_JMP + displacement
# end_of_JMP = 0x1021
# target = 0x1085 (write_base + 0x85)
# displacement = 0x1085 - 0x1021 = 0x64 = 100
python3 -c "
import sys
f = open('gen2v6.elf', 'rb').read()
# Check current displacement at offset 0x101D
disp = int.from_bytes(f[0x101D:0x1021], 'little')
print('Current displacement:', disp)
# Write new displacement 0x64
new = bytearray(f)
new[0x101D:0x1021] = (0x64).to_bytes(4, 'little')
with open('gen2v6-patched.elf', 'wb') as out:
    out.write(new)
print('Patched to 0x64')
"