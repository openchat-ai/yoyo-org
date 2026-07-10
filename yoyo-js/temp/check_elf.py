#!/usr/bin/env python3
import struct
f = open('gen2v2.elf', 'rb').read()
entry = struct.unpack_from('<I', f, 0x18)[0]
print('Entry point VA: 0x%x' % entry)
print('File size: %d bytes' % len(f))
# Entry VA 0x401000 maps to file offset 0x1000 (from program header: p_offset=0x1000)
file_off = 0x1000
print('Code at entry (32 bytes) file offset 0x%x:' % file_off)
code = f[file_off:file_off+64]
print(code.hex())
# Check for startup code pattern: 4c 8d 3d ...
if len(code) >= 4 and code[0] == 0x4c and code[1] == 0x8d and code[2] == 0x3d:
    print('Startup: LEA RDI found (correct)')
else:
    print('Startup: MISSING or CORRUPTED')