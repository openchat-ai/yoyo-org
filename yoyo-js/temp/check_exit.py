#!/usr/bin/env python3
import struct
f = open('gen2v3.elf', 'rb').read()
# Check what's at file offset 0x1000 (entry point)
startup = f[0x1000:0x1020]
print('Code at 0x1000 (startup):', startup[:16].hex())
is_exit = startup[:3] == b'\x48\x31\xff'
print('Is exit syscall:', is_exit)
# Check end of code section
code_end_slice = f[0x8FF0:0x9000]
print('Code at 0x8FF0:', code_end_slice[:16].hex())
print('File size:', len(f))
# Search for exit syscall pattern
pat = b'\x48\x31\xff\xc7\xc0\x3c'
pos = f.find(pat)
print('Exit syscall found at:', hex(pos) if pos >= 0 else 'NOT FOUND')
# Check at 0x9000 (data section start)
ds = f[0x9000:0x9020]
print('Data section start:', ds[:32].hex())