import struct
import sys
d = open(sys.argv[1], 'rb').read()
nl_count = struct.unpack('<I', d[0x16C:0x170])[0]
op_skip = struct.unpack('<I', d[0x174:0x178])[0]
rsi = struct.unpack('<Q', d[0x168:0x170])[0]
first_byte = d[0x180]
print(f'.next_line entry count: {nl_count}')
print(f'.op_skip_line call count: {op_skip}')
print(f'last rsi: 0x{rsi & 0xFFFFFFFFFFFFFFFF:016X}')
if 32 <= first_byte < 127:
    fb_char = chr(first_byte)
else:
    fb_char = '?'
print(f'first byte at rsi: 0x{first_byte:02x} ({fb_char})')
