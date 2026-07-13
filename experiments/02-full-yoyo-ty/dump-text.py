import sys, re
d = open(sys.argv[1], 'rb').read()
# Dump bytes from 0x200 (start of .text) to end
print('bytes from 0x200 to 0x420 (first 32 inst):')
for i in range(0x200, min(len(d), 0x420), 16):
    chunk = d[i:i+16]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    print(f'  {i:04x}: {hex_str}')
