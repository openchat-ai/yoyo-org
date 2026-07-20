import os
content = b'00 00 40 00\n00 00 30 0E 00\n00 00 30 10 00\n00 00 30 11 00\n00 00 FF\n'
with open(r'F:\yoyo-org\yoyo-asm\test.ky', 'wb') as f:
    f.write(content)
print(f'wrote {len(content)} bytes')
d = open(r'F:\yoyo-org\yoyo-asm\test.ky', 'rb').read()
print(f'file size: {len(d)}')
print(f'first 15 bytes: {d[:15].hex()}')
print(f'byte 6: 0x{d[6]:02x} (expected 0x45 for E)')
