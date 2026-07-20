lines = [
    b'00 00 40 00',
    b'00 00 30 0E 00',
    b'00 00 30 10 00',
    b'00 00 30 11 00',
    b'00 00 FF',
]
content = b'\n'.join(lines) + b'\n'
with open(r'F:\yoyo-org\yoyo-asm\test.ky', 'wb') as f:
    f.write(content)
print(f'wrote {len(content)} bytes')
d = open(r'F:\yoyo-org\yoyo-asm\test.ky', 'rb').read()
print(f'file size: {len(d)}')
print(f'first 20 bytes: {d[:20].hex()}')
