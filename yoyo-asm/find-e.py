import re
d = open(r'F:\yoyo-org\yoyo-asm\test.ky','rb').read()
print(f'size: {len(d)}')
positions_e = [m.start() for m in re.finditer(b'\x45', d)]
print(f'0x45 (E) positions: {positions_e[:5]}')
# Check 0x0E (uppercase E)
positions_0E = [m.start() for m in re.finditer(b'\x0e', d)]
print(f'0x0E positions: {positions_0E[:5]}')
