import sys
d = open(sys.argv[1], 'rb').read()
# Find mov [r15+disp8], rax = 49 89 47 XX or mov [r15+disp32], rax = 49 89 87 XX XX XX XX
import re

# Find all 49 89 47 XX patterns
hits = [(m.start(), m.group(0)[3]) for m in re.finditer(rb'\x49\x89\x47.', d)]
disp8_values = sorted(set(h[1] for h in hits))
slot_values = sorted(set(d // 8 for d in disp8_values))
print(f'49 89 47 (disp8 path): {len(hits)} hits')
print(f'  unique disp8: {[hex(x) for x in disp8_values]}')
print(f'  unique slots (disp8/8): {[hex(s) for s in slot_values]}')

# Find all 49 89 87 XX XX XX XX patterns (disp32)
hits32 = [(m.start(), int.from_bytes(m.group(0)[3:7], 'little')) for m in re.finditer(rb'\x49\x89\x87(.{4})', d)]
print(f'\n49 89 87 (disp32 path): {len(hits32)} hits')
disp32_values = sorted(set(h[1] for h in hits32))
print(f'  unique disp32 (slot*8): {[hex(x) for x in disp32_values[:20]]}')

# Check first SET (slot 0x0E, slot*8=0x70)
# Should be disp8 path with disp8=0x70
expected_disp8 = 0x70
found_0e = expected_disp8 in [h[1] for h in hits]
print(f'\nFirst SET (slot 0x0E): disp8=0x70 {"FOUND" if found_0e else "MISSING"}')

# Check last byte of mov rax, imm64 (which is 0 for SET 0)
# mov rax, 0 is 48 B8 00 00 00 00 00 00 00 00
rax_zeros = len(re.findall(rb'\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00', d))
print(f'\nmov rax, 0 (10-byte) count: {rax_zeros}')
