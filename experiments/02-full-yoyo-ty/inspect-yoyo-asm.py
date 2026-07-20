import sys, re
d = open(sys.argv[1], 'rb').read()
print('size:', len(d))
print('first 16 bytes of .text (offset 0x200):', d[0x200:0x210].hex())

# mov [r15+disp8], rax: 49 89 47 XX
hits = [(m.start(), m.group(0)[3]) for m in re.finditer(rb'\x49\x89\x47.', d)]
print(f'mov [r15+disp8] count: {len(hits)}')
disp8_values = sorted(set(h[1] for h in hits))
print(f'unique disp8 values used (slot*8): {disp8_values}')
slot_values = sorted(set(d // 8 for d in disp8_values))
print(f'unique slots used: {slot_values}')

# mov rax, imm64: 48 B8 + 8 bytes imm
rax_hits = list(re.finditer(rb'\x48\xb8(........)', d))
print(f'mov rax, imm64 count: {len(rax_hits)}')
imms = [int.from_bytes(h.group(1)[:4], 'little') for h in rax_hits]
print(f'first 20 imm low 32 bits: {imms[:20]}')
