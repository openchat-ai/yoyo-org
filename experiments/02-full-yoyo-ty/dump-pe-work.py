import sys
d = open(sys.argv[1], 'rb').read()
# PE_work_buf starts at 0x80 in yoyo-asm's output
# Opcodes dumped at offset 0x28 within pe_work_buf
# So pe_work_buf offset 0x28 → file offset 0x80 + 0x28 = 0xA8
# But there might be alignment. Let me just look at pe_work_buf
print('pe_work_buf (offset 0x80 - 0x180):')
for i in range(0x80, min(len(d), 0x180), 16):
    chunk = d[i:i+16]
    if any(b != 0 for b in chunk):
        print(f'  {i:04x}: {" ".join(f"{b:02x}" for b in chunk)}')
