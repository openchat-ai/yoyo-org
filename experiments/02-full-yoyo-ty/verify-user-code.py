import sys, struct

def find_user_code(filename):
    """Find the user-emitted RET byte after the startup tail."""
    d = open(filename, 'rb').read()
    # Pattern: add rsp, imm8/imm32 (48 83 c4 ?? or 48 81 c4 ????)
    # then c3 (ret = startup's last ret)
    # then user's compiled code (in this case, another c3)
    for i in range(0, len(d) - 10):
        # Match "add rsp, imm8": 48 83 c4 XX
        if d[i:i+3] == b'\x48\x83\xc4' and 0x00 <= d[i+4] <= 0xFF:
            # Could be startup's add rsp + ret
            if d[i+5] == 0xc3:
                # Now check what's after the c3
                user_start = i + 6
                # Look for next non-trivial bytes
                user_code = d[user_start:user_start+16]
                return i, user_code
        # Match "add rsp, imm32": 48 81 c4 XX XX XX XX
        if d[i:i+3] == b'\x48\x81\xc4':
            if d[i+7] == 0xc3:
                user_start = i + 8
                user_code = d[user_start:user_start+16]
                return i, user_code
    return None, None

for name in ['yoyo-js.exe', 'yoyo-rust.exe', 'yoyo-asm.exe']:
    path = f'F:\\yoyo-org\\experiments\\02-full-yoyo-ty\\products\\{name}'
    offset, user_code = find_user_code(path)
    if user_code is not None:
        print(f'{name}: startup tail at 0x{offset:04x}, user code: {user_code.hex()}')
    else:
        print(f'{name}: NO startup tail found')
