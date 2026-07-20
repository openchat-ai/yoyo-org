#!/usr/bin/env python3
"""Scan yoyo.ty for opcodes that take 3 args but only have 2 in source.

Expected 3-arg opcodes: 0x80 (LDB), 0x84 (MEMCPYD), 0x85 (MEMCPYS),
0x55 (LIBYOYO_READ), 0x56 (LIBYOYO_WRITE), 0x51 (WRITEFILE).
"""
import sys
import re

THREE_ARG_OPCODES = {
    0x80: "LDB",
    0x84: "MEMCPYD",
    0x85: "MEMCPYS",
    0x55: "LIBYOYO_READ",
    0x56: "LIBYOYO_WRITE",
    0x51: "WRITEFILE",
}

def scan(path):
    bugs = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('#'):
                continue
            tokens = line.split()
            if not tokens:
                continue
            # 24-bit or 1-byte opcode
            if len(tokens) >= 3 and tokens[0] in ('00', '0x00') and tokens[1] in ('00', '0x00'):
                op = int(tokens[2], 16)
                args = tokens[3:]
            else:
                op = int(tokens[0], 16)
                args = tokens[1:]
            # Strip comments at end (shouldn't happen if stripped)
            # Count args (skip 's<hex>' data tokens)
            arg_count = 0
            for tok in args:
                if tok.startswith('s'):
                    break
                arg_count += 1
            if op in THREE_ARG_OPCODES and arg_count < 3:
                bugs.append((line_no, op, THREE_ARG_OPCODES[op], arg_count, line[:80]))
    return bugs

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"F:\yoyo-ide\projects\yoyo.ty"
    bugs = scan(path)
    print(f"Found {len(bugs)} bugs in {path}:")
    for line_no, op, name, arg_count, line in bugs:
        print(f"  line {line_no}: op=0x{op:02X} ({name}) has only {arg_count} args (need 3)")
        print(f"    {line}")
    sys.exit(0 if not bugs else 1)