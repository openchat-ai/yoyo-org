import sys
d = open(sys.argv[1], 'rb').read()
# Find all C3 bytes (RET) at offsets after a likely startup
for i in range(0, len(d) - 1):
    if d[i] == 0xC3:
        # Show context: 4 bytes before, C3, 4 bytes after
        start = max(0, i - 8)
        end = min(len(d), i + 9)
        ctx = d[start:end]
        # Skip if all the surrounding bytes are 0 (likely padding)
        non_zero_before = any(b != 0 for b in d[max(0, i-8):i])
        non_zero_after = any(b != 0 for b in d[i+1:end])
        if non_zero_before or non_zero_after:
            print(f'  offset 0x{i:04x}: ' + ' '.join(f'{b:02x}' for b in ctx))
