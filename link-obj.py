"""
Tiny PE linker for NASM COFF AMD64 .obj files.
Builds minimal PE32+ image (.text + .data + .bss) with kernel32 imports.

Usage: python link-obj.py input.obj output.exe
"""
import struct
import sys

# === COFF constants ===
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

REL_BASED_DIR64 = 1

class Section:
    def __init__(self, name):
        self.name = name
        self.raw_data = b''
        self.virt_size = 0
        self.virt_addr = 0
        self.raw_ptr = 0
        self.raw_size = 0
        self.relocs = []
        self.chars = 0

class Symbol:
    def __init__(self, idx, name, value, sect_num, sym_type, storage, aux_count):
        self.idx = idx
        self.name = name
        self.value = value
        self.sect_num = sect_num
        self.type = sym_type
        self.storage = storage
        self.aux_count = aux_count

def parse_obj(path):
    with open(path, 'rb') as f:
        data = f.read()

    machine, num_sections, ts, sym_off, num_syms, opt_size, chars = struct.unpack_from('<HHIIIHH', data, 0)
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"not AMD64: 0x{machine:X}")

    sections = []
    sect_base = 20
    for i in range(num_sections):
        b = sect_base + i * 40
        raw = data[b:b+40]
        name = raw[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size, virt_addr, raw_size, raw_ptr, rel_ptr, line_ptr, num_relocs, num_lines, sect_chars = struct.unpack_from('<IIIIIIHHI', raw, 8)
        sec = Section(name)
        sec.virt_size = virt_size
        sec.raw_size = raw_size
        sec.raw_ptr = raw_ptr
        sec.chars = sect_chars
        if raw_size > 0 and raw_ptr > 0:
            sec.raw_data = data[raw_ptr:raw_ptr+raw_size]
        if num_relocs > 0 and rel_ptr > 0:
            for j in range(num_relocs):
                rb = rel_ptr + j * 10
                rva, sym_idx, rtype = struct.unpack_from('<IIH', data, rb)
                sec.relocs.append((rva, sym_idx, rtype))
        sections.append(sec)

    string_tab_off = sym_off + num_syms * 18

    def read_string_at(off):
        if off >= len(data) - string_tab_off:
            return ''
        end = string_tab_off + off
        while end < len(data) and data[end] != 0:
            end += 1
        return data[string_tab_off+off:end].decode('ascii', errors='replace')

    symbols = []
    i = 0
    while i < num_syms:
        b = sym_off + i * 18
        raw = data[b:b+18]
        name_bytes = raw[0:8]
        value, sect_num, sym_type, storage, aux_count = struct.unpack_from('<IHHBB', raw, 8)
        if name_bytes[4:8] == b'\x00\x00\x00\x00':
            offset = struct.unpack_from('<I', name_bytes, 0)[0]
            name = read_string_at(offset)
        else:
            name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
        sym = Symbol(i, name, value, sect_num, sym_type, storage, aux_count)
        symbols.append(sym)
        i += 1 + aux_count

    return sections, symbols, data

def resolve_symbol(symbols, sections, sym_idx):
    if sym_idx >= len(symbols):
        return 0
    sym = symbols[sym_idx]
    if sym.sect_num > 0 and sym.sect_num <= len(sections):
        sec = sections[sym.sect_num - 1]
        return sec.virt_addr + sym.value
    return 0  # external symbol; resolved at runtime via IAT

def build_pe(sections_in, symbols, image_base=0x400000):
    """Build PE32+ image with kernel32 import table for yoy-asm."""
    # External imports
    EXTERNS = ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess", "GetCommandLineA"]

    sections = sections_in

    # Compute virtual addresses: .text at 0x1000
    section_align = 0x1000
    file_align = 0x200

    # Allocate VAs in NASM input order
    cur_va = 0x1000
    for sec in sections:
        sec.virt_addr = cur_va
        if sec.name == '.bss':
            sec.virt_size = sec.raw_size
        else:
            sec.virt_size = len(sec.raw_data)
        cur_va = ((cur_va + sec.virt_size + section_align - 1) // section_align) * section_align

    # Build import directory (placed AFTER existing sections in a separate .idata section)
    # Compute imports: an ILT (Import Lookup Table) entry per function (8 bytes each) + 1 terminator
    # Each function: IMAGE_THUNK_DATA = 8 bytes (RVA into IAT hint/name by ordinal)
    # Hints/name table: 2-byte hint + name string + null terminator, padded to even

    # We'll use ordinal imports (no hint) for simplicity: high bit set, low 16 bits = ordinal

    # IAT structure per DLL:
    # IMAGE_IMPORT_DESCRIPTOR (20 bytes each), terminated by all-zero entry
    # ILT entries: 8 bytes each, terminated by zero entry
    # IAT entries: 8 bytes each, terminated by zero entry (linked separately)

    n_funcs = len(EXTERNS)
    # Per DLL: 20 bytes IMAGE_IMPORT_DESCRIPTOR + (n_funcs+1)*8 ILT + (n_funcs+1)*8 IAT + DLL name + function hint-name
    idl_size = 20  # IMAGE_IMPORT_DESCRIPTOR (1 entry)
    idl_size += (n_funcs + 1) * 8  # ILT
    idl_size += (n_funcs + 1) * 8  # IAT
    dll_name = b'kernel32.dll\x00'
    hint_name_block = b''.join(
        struct.pack('<H', 0) + name.encode('ascii') + b'\x00'
        for name in EXTERNS
    )
    # Pad hint-name block to even
    if len(hint_name_block) % 2:
        hint_name_block += b'\x00'
    idl_size += len(dll_name) + len(hint_name_block)

    # Allocate .idata section after .data/.bss
    idata_va = cur_va
    idata_raw_size = ((idl_size + file_align - 1) // file_align) * file_align
    cur_va = ((cur_va + idata_raw_size + section_align - 1) // section_align) * section_align
    size_of_image = cur_va

    # === Build import directory raw data ===
    # We'll fill rvas to ILT/IAT strings later when we know the base address
    idata_buf = bytearray(idata_size(idl_size))

    # Image Import Descriptor (1 DLL: kernel32.dll)
    # Offset 0: OriginalFirstThunk = RVA to ILT
    # Offset 4: TimeDateStamp = 0
    # Offset 8: ForwarderChain = -1
    # Offset 12: Name = RVA to DLL name
    # Offset 16: FirstThunk = RVA to IAT
    descriptor_off = 0
    ilt_off = 20
    iat_off = ilt_off + (n_funcs + 1) * 8
    dll_name_off = iat_off + (n_funcs + 1) * 8
    hint_name_off = dll_name_off + len(dll_name)

    # Build IAT/ILT: each entry is a 64-bit RVA, terminate with 0
    # Use ordinal-style: not used here. We use hint/name RVAs.
    # Each thunk = hint_name_off + RVA-of-hint-name
    for i, name in enumerate(EXTERNS):
        ih_off = sum(len(EXTERNS[j].encode('ascii')) + 3 for j in range(i))  # cumulative offset within hint block
        # ih_off needs adjustment for 2-byte hint prefix
        full_hint_off = hint_name_off + ih_off
        thunk_rva = idata_va + full_hint_off
        struct.pack_into('<Q', idata_buf, ilt_off + i * 8, thunk_rva)
        struct.pack_into('<Q', idata_buf, iat_off + i * 8, thunk_rva)
    # Zero terminators
    struct.pack_into('<Q', idata_buf, ilt_off + n_funcs * 8, 0)
    struct.pack_into('<Q', idata_buf, iat_off + n_funcs * 8, 0)
    # Descriptor
    struct.pack_into('<I', idata_buf, descriptor_off + 0, idata_va + ilt_off)  # OriginalFirstThunk
    struct.pack_into('<I', idata_buf, descriptor_off + 4, 0)  # TimeDateStamp
    struct.pack_into('<I', idata_buf, descriptor_off + 8, 0xFFFFFFFF)  # ForwarderChain
    struct.pack_into('<I', idata_buf, descriptor_off + 12, idata_va + dll_name_off)  # Name
    struct.pack_into('<I', idata_buf, descriptor_off + 16, idata_va + iat_off)  # FirstThunk
    # DLL name
    idata_buf[dll_name_off:dll_name_off+len(dll_name)] = dll_name
    # Hint/Name block
    idata_buf[hint_name_off:hint_name_off+len(hint_name_block)] = hint_name_block

    # === Headers ===
    pe_hdr_offset = 0x80
    num_sections = len(sections) + 1  # +1 for .idata
    opt_hdr_size = 240

    headers_size = pe_hdr_offset + opt_hdr_size + num_sections * 40
    headers_size = ((headers_size + file_align - 1) // file_align) * file_align

    # Set section raw pointers
    cur_raw = headers_size
    for sec in sections:
        sec.raw_ptr = cur_raw if sec.name != '.bss' else 0
        if sec.name != '.bss':
            sec.raw_size = ((len(sec.raw_data) + file_align - 1) // file_align) * file_align
            cur_raw += sec.raw_size

    idata_raw_ptr = cur_raw

    # Find size of code
    code_size = sum(len(s.raw_data) for s in sections if s.name == '.text')
    init_data_size = sum(len(s.raw_data) for s in sections if s.name == '.data') + len(idata_buf)
    uninit_size = sum(s.raw_size for s in sections if s.name == '.bss')

    # Find entry symbol 'start'
    entry_rva = 0x1000
    for sym in symbols:
        if sym.name == 'start' and sym.sect_num > 0 and sym.sect_num <= len(sections):
            sec = sections[sym.sect_num - 1]
            entry_rva = sec.virt_addr + sym.value
            break

    # === Build out bytes ===
    out = bytearray(size_of_image)
    import sys
    sys.stderr.write(f"DEBUG: size_of_image=0x{size_of_image:X} idata_va=0x{idata_va:X} idata_raw_size=0x{idata_raw_size:X} idl_size={idl_size}\n")
    sys.stderr.write(f"DEBUG: n_funcs={n_funcs} ilt_off={ilt_off} iat_off={iat_off} dll_name_off={dll_name_off} hint_name_off={hint_name_off}\n")
    sys.stderr.write(f"DEBUG: len(idata_buf)={len(idata_buf)} n_zero_byte={sum(1 for b in idata_buf if b == 0)}\n")
    sys.stderr.flush()

    # MZ header
    out[0:2] = b'MZ'
    struct.pack_into('<I', out, 0x3C, pe_hdr_offset)

    # PE signature
    out[pe_hdr_offset:pe_hdr_offset+4] = b'PE\x00\x00'

    # IMAGE_FILE_HEADER
    coff_off = pe_hdr_offset + 4
    struct.pack_into('<HHIIIHH', out, coff_off,
        IMAGE_FILE_MACHINE_AMD64,
        num_sections,
        0, 0, 0,
        opt_hdr_size,
        0x2102,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DEBUG_STRIPPED | LINE_NUMS_STRIPPED | LOCAL_SYMS_STRIPPED
    )

    # IMAGE_OPTIONAL_HEADER (PE32+)
    opt_off = coff_off + 20
    struct.pack_into('<H', out, opt_off + 0, 0x20B)
    struct.pack_into('<B', out, opt_off + 2, 14)
    struct.pack_into('<B', out, opt_off + 3, 0)
    struct.pack_into('<I', out, opt_off + 4, code_size)
    struct.pack_into('<I', out, opt_off + 8, init_data_size)
    struct.pack_into('<I', out, opt_off + 12, uninit_size)
    struct.pack_into('<I', out, opt_off + 16, entry_rva)
    struct.pack_into('<I', out, opt_off + 20, 0x1000)  # BaseOfCode
    struct.pack_into('<Q', out, opt_off + 24, image_base)
    struct.pack_into('<I', out, opt_off + 32, section_align)
    struct.pack_into('<I', out, opt_off + 36, file_align)
    struct.pack_into('<H', out, opt_off + 40, 6)  # MajorOS
    struct.pack_into('<H', out, opt_off + 42, 0)
    struct.pack_into('<H', out, opt_off + 44, 0)
    struct.pack_into('<H', out, opt_off + 46, 0)
    struct.pack_into('<H', out, opt_off + 48, 6)  # MajorSubsystem
    struct.pack_into('<H', out, opt_off + 50, 0)
    struct.pack_into('<I', out, opt_off + 52, 0)
    struct.pack_into('<I', out, opt_off + 56, size_of_image)
    struct.pack_into('<I', out, opt_off + 60, headers_size)
    struct.pack_into('<I', out, opt_off + 64, 0)
    struct.pack_into('<H', out, opt_off + 68, 3)  # Subsystem=CONSOLE
    struct.pack_into('<H', out, opt_off + 70, 0)
    struct.pack_into('<Q', out, opt_off + 72, 0x100000)
    struct.pack_into('<Q', out, opt_off + 80, 0x1000)
    struct.pack_into('<Q', out, opt_off + 88, 0x100000)
    struct.pack_into('<Q', out, opt_off + 96, 0x1000)
    struct.pack_into('<I', out, opt_off + 104, 0)
    struct.pack_into('<I', out, opt_off + 108, 16)  # NumberOfRvaAndSizes

    # Data Directories (16 entries)
    # [0] Export: nothing
    struct.pack_into('<II', out, opt_off + 112, 0, 0)
    # [1] Import: IAT RVA, size
    iat_size = n_funcs * 8 + len(dll_name) + len(hint_name_block) + 20
    struct.pack_into('<II', out, opt_off + 120, idata_va + ilt_off, iat_size)
    # [2..15] zeros
    for dd in range(2, 16):
        struct.pack_into('<II', out, opt_off + 112 + dd * 8, 0, 0)

    # === Section headers ===
    sect_hdrs_off = pe_hdr_offset + 4 + 20 + opt_hdr_size
    all_sections = list(sections) + [Section('.idata')]  # append .idata
    all_sections[-1].virt_addr = idata_va
    all_sections[-1].virt_size = idata_raw_size
    all_sections[-1].raw_ptr = idata_raw_ptr
    all_sections[-1].raw_size = idata_raw_size
    all_sections[-1].raw_data = bytes(idata_buf)
    all_sections[-1].chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

    for i, sec in enumerate(all_sections):
        sh = sect_hdrs_off + i * 40
        name_bytes = sec.name.encode('ascii')[:8].ljust(8, b'\x00')
        out[sh:sh+8] = name_bytes
        struct.pack_into('<I', out, sh+8, sec.virt_size)
        struct.pack_into('<I', out, sh+12, sec.virt_addr)
        struct.pack_into('<I', out, sh+16, sec.raw_size)
        struct.pack_into('<I', out, sh+20, sec.raw_ptr)
        struct.pack_into('<I', out, sh+24, 0)
        struct.pack_into('<I', out, sh+28, 0)
        struct.pack_into('<H', out, sh+32, 0)
        struct.pack_into('<H', out, sh+34, 0)
        struct.pack_into('<I', out, sh+36, sec.chars)

    # === Copy section raw data to both virtual memory view (for relocation) ===
    # === and to file offset (for the actual file content) ===
    # We use a memory-view buffer for relocations, then write final file from it.
    mem_view = bytearray(size_of_image)
    for sec in all_sections:
        if sec.name == '.bss':
            continue
        if sec.raw_ptr == 0:
            continue
        # Place section data at virtual address
        mem_view[sec.virt_addr:sec.virt_addr+len(sec.raw_data)] = sec.raw_data

    # === Apply relocations via memory view ===
    for sec in sections:
        for (rel_offset, sym_idx, rtype) in sec.relocs:
            if rtype == REL_BASED_DIR64:
                abs_vaddr = sec.virt_addr + rel_offset
                symbol_addr = resolve_symbol(symbols, sections, sym_idx)
                target = image_base + symbol_addr
                struct.pack_into('<Q', mem_view, abs_vaddr, target)

    # === Copy from memory view to file (at raw_ptr positions) ===
    for sec in all_sections:
        if sec.name == '.bss':
            continue
        if sec.raw_ptr == 0:
            continue
        # raw_data now needs to include relocation patches
        # So take mem_view[virt_addr:virt_addr+len]
        section_data = bytes(mem_view[sec.virt_addr:sec.virt_addr+sec.raw_size])
        out[sec.raw_ptr:sec.raw_ptr+len(section_data)] = section_data

    # DEBUG
    sys.stderr.write(f"DEBUG .text at file 0x{all_sections[0].raw_ptr:X} (16 bytes): {bytes(out[all_sections[0].raw_ptr:all_sections[0].raw_ptr+16]).hex()}\n")
    for sec in all_sections:
        if sec.name == '.idata':
            sys.stderr.write(f"DEBUG .idata at file 0x{sec.raw_ptr:X} (16 bytes): {bytes(out[sec.raw_ptr:sec.raw_ptr+16]).hex()}\n")
    sys.stderr.flush()

    return bytes(out)

    # === Apply relocations (DIR64) ===
    for sec in sections:
        for (rel_offset, sym_idx, rtype) in sec.relocs:
            if rtype == REL_BASED_DIR64:
                abs_vaddr = sec.virt_addr + rel_offset
                symbol_addr = resolve_symbol(symbols, sections, sym_idx)
                target = image_base + symbol_addr
                struct.pack_into('<Q', out, abs_vaddr, target)
            # else: skip (rare types)

    # DEBUG: check idata contents at out[idata_va]
    sys.stderr.write(f"DEBUG after copy: out[0x{idata_va:X}:0x{idata_va+16:X}] = {bytes(out[idata_va:idata_va+16]).hex()}\n")
    sys.stderr.flush()
    return bytes(out)

def idata_size(byte_len):
    return byte_len

def main():
    if len(sys.argv) != 3:
        print("Usage: python link-obj.py input.obj output.exe", file=sys.stderr)
        sys.exit(1)

    sections, symbols, _ = parse_obj(sys.argv[1])
    out_bytes = build_pe(sections, symbols)

    with open(sys.argv[2], 'wb') as f:
        f.write(out_bytes)

    print(f"Wrote {sys.argv[2]}: {len(out_bytes)} bytes", file=sys.stderr)

if __name__ == '__main__':
    main()
