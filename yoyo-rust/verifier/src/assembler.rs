use crate::types::Reg;

const STATE_BASE: Reg = Reg::R15;

/// Fixup entry for rel32 (4-byte displacement) jumps/calls to labels.
struct Fixup32 {
    /// Byte offset of the rel32 field (last 4 bytes of instruction).
    rel32_off: usize,
    label_id: usize,
}

/// Type-safe x64 assembler.
///
/// No `Result`, no `FixedBuf`, no const generics. Just a `Vec<u8>` under the hood.
/// All REX prefix and ModRM bytes are computed automatically from `Reg` operands.
pub struct X64Assembler {
    pub bytes: Vec<u8>,
    labels: Vec<usize>,
    fixups: Vec<(usize, usize)>,
    fixups32: Vec<Fixup32>,
}

impl X64Assembler {
    pub fn new() -> Self {
        Self { bytes: Vec::new(), labels: Vec::new(), fixups: Vec::new(), fixups32: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Write bytes at given offset (for patching rel32 etc.)
    pub fn write_at(&mut self, offset: usize, data: &[u8]) {
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }

    /// Read byte at offset
    pub fn read_at(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }

    /// When r/m low3 == 4 (RSP/R12), emit mandatory SIB byte `0x24` = [base] no index.
    /// Must be called after `emit_modrm` whenever a base register is used as r/m.
    fn maybe_emit_sib(&mut self, base: Reg) {
        if base.low3() == 4 {
            self.emit_u8(0x24);
        }
    }

    // ── Label / fixup system (for short jumps rel8 inside emitted code) ──

    /// Allocate a new label slot. Returns label id — use with `set_label` + `jmp_rel8_label` / `jcc_rel8_label`.
    pub fn alloc_label(&mut self) -> usize {
        let id = self.labels.len();
        self.labels.push(0); // placeholder, set_label fills it in
        id
    }

    /// Record current byte position as the target of `id` (must have been allocated by `alloc_label`).
    pub fn set_label(&mut self, id: usize) {
        self.labels[id] = self.bytes.len();
    }

    /// Get the byte offset of a label (must have been allocated and set).
    pub fn get_label_offset(&self, id: usize) -> usize {
        self.labels[id]
    }

    /// Emit `E9 00 00 00 00` (rel32 placeholder) and record a fixup.
    /// Always uses rel32 form to avoid distance overflow issues.
    pub fn jmp_rel8_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0xE9);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 1, label_id: label });
    }

    /// Emit `0F 8x 00 00 00 00` (rel32 placeholder) and record a fixup.
    /// Always uses rel32 form to avoid distance overflow issues.
    pub fn jcc_rel8_label(&mut self, cc: u8, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0x0F);
        self.emit_u8(0x80 | (cc & 0x0F));
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 2, label_id: label });
    }

    /// Resolve all fixups: compute disp = label_pos - (fixup_offset + 2).
    /// Must be called after all labels and instructions are emitted.
    pub fn resolve_fixups(&mut self) {
        // rel8 fixups
        for &(fixup_offset, label_id) in &self.fixups {
            let label_pos = self.labels[label_id];
            let disp = label_pos as i32 - (fixup_offset as i32 + 2);
            self.bytes[fixup_offset + 1] = disp as u8;
        }
        // rel32 fixups
        for fixup in &self.fixups32 {
            let label_pos = self.labels[fixup.label_id] as i32;
            let rel32_off = fixup.rel32_off as i32;
            // disp = target - (instruction_end), where instruction_end = rel32_off + 4
            // because rel32 is stored at the 4 bytes starting at rel32_off.
            let disp = label_pos - (rel32_off + 4);
            self.bytes[fixup.rel32_off..fixup.rel32_off + 4].copy_from_slice(&disp.to_le_bytes());
        }
    }

    // ── rel32 label fixup methods (for CALL/JMP/JCC with 4-byte displacement) ──

    /// `E8 rel32` — call to label, patched via fixups32
    pub fn call_rel32_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0xE8);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 1, label_id: label });
    }

    /// `E9 rel32` — jmp to label, patched via fixups32
    pub fn jmp_rel32_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0xE9);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 1, label_id: label });
    }

    /// `0F 8x rel32` — jcc to label, patched via fixups32
    pub fn jcc_rel32_label(&mut self, cc: u8, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0x0F);
        self.emit_u8(0x80 | (cc & 0x0F));
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 2, label_id: label });
    }

    // ── Private helpers ──

    fn rex(w: bool, r: bool, x: bool, b: bool) -> u8 {
        0x40 | if w { 0x08 } else { 0 }
             | if r { 0x04 } else { 0 }
             | if x { 0x02 } else { 0 }
             | if b { 0x01 } else { 0 }
    }

    fn modrm(mod_: u8, reg: u8, rm: u8) -> u8 {
        (mod_ << 6) | ((reg & 7) << 3) | (rm & 7)
    }

    pub fn emit_u8(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    fn emit_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn emit_i32(&mut self, val: i32) {
        self.bytes.extend(&val.to_le_bytes());
    }

    pub fn emit_u32(&mut self, val: u32) {
        self.bytes.extend(&val.to_le_bytes());
    }

    pub fn emit_u64(&mut self, val: u64) {
        self.bytes.extend(&val.to_le_bytes());
    }

    fn emit_rex(&mut self, w: bool, r: bool, x: bool, b: bool) {
        self.emit_u8(Self::rex(w, r, x, b));
    }

    fn emit_modrm(&mut self, mod_: u8, reg: u8, rm: u8) {
        self.emit_u8(Self::modrm(mod_, reg, rm));
    }

    // ── Register operations ──

    /// `mov dst, src` (3 bytes: REX.W + 0x89 + ModRM)
    pub fn mov_rr(&mut self, dst: Reg, src: Reg) {
        self.emit_rex(true, src.rex_r(), false, dst.rex_b());
        self.emit_u8(0x89);
        self.emit_modrm(3, src.low3(), dst.low3());
    }

    /// `mov reg, imm64` (10 bytes: REX.W + 0xB8|low3 + imm64)
    pub fn mov_imm64(&mut self, reg: Reg, imm: u64) {
        self.emit_rex(true, false, false, reg.rex_b());
        self.emit_u8(0xB8 | reg.low3());
        self.emit_u64(imm);
    }

    /// `push reg`
    pub fn push(&mut self, reg: Reg) {
        if reg.rex_b() {
            self.emit_u8(0x41);
            self.emit_u8(0x50 | reg.low3());
        } else {
            // REX-free: 0x50 | low3 for all low 8 registers
            self.emit_u8(0x50 | reg.low3());
        }
    }

    /// `pop reg`
    pub fn pop(&mut self, reg: Reg) {
        if reg.rex_b() {
            self.emit_u8(0x41);
            self.emit_u8(0x58 | reg.low3());
        } else {
            self.emit_u8(0x58 | reg.low3());
        }
    }

    /// `ret`
    pub fn ret(&mut self) {
        self.emit_u8(0xC3);
    }

    /// `inc reg` (48 FF C0+rm for 64-bit extended registers)
    pub fn inc(&mut self, reg: Reg) {
        self.emit_rex(true, false, false, reg.rex_b());
        self.emit_u8(0xFF);
        self.emit_modrm(3, 0, reg.low3());
    }

    /// `dec reg`
    pub fn dec(&mut self, reg: Reg) {
        self.emit_rex(true, false, false, reg.rex_b());
        self.emit_u8(0xFF);
        self.emit_modrm(3, 1, reg.low3());
    }

    // ── State slot operations [r15 + slot*8] ──

    fn state_offset(slot: u8) -> u16 {
        (slot as u16) * 8
    }

    /// `mov [r15 + slot*8], src` (4 or 7 bytes)
    pub fn store_state(&mut self, slot: u8, src: Reg) {
        let off = Self::state_offset(slot);
        self.emit_rex(true, src.rex_r(), false, Reg::R15.rex_b());
        self.emit_u8(0x89);
        if off <= 127 {
            self.emit_modrm(1, src.low3(), Reg::R15.low3());
            self.emit_u8(off as u8);
        } else {
            self.emit_modrm(2, src.low3(), Reg::R15.low3());
            self.emit_u32(off as u32);
        }
    }

    /// `mov dst, [r15 + slot*8]` (4 or 7 bytes)
    pub fn load_state(&mut self, dst: Reg, slot: u8) {
        let off = Self::state_offset(slot);
        self.emit_rex(true, dst.rex_r(), false, Reg::R15.rex_b());
        self.emit_u8(0x8B);
        if off <= 127 {
            self.emit_modrm(1, dst.low3(), Reg::R15.low3());
            self.emit_u8(off as u8);
        } else {
            self.emit_modrm(2, dst.low3(), Reg::R15.low3());
            self.emit_u32(off as u32);
        }
    }

    /// `lea dst, [r15 + slot*8]` (always disp32, 7 bytes)
    pub fn lea_state(&mut self, dst: Reg, slot: u16) {
        let off = (slot as u32) * 8;
        self.emit_rex(true, dst.rex_r(), false, Reg::R15.rex_b());
        self.emit_u8(0x8D);
        self.emit_modrm(2, dst.low3(), Reg::R15.low3());
        self.emit_u32(off);
    }

    // ── ALU operations ──

    /// `add reg, imm` (auto s8/s32: 4 or 7 bytes)
    pub fn add_imm(&mut self, reg: Reg, imm: i32) {
        let rm = reg.low3();
        self.emit_rex(true, false, false, reg.rex_b());
        if imm >= -128 && imm <= 127 {
            self.emit_u8(0x83);
            self.emit_modrm(3, 0, rm);
            self.emit_u8(imm as u8);
        } else {
            self.emit_u8(0x81);
            self.emit_modrm(3, 0, rm);
            self.emit_i32(imm);
        }
    }

    /// `sub reg, imm` (auto s8/s32)
    pub fn sub_imm(&mut self, reg: Reg, imm: i32) {
        let rm = reg.low3();
        self.emit_rex(true, false, false, reg.rex_b());
        if imm >= -128 && imm <= 127 {
            self.emit_u8(0x83);
            self.emit_modrm(3, 5, rm);
            self.emit_u8(imm as u8);
        } else {
            self.emit_u8(0x81);
            self.emit_modrm(3, 5, rm);
            self.emit_i32(imm);
        }
    }

    /// `add dst, src`
    pub fn add_rr(&mut self, dst: Reg, src: Reg) {
        self.emit_rex(true, src.rex_r(), false, dst.rex_b());
        self.emit_u8(0x01);
        self.emit_modrm(3, src.low3(), dst.low3());
    }

    /// `sub dst, src`
    pub fn sub_rr(&mut self, dst: Reg, src: Reg) {
        self.emit_rex(true, src.rex_r(), false, dst.rex_b());
        self.emit_u8(0x29);
        self.emit_modrm(3, src.low3(), dst.low3());
    }

    /// `imul dst, src`
    pub fn imul_rr(&mut self, dst: Reg, src: Reg) {
        self.emit_rex(true, dst.rex_r(), false, src.rex_b());
        self.emit_u8(0x0F);
        self.emit_u8(0xAF);
        self.emit_modrm(3, dst.low3(), src.low3());
    }

    /// `cmp reg1, reg2`
    pub fn cmp_rr(&mut self, reg1: Reg, reg2: Reg) {
        self.emit_rex(true, reg2.rex_r(), false, reg1.rex_b());
        self.emit_u8(0x39);
        self.emit_modrm(3, reg2.low3(), reg1.low3());
    }

    // ── Memory operations ──

    /// `mov reg, [base + disp]` — load 64-bit from memory into register.
    /// Auto mod=00 (3B), disp8 (4B), or disp32 (7B).
    pub fn load_mem(&mut self, reg: Reg, base: Reg, disp: i32) {
        self.emit_rex(true, reg.rex_r(), false, base.rex_b());
        self.emit_u8(0x8B);
        if disp == 0 {
            self.emit_modrm(0, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
        } else if disp >= -128 && disp <= 127 {
            self.emit_modrm(1, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(disp as u8);
        } else {
            self.emit_modrm(2, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_i32(disp);
        }
    }

    /// `lea reg, [base + disp]` — load effective address (REX.W prefixed).
    pub fn lea_mem(&mut self, reg: Reg, base: Reg, disp: i32) {
        self.emit_rex(true, reg.rex_r(), false, base.rex_b());
        self.emit_u8(0x8D);
        if disp == 0 {
            self.emit_modrm(0, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
        } else if disp >= -128 && disp <= 127 {
            self.emit_modrm(1, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(disp as u8);
        } else {
            self.emit_modrm(2, reg.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_i32(disp);
        }
    }

    /// `mov qword [rsp + disp8], imm32` (10 bytes):
    /// `48 C7 44 24 dd ii ii ii ii`
    pub fn mov_qword_rsp_disp(&mut self, disp: u8, imm: i32) {
        self.emit_u8(0x48);  // REX.W
        self.emit_u8(0xC7);  // MOV r/m64, imm32
        self.emit_modrm(1, 0, Reg::Rsp.low3()); // mod=01, reg=000, rm=100 → SIB
        self.emit_u8(0x24);  // SIB: base=RSP
        self.emit_u8(disp);
        self.emit_i32(imm);
    }

    /// `movzx eax, byte [base + disp]` — zero-extend byte to RAX.
    /// Auto disp8 (4B total without REX) or disp32 (7B).
    pub fn movzx_eax_byte_mem(&mut self, base: Reg, disp: i32) {
        if base.rex_b() {
            self.emit_u8(0x41); // REX.B for high base register
        }
        self.emit_u8(0x0F);
        self.emit_u8(0xB6); // MOVZX r32, r/m8
        if disp >= -128 && disp <= 127 {
            self.emit_modrm(1, 0, base.low3()); // mod=01, reg=000(eax), rm=base
            self.maybe_emit_sib(base);
            self.emit_u8(disp as u8);
        } else {
            self.emit_modrm(2, 0, base.low3()); // mod=10, reg=000(eax), rm=base
            self.maybe_emit_sib(base);
            self.emit_i32(disp);
        }
    }

    // ── Stack frame helpers ──

    /// `sub rsp, 0x20` — standard x64 shadow space (4 × 8 bytes).
    /// Keeps RSP 16-byte aligned BEFORE the CALL instruction
    /// so that inside the callee RSP is 8 bytes off from 16-byte
    /// alignment (as required by the Windows x64 calling convention).
    pub fn shadow_frame(&mut self) {
        self.sub_imm(Reg::Rsp, 0x20);
    }

    /// `add rsp, 0x20`
    pub fn shadow_ret(&mut self) {
        self.add_imm(Reg::Rsp, 0x20);
    }

    /// `mov byte [base], val` (e.g. mov byte [rsi], al = 88 06)
    pub fn mov_byte_mem_reg(&mut self, base: Reg, val: Reg) {
        let need_rex = base.rex_b() || val.rex_r();
        if need_rex {
            self.emit_u8(0x40 | (if val.rex_r() { 4 } else { 0 }) | (if base.rex_b() { 1 } else { 0 }));
        }
        self.emit_u8(0x88);
        if base.low3() == 5 {
            self.emit_modrm(1, val.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(0);
        } else {
            self.emit_modrm(0, val.low3(), base.low3());
            self.maybe_emit_sib(base);
        }
    }

    /// `mov reg, byte [base]` (e.g. mov al, [rsi] = 8A 06)
    pub fn mov_reg_byte_mem(&mut self, dst: Reg, base: Reg) {
        let need_rex = base.rex_b() || dst.rex_r();
        if need_rex {
            self.emit_u8(0x40 | (if dst.rex_r() { 4 } else { 0 }) | (if base.rex_b() { 1 } else { 0 }));
        }
        self.emit_u8(0x8A);
        if base.low3() == 5 {
            self.emit_modrm(1, dst.low3(), base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(0);
        } else {
            self.emit_modrm(0, dst.low3(), base.low3());
            self.maybe_emit_sib(base);
        }
    }

    /// `mov byte [base], imm8` (e.g. C6 06 00 = mov byte [rsi], 0)
    pub fn mov_byte_mem_imm(&mut self, base: Reg, imm: u8) {
        if base.rex_b() {
            self.emit_u8(0x41);
        }
        self.emit_u8(0xC6);
        if base.low3() == 5 {
            self.emit_modrm(1, 0, base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(0);
        } else {
            self.emit_modrm(0, 0, base.low3());
            self.maybe_emit_sib(base);
        }
        self.emit_u8(imm);
    }

    /// `cmp byte [base], imm8` (e.g. 80 3E 20 = cmp byte [rsi], 0x20)
    pub fn cmp_byte_mem_imm(&mut self, base: Reg, imm: u8) {
        if base.rex_b() {
            self.emit_u8(0x41);
        }
        self.emit_u8(0x80);
        if base.low3() == 5 {
            self.emit_modrm(1, 7, base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(0);
        } else {
            self.emit_modrm(0, 7, base.low3());
            self.maybe_emit_sib(base);
        }
        self.emit_u8(imm);
    }

    // ── Test ──

    /// `test reg, reg` (byte, e.g. test al, al = 84 C0)
    pub fn test_r8_r8(&mut self, r1: Reg, r2: Reg) {
        let need_rex = r1.rex_b() || r2.rex_r();
        if need_rex {
            self.emit_u8(0x40 | (if r2.rex_r() { 4 } else { 0 }) | (if r1.rex_b() { 1 } else { 0 }));
        }
        self.emit_u8(0x84);
        self.emit_modrm(3, r2.low3(), r1.low3());
    }

    // ── Jumps / Calls (rel32 with placeholder zeros, caller patches later) ──

    /// `E8 rel32` (5 bytes)
    pub fn call_rel32_placeholder(&mut self) {
        self.emit_u8(0xE8);
        self.emit_i32(0);
    }

    /// `E9 rel32` (5 bytes)
    pub fn jmp_rel32_placeholder(&mut self) {
        self.emit_u8(0xE9);
        self.emit_i32(0);
    }

    /// `0F 8x rel32` (6 bytes)
    pub fn jcc_rel32_placeholder(&mut self, cc: u8) {
        self.emit_u8(0x0F);
        self.emit_u8(0x80 | (cc & 0x0F));
        self.emit_i32(0);
    }

    // ── Short jumps (rel8, used in emitted code for small loops) ──

    /// `EB rel8` (2 bytes)
    pub fn jmp_rel8(&mut self, disp: i8) {
        self.emit_u8(0xEB);
        self.emit_u8(disp as u8);
    }

    /// `7x rel8` (2 bytes)
    pub fn jcc_rel8(&mut self, cc: u8, disp: i8) {
        self.emit_u8(0x70 | (cc & 0x0F));
        self.emit_u8(disp as u8);
    }

    // ── New primitives for V3 executor ──

    /// `stosb` — store AL at [RDI], increment RDI (AA, 1 byte)
    pub fn stosb(&mut self) {
        self.emit_u8(0xAA);
    }

    /// `stosd` — store EAX at [RDI], increment RDI by 4 (AB, 1 byte)
    pub fn stosd(&mut self) {
        self.emit_u8(0xAB);
    }

    /// `xlatb` — mov al, [rbx + al] (D7, 1 byte)
    /// `xlatb` replacement: `al = [rbx + al]` using movzx instead of D7.
    /// Original D7 was removed on AMD Zen 3+ → illegal instruction.
/// Equivalent: movzx eax,al; movzx rax,byte[rbx+rax]; AL = lookup result
    /// ModRM=0x04 (mod=00, reg=000=RAX, rm=SIB); SIB=0x03 (scale=1, idx=RAX, base=RBX)
    pub fn xlatb(&mut self) {
        self.emit_u8(0x0F); self.emit_u8(0xB6); self.emit_u8(0xC0); // movzx eax, al (3B)
        self.emit_u8(0x48); self.emit_u8(0x0F); self.emit_u8(0xB6); // movzx rax, byte [rbx+rax] (5B)
        self.emit_u8(0x04); self.emit_u8(0x03);
    }

    /// `lea rbx, [rip + disp32]` (48 8D 1D disp32, 7 bytes)
    pub fn lea_rbx_rip(&mut self, disp: i32) {
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x1D);
        self.emit_i32(disp);
    }

    /// `mov al, imm8` (B0 imm8, 2 bytes)
    pub fn mov_al_imm8(&mut self, imm: u8) {
        self.emit_u8(0xB0);
        self.emit_u8(imm);
    }

    /// `mov eax, imm32` (B8 imm32, 5 bytes, 32-bit — clears upper 32 bits of RAX)
    pub fn mov_eax_imm32(&mut self, imm: u32) {
        self.emit_u8(0xB8);
        self.emit_u32(imm);
    }

    /// `cmp al, imm8` (3C imm8, 2 bytes)
    pub fn cmp_al_imm8(&mut self, imm: u8) {
        self.emit_u8(0x3C);
        self.emit_u8(imm);
    }

    /// `shl al, imm8` (C0 E0 imm8, 3 bytes)
    pub fn shl_al_imm8(&mut self, imm: u8) {
        self.emit_u8(0xC0);
        self.emit_u8(0xE0);
        self.emit_u8(imm);
    }

    /// `or al, cl` (08 C8, 2 bytes)
    pub fn or_al_cl(&mut self) {
        self.emit_u8(0x08);
        self.emit_u8(0xC8);
    }

    /// `stc` (F9, 1 byte)
    pub fn stc(&mut self) {
        self.emit_u8(0xF9);
    }

    /// `clc` (F8, 1 byte)
    pub fn clc(&mut self) {
        self.emit_u8(0xF8);
    }

    /// `movzx ecx, al` (0F B6 C8, 3 bytes — zero-extend AL to ECX)
    pub fn movzx_ecx_al(&mut self) {
        self.emit_u8(0x0F);
        self.emit_u8(0xB6);
        self.emit_u8(0xC8);
    }

    /// `mov dword [rdi], eax` (89 07, 2 bytes)
    pub fn mov_dword_rdi_eax(&mut self) {
        self.emit_u8(0x89);
        self.emit_u8(0x07);
    }

    /// `add rdi, imm` (auto s8/s32)
    pub fn add_rdi_imm(&mut self, imm: i32) {
        let rm = Reg::Rdi.low3();
        self.emit_rex(true, false, false, false);
        if imm >= -128 && imm <= 127 {
            self.emit_u8(0x83);
            self.emit_modrm(3, 0, rm);
            self.emit_u8(imm as u8);
        } else {
            self.emit_u8(0x81);
            self.emit_modrm(3, 0, rm);
            self.emit_i32(imm);
        }
    }

    /// `mov byte [rdi], imm8` (C6 07 imm8, 3 bytes)
    pub fn mov_byte_rdi_imm8(&mut self, imm: u8) {
        self.emit_u8(0xC6);
        self.emit_u8(0x07);
        self.emit_u8(imm);
    }

    /// `sub rdi, r14` — compute current_output_offset = RDI - R14
    pub fn sub_rdi_r14(&mut self) {
        // 4C 29 F7
        self.emit_u8(0x4C);
        self.emit_u8(0x29);
        self.emit_modrm(3, Reg::R14.low3(), Reg::Rdi.low3());
    }

    // ── Special patterns ──

    /// `rep movsb` (F3 A4)
    pub fn rep_movsb(&mut self) {
        self.emit_u8(0xF3);
        self.emit_u8(0xA4);
    }

    /// `nop` (0x90, 1 byte)
    pub fn nop(&mut self) {
        self.emit_u8(0x90);
    }

    /// `movzx eax, byte [base + disp]` — used by LDB opcode
    /// disp8: 0F B6 42/82 + disp (4 or 7 bytes)
    pub fn movzx_eax_byte_disp(&mut self, base: Reg, oo: i32) {
        self.emit_u8(0x0F);
        self.emit_u8(0xB6);
        if oo >= -128 && oo <= 127 {
            self.emit_modrm(1, 0, base.low3());
            self.maybe_emit_sib(base);
            self.emit_u8(oo as u8);
        } else {
            self.emit_modrm(2, 0, base.low3());
            self.maybe_emit_sib(base);
            self.emit_i32(oo);
        }
    }

    /// `lea rsi, [rip + disp]` (7 bytes: 48 8D 35 + rel32)
    pub fn lea_rsi_rip(&mut self, disp: i32) {
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x35);
        self.emit_i32(disp);
    }

    // ── IAT / Placeholder patterns ──

    /// `FF 15 ii 00 00 00` — call [rip + ii] for IAT thunk
    pub fn call_iat_thunk(&mut self, api_index: u8) {
        self.emit_u8(0xFF);
        self.emit_u8(0x15);
        self.emit_u8(api_index);
        self.emit_u8(0x00);
        self.emit_u8(0x00);
        self.emit_u8(0x00);
    }

    /// `FF 15 00 00 00 00` — call [rip + 0] placeholder
    pub fn call_rip_placeholder(&mut self) {
        self.call_iat_thunk(0);
    }

    /// `48 8D 35 00 00 00 00` — lea rsi, [rip + 0] placeholder
    pub fn lea_rsi_rip_placeholder(&mut self) {
        self.lea_rsi_rip(0);
    }

    /// `48 8D 3D 00 00 00 00` — lea rdi, [rip + 0] placeholder
    pub fn lea_rdi_rip_placeholder(&mut self) {
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x3D);
        self.emit_i32(0);
    }

    /// `48 8D 0D 00 00 00 00` — lea rcx, [rip + 0] placeholder
    pub fn lea_rcx_rip_placeholder(&mut self) {
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x0D);
        self.emit_i32(0);
    }

    // ── SIB-based LEA (for lea reg, [rsp + disp32]) ──

    /// `lea dst, [rsp + disp32]` using SIB byte: REX.W + 8D + ModRM(SIB) + SIB + disp32
    pub fn lea_rsp_sib32(&mut self, dst: Reg, disp: u32) {
        self.emit_rex(true, dst.rex_r(), false, false);
        self.emit_u8(0x8D);
        // ModRM: mod=10(disp32), reg=dst, r/m=100(SIB)
        self.emit_modrm(2, dst.low3(), 4);
        // SIB: scale=0, index=100(none), base=100(rsp)
        self.emit_u8(0x24);
        self.emit_u32(disp);
    }

    /// `mov [r14 + reg*4], eax` — store dword to handler_offsets table (SIB: 41 89 04 8E)
    pub fn store_handler_offset(&mut self, reg: Reg) {
        // 41 89 04 8E: REX.B=1 (r14 base), opcode=0x89, ModRM=0x04(SIB), SIB=scale=10(index*4)+index+base=110(r14)
        let sib = (2 << 6) | ((reg.low3() as u8) << 3) | (Reg::R14.low3() as u8);
        self.emit_u8(0x41);  // REX.B
        self.emit_u8(0x89);  // MOV r/m32, r32
        self.emit_u8(0x04);  // ModRM: mod=00, reg=000(eax), rm=100(SIB)
        self.emit_u8(sib);
    }

    /// `mov eax, [r14 + reg*4]` — load dword from handler_offsets table (SIB: 41 8B 04 8E)
    pub fn load_handler_offset(&mut self, reg: Reg) {
        let sib = (2 << 6) | ((reg.low3() as u8) << 3) | (Reg::R14.low3() as u8);
        self.emit_u8(0x41);  // REX.B
        self.emit_u8(0x8B);  // MOV r32, r/m32
        self.emit_u8(0x04);  // ModRM: mod=00, reg=000(eax), rm=100(SIB)
        self.emit_u8(sib);
    }

    /// `mov rsi, [rdi]` — load from pointer
    pub fn mov_rsi_rdi_ptr(&mut self) {
        self.emit_u8(0x48);
        self.emit_u8(0x8B);
        self.emit_u8(0x37);
    }

    // ── Syscall (Linux) ──

    // ── Division / multiplication (for PE builder alignment) ──

    /// `DIV r/m64` — unsigned divide RDX:RAX by `divisor`. RAX = quotient, RDX = remainder.
    /// REX.W + F7 + modrm(3, 6, rm)
    pub fn div_r64(&mut self, divisor: Reg) {
        self.emit_rex(true, false, false, divisor.rex_b());
        self.emit_u8(0xF7);
        self.emit_modrm(3, 6, divisor.low3());
    }

    /// `xor edx, edx` (31 D2, 2 bytes) — zero RDX (works because writing to EDX zeros upper 32 bits)
    pub fn xor_edx_edx(&mut self) {
        self.emit_u8(0x31);
        self.emit_u8(0xD2);
    }

    // ── LEA RDI, [RIP + disp] with label fixup ──

    /// Emit `48 8D 3D 00 00 00 00` (LEA RDI, [RIP + 0]) and record a fixup
    /// so the disp32 is patched to point at `label` at resolution time.
    pub fn lea_rdi_rip_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x3D);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 3, label_id: label });
    }

    /// Emit `48 8D 35 00 00 00 00` (LEA RSI, [RIP + 0]) and record a fixup.
    pub fn lea_rsi_rip_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x35);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 3, label_id: label });
    }

    /// Emit `48 8D 0D 00 00 00 00` (LEA RCX, [RIP + 0]) and record a fixup.
    pub fn lea_rcx_rip_label(&mut self, label: usize) {
        let off = self.bytes.len();
        self.emit_u8(0x48);
        self.emit_u8(0x8D);
        self.emit_u8(0x0D);
        self.emit_i32(0);
        self.fixups32.push(Fixup32 { rel32_off: off + 3, label_id: label });
    }

    /// `syscall` (0F 05)
    pub fn syscall(&mut self) {
        self.emit_u8(0x0F);
        self.emit_u8(0x05);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── mov_rr tests ──

    fn expected_mov_r_r_rex(dst: Reg, src: Reg) -> u8 {
        X64Assembler::rex(true, src.rex_r(), false, dst.rex_b())
    }

    fn expected_mov_r_r_modrm(dst: Reg, src: Reg) -> u8 {
        X64Assembler::modrm(3, src.low3(), dst.low3())
    }

    #[test]
    fn test_mov_r_r_all_register_pairs() {
        let regs = [
            Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
            Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
            Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
            Reg::R12, Reg::R13, Reg::R14, Reg::R15,
        ];
        for &dst in &regs {
            for &src in &regs {
                let mut asm = X64Assembler::new();
                asm.mov_rr(dst, src);
                let bytes = asm.as_slice();
                let exp_rex = expected_mov_r_r_rex(dst, src);
                let exp_modrm = expected_mov_r_r_modrm(dst, src);
                assert_eq!(bytes.len(), 3);
                assert_eq!(bytes[0], exp_rex);
                assert_eq!(bytes[1], 0x89);
                assert_eq!(bytes[2], exp_modrm);
            }
        }
    }

    #[test]
    fn test_mov_r_r_rsi_r13_regression() {
        let mut asm = X64Assembler::new();
        asm.mov_rr(Reg::Rsi, Reg::R13);
        assert_eq!(asm.as_slice(), &[0x4C, 0x89, 0xEE]);
    }

    #[test]
    fn test_mov_r_r_rsi_r12_regression() {
        let mut asm = X64Assembler::new();
        asm.mov_rr(Reg::Rsi, Reg::R12);
        assert_eq!(asm.as_slice(), &[0x4C, 0x89, 0xE6]);
    }

    // ── store_state / load_state tests ──

    fn expected_store_state_rex(src: Reg) -> u8 {
        X64Assembler::rex(true, src.rex_r(), false, Reg::R15.rex_b())
    }

    fn expected_load_state_rex(dst: Reg) -> u8 {
        X64Assembler::rex(true, dst.rex_r(), false, Reg::R15.rex_b())
    }

    fn expected_state_modrm_disp8(reg: Reg) -> u8 {
        X64Assembler::modrm(1, reg.low3(), Reg::R15.low3())
    }

    #[test]
    fn test_store_state_all_registers_disp8() {
        let regs = [
            Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
            Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
            Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
            Reg::R12, Reg::R13, Reg::R14, Reg::R15,
        ];
        for &src in &regs {
            let mut asm = X64Assembler::new();
            asm.store_state(0, src);
            let bytes = asm.as_slice();
            assert_eq!(bytes[0], expected_store_state_rex(src));
            assert_eq!(bytes[1], 0x89);
            assert_eq!(bytes[2], expected_state_modrm_disp8(src));
            assert_eq!(bytes[3], 0x00);
        }
    }

    #[test]
    fn test_load_state_all_registers_disp8() {
        let regs = [
            Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
            Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
            Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
            Reg::R12, Reg::R13, Reg::R14, Reg::R15,
        ];
        for &dst in &regs {
            let mut asm = X64Assembler::new();
            asm.load_state(dst, 0);
            let bytes = asm.as_slice();
            assert_eq!(bytes[0], expected_load_state_rex(dst));
            assert_eq!(bytes[1], 0x8B);
            assert_eq!(bytes[2], expected_state_modrm_disp8(dst));
            assert_eq!(bytes[3], 0x00);
        }
    }

    #[test]
    fn test_store_state_disp32_high_register() {
        let mut asm = X64Assembler::new();
        asm.store_state(16, Reg::R14);
        assert_eq!(asm.as_slice(), &[0x4D, 0x89, 0xB7, 0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_load_state_disp32_high_register() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::R14, 16);
        assert_eq!(asm.as_slice(), &[0x4D, 0x8B, 0xB7, 0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_store_state_slot8_r14_regression() {
        let mut asm = X64Assembler::new();
        asm.store_state(8, Reg::R14);
        assert_eq!(asm.as_slice(), &[0x4D, 0x89, 0x77, 0x40]);
    }

    #[test]
    fn test_store_state_slot0_r13_regression() {
        let mut asm = X64Assembler::new();
        asm.store_state(0, Reg::R13);
        assert_eq!(asm.as_slice(), &[0x4D, 0x89, 0x6F, 0x00]);
    }

    #[test]
    fn test_load_state_slot0_rsi_regression() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::Rsi, 0);
        assert_eq!(asm.as_slice(), &[0x49, 0x8B, 0x77, 0x00]);
    }

    #[test]
    fn test_store_state_slot1() {
        let mut asm = X64Assembler::new();
        asm.store_state(1, Reg::R12);
        assert_eq!(asm.as_slice(), &[0x4D, 0x89, 0x67, 0x08]);
    }

    #[test]
    fn test_store_state_slot0x50() {
        let mut asm = X64Assembler::new();
        asm.store_state(0x50, Reg::Rax);
        assert_eq!(asm.as_slice(), &[0x49, 0x89, 0x87, 0x80, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_store_state_slot0_r14() {
        let mut asm = X64Assembler::new();
        asm.store_state(0, Reg::R14);
        assert_eq!(asm.as_slice(), &[0x4D, 0x89, 0x77, 0x00]);
    }

    #[test]
    fn test_load_state_slot1() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::Rax, 1);
        assert_eq!(asm.as_slice(), &[0x49, 0x8B, 0x47, 0x08]);
    }

    #[test]
    fn test_load_state_slot0x50() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::Rax, 0x50);
        assert_eq!(asm.as_slice(), &[0x49, 0x8B, 0x87, 0x80, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_load_state_slot0_rdi() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::Rdi, 0);
        assert_eq!(asm.as_slice(), &[0x49, 0x8B, 0x7F, 0x00]);
    }

    #[test]
    fn test_load_state_slot0_rsi() {
        let mut asm = X64Assembler::new();
        asm.load_state(Reg::Rsi, 0);
        assert_eq!(asm.as_slice(), &[0x49, 0x8B, 0x77, 0x00]);
    }

    #[test]
    fn test_store_state_rex_disp8() {
        for slot in [0x0Au8, 0x0B, 0x0E, 0x0F, 0x10, 0x18, 0x1F].iter() {
            let mut asm = X64Assembler::new();
            asm.store_state(*slot, Reg::Rax);
            assert_eq!(asm.as_slice()[0], 0x49, "slot=0x{:02X} REX.WB", slot);
        }
    }

    // ── mov_imm64 tests ──

    #[test]
    fn test_mov_imm64_rax() {
        let mut asm = X64Assembler::new();
        asm.mov_imm64(Reg::Rax, 0x123456789ABCDEF0);
        assert_eq!(asm.as_slice(), &[
            0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
        ]);
    }

    #[test]
    fn test_mov_imm64_r12_zero() {
        let mut asm = X64Assembler::new();
        asm.mov_imm64(Reg::R12, 0);
        assert_eq!(asm.as_slice(), &[0x49, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    // ── ALU tests ──

    #[test]
    fn test_add_imm_rax_5() {
        let mut asm = X64Assembler::new();
        asm.add_imm(Reg::Rax, 5);
        assert_eq!(asm.as_slice(), &[0x48, 0x83, 0xC0, 0x05]);
    }

    #[test]
    fn test_add_imm_rax_256() {
        let mut asm = X64Assembler::new();
        asm.add_imm(Reg::Rax, 256);
        assert_eq!(asm.as_slice(), &[0x48, 0x81, 0xC0, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_add_imm_r12_neg1() {
        let mut asm = X64Assembler::new();
        asm.add_imm(Reg::R12, -1);
        assert_eq!(asm.as_slice(), &[0x49, 0x83, 0xC4, 0xFF]);
    }

    #[test]
    fn test_sub_imm_rbx_7() {
        let mut asm = X64Assembler::new();
        asm.sub_imm(Reg::Rbx, 7);
        assert_eq!(asm.as_slice(), &[0x48, 0x83, 0xEB, 0x07]);
    }

    #[test]
    fn test_sub_imm_r12_0x1000() {
        let mut asm = X64Assembler::new();
        asm.sub_imm(Reg::R12, 0x1000);
        assert_eq!(asm.as_slice(), &[0x49, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_add_rr_rax_rdx() {
        let mut asm = X64Assembler::new();
        asm.add_rr(Reg::Rax, Reg::Rdx);
        assert_eq!(asm.as_slice(), &[0x48, 0x01, 0xD0]);
    }

    #[test]
    fn test_add_rr_r12_r13() {
        let mut asm = X64Assembler::new();
        asm.add_rr(Reg::R12, Reg::R13);
        assert_eq!(asm.as_slice(), &[0x4D, 0x01, 0xEC]);
    }

    #[test]
    fn test_sub_rr_rdi_rsi() {
        let mut asm = X64Assembler::new();
        asm.sub_rr(Reg::Rdi, Reg::Rsi);
        assert_eq!(asm.as_slice(), &[0x48, 0x29, 0xF7]);
    }

    #[test]
    fn test_sub_rr_r8_r9() {
        let mut asm = X64Assembler::new();
        asm.sub_rr(Reg::R8, Reg::R9);
        assert_eq!(asm.as_slice(), &[0x4D, 0x29, 0xC8]);
    }

    #[test]
    fn test_imul_rr_rax_rdx() {
        let mut asm = X64Assembler::new();
        asm.imul_rr(Reg::Rax, Reg::Rdx);
        assert_eq!(asm.as_slice(), &[0x48, 0x0F, 0xAF, 0xC2]);
    }

    #[test]
    fn test_imul_rr_r12_r13() {
        let mut asm = X64Assembler::new();
        asm.imul_rr(Reg::R12, Reg::R13);
        assert_eq!(asm.as_slice(), &[0x4D, 0x0F, 0xAF, 0xE5]);
    }

    #[test]
    fn test_cmp_rr_rax_rbx() {
        let mut asm = X64Assembler::new();
        asm.cmp_rr(Reg::Rax, Reg::Rbx);
        assert_eq!(asm.as_slice(), &[0x48, 0x39, 0xD8]);
    }

    #[test]
    fn test_cmp_rr_r8_r9() {
        let mut asm = X64Assembler::new();
        asm.cmp_rr(Reg::R8, Reg::R9);
        assert_eq!(asm.as_slice(), &[0x4D, 0x39, 0xC8]);
    }

    // ── Push/Pop tests ──

    #[test]
    fn test_push_pop_low_reg() {
        let mut asm = X64Assembler::new();
        asm.push(Reg::Rbx);
        assert_eq!(asm.as_slice(), &[0x53]);
        let mut asm = X64Assembler::new();
        asm.pop(Reg::Rbx);
        assert_eq!(asm.as_slice(), &[0x5B]);
    }

    #[test]
    fn test_push_pop_high_reg() {
        let mut asm = X64Assembler::new();
        asm.push(Reg::R12);
        assert_eq!(asm.as_slice(), &[0x41, 0x54]);
        let mut asm = X64Assembler::new();
        asm.pop(Reg::R12);
        assert_eq!(asm.as_slice(), &[0x41, 0x5C]);
    }

    #[test]
    fn test_push_pop_rsi() {
        let mut asm = X64Assembler::new();
        asm.push(Reg::Rsi);
        assert_eq!(asm.as_slice(), &[0x56]);
        let mut asm = X64Assembler::new();
        asm.pop(Reg::Rsi);
        assert_eq!(asm.as_slice(), &[0x5E]);
    }

    #[test]
    fn test_push_pop_rcx() {
        let mut asm = X64Assembler::new();
        asm.push(Reg::Rcx);
        assert_eq!(asm.as_slice(), &[0x51]);
        let mut asm = X64Assembler::new();
        asm.pop(Reg::Rcx);
        assert_eq!(asm.as_slice(), &[0x59]);
    }

    // ── Ret / Rep movsb test ──

    #[test]
    fn test_ret() {
        let mut asm = X64Assembler::new();
        asm.ret();
        assert_eq!(asm.as_slice(), &[0xC3]);
    }

    #[test]
    fn test_rep_movsb() {
        let mut asm = X64Assembler::new();
        asm.rep_movsb();
        assert_eq!(asm.as_slice(), &[0xF3, 0xA4]);
    }

    // ── Jumps / Calls ──

    #[test]
    fn test_call_rel32_placeholder() {
        let mut asm = X64Assembler::new();
        asm.call_rel32_placeholder();
        assert_eq!(asm.as_slice(), &[0xE8, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_jmp_rel32_placeholder() {
        let mut asm = X64Assembler::new();
        asm.jmp_rel32_placeholder();
        assert_eq!(asm.as_slice(), &[0xE9, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_jcc_rel32_placeholder_je() {
        let mut asm = X64Assembler::new();
        asm.jcc_rel32_placeholder(4); // je
        assert_eq!(asm.as_slice(), &[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_jcc_rel32_placeholder_jl() {
        let mut asm = X64Assembler::new();
        asm.jcc_rel32_placeholder(12); // jl
        assert_eq!(asm.as_slice(), &[0x0F, 0x8C, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_jmp_rel8() {
        let mut asm = X64Assembler::new();
        asm.jmp_rel8(-16);
        assert_eq!(asm.as_slice(), &[0xEB, 0xF0]);
    }

    #[test]
    fn test_jcc_rel8() {
        let mut asm = X64Assembler::new();
        asm.jcc_rel8(4, 8); // je +8
        assert_eq!(asm.as_slice(), &[0x74, 0x08]);
    }

    // ── LEA / special ──

    #[test]
    fn test_lea_rsi_rip() {
        let mut asm = X64Assembler::new();
        asm.lea_rsi_rip(0x1234);
        assert_eq!(asm.as_slice(), &[0x48, 0x8D, 0x35, 0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_rsp_sib32() {
        let mut asm = X64Assembler::new();
        asm.lea_rsp_sib32(Reg::R15, 0x800);
        // 4C 8D BC 24 00 08 00 00
        assert_eq!(asm.as_slice(), &[0x4C, 0x8D, 0xBC, 0x24, 0x00, 0x08, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_rsp_sib32_rsi() {
        let mut asm = X64Assembler::new();
        asm.lea_rsp_sib32(Reg::Rsi, 0x100);
        // 48 8D B4 24 00 01 00 00
        assert_eq!(asm.as_slice(), &[0x48, 0x8D, 0xB4, 0x24, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_rsp_sib32_rdi() {
        let mut asm = X64Assembler::new();
        asm.lea_rsp_sib32(Reg::Rdi, 0x100);
        // 48 8D BC 24 00 01 00 00
        assert_eq!(asm.as_slice(), &[0x48, 0x8D, 0xBC, 0x24, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_state() {
        let mut asm = X64Assembler::new();
        asm.lea_state(Reg::Rdi, 0);
        // R15 has rex_b=true: 49 8D BF 00 00 00 00
        assert_eq!(asm.as_slice(), &[0x49, 0x8D, 0xBF, 0x00, 0x00, 0x00, 0x00]);
    }

    // ── Memory operations ──

    #[test]
    fn test_mov_qword_rsp_disp() {
        let mut asm = X64Assembler::new();
        asm.mov_qword_rsp_disp(0x20, 3);
        assert_eq!(asm.as_slice(), &[0x48, 0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_mov_byte_mem_reg() {
        let mut asm = X64Assembler::new();
        asm.mov_byte_mem_reg(Reg::Rdi, Reg::Rax); // mov [rdi], al
        assert_eq!(asm.as_slice(), &[0x88, 0x07]);
    }

    #[test]
    fn test_mov_reg_byte_mem() {
        let mut asm = X64Assembler::new();
        asm.mov_reg_byte_mem(Reg::Rax, Reg::Rsi); // mov al, [rsi]
        assert_eq!(asm.as_slice(), &[0x8A, 0x06]);
    }

    #[test]
    fn test_mov_byte_mem_imm() {
        let mut asm = X64Assembler::new();
        asm.mov_byte_mem_imm(Reg::Rsi, 0); // mov byte [rsi], 0
        assert_eq!(asm.as_slice(), &[0xC6, 0x06, 0x00]);
    }

    #[test]
    fn test_cmp_byte_mem_imm() {
        let mut asm = X64Assembler::new();
        asm.cmp_byte_mem_imm(Reg::Rsi, 0x20); // cmp byte [rsi], 0x20
        assert_eq!(asm.as_slice(), &[0x80, 0x3E, 0x20]);
    }

    #[test]
    fn test_test_r8_r8() {
        let mut asm = X64Assembler::new();
        asm.test_r8_r8(Reg::Rax, Reg::Rax); // test al, al
        assert_eq!(asm.as_slice(), &[0x84, 0xC0]);
    }

    #[test]
    fn test_inc() {
        let mut asm = X64Assembler::new();
        asm.inc(Reg::Rsi);
        assert_eq!(asm.as_slice(), &[0x48, 0xFF, 0xC6]);
    }

    #[test]
    fn test_dec() {
        let mut asm = X64Assembler::new();
        asm.dec(Reg::Rsi);
        assert_eq!(asm.as_slice(), &[0x48, 0xFF, 0xCE]);
    }

    // ── IAT / Placeholder tests ──

    #[test]
    fn test_call_iat_thunk() {
        let mut asm = X64Assembler::new();
        asm.call_iat_thunk(5); // CloseHandle
        assert_eq!(asm.as_slice(), &[0xFF, 0x15, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_rdi_rip_placeholder() {
        let mut asm = X64Assembler::new();
        asm.lea_rdi_rip_placeholder();
        assert_eq!(asm.as_slice(), &[0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_lea_rcx_rip_placeholder() {
        let mut asm = X64Assembler::new();
        asm.lea_rcx_rip_placeholder();
        assert_eq!(asm.as_slice(), &[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_mov_rsi_rdi_ptr() {
        let mut asm = X64Assembler::new();
        asm.mov_rsi_rdi_ptr();
        assert_eq!(asm.as_slice(), &[0x48, 0x8B, 0x37]);
    }

    #[test]
    fn test_movzx_eax_byte_disp() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_disp(Reg::Rdx, 0x10);
        assert_eq!(asm.as_slice(), &[0x0F, 0xB6, 0x42, 0x10]);
    }

    #[test]
    fn test_movzx_eax_byte_disp32() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_disp(Reg::Rdx, 0x100);
        assert_eq!(asm.as_slice(), &[0x0F, 0xB6, 0x82, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_shadow_frame() {
        let mut asm = X64Assembler::new();
        asm.shadow_frame();
        assert_eq!(asm.as_slice(), &[0x48, 0x83, 0xEC, 0x20]);
    }

    #[test]
    fn test_shadow_ret() {
        let mut asm = X64Assembler::new();
        asm.shadow_ret();
        assert_eq!(asm.as_slice(), &[0x48, 0x83, 0xC4, 0x20]);
    }

    #[test]
    fn test_syscall() {
        let mut asm = X64Assembler::new();
        asm.syscall();
        assert_eq!(asm.as_slice(), &[0x0F, 0x05]);
    }

    #[test]
    fn test_chain_mov_imm64_add_imm_ret() {
        let mut asm = X64Assembler::new();
        asm.mov_imm64(Reg::Rax, 42);
        asm.add_imm(Reg::Rax, 1);
        asm.ret();
        assert_eq!(asm.as_slice(), &[
            0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0x83, 0xC0, 0x01,
            0xC3,
        ]);
    }

    #[test]
    fn test_write_at() {
        let mut asm = X64Assembler::new();
        asm.call_rel32_placeholder(); // E8 00 00 00 00 at bytes 0-4
        asm.jmp_rel32_placeholder();  // E9 00 00 00 00 at bytes 5-9
        asm.write_at(1, &0x1234i32.to_le_bytes());
        asm.write_at(6, &(-0x100i32).to_le_bytes());
        assert_eq!(asm.as_slice(), &[
            0xE8, 0x34, 0x12, 0x00, 0x00,
            0xE9, 0x00, 0xFF, 0xFF, 0xFF,
        ]);
    }

    #[test]
    fn test_push_pop_all_16() {
        let regs = [
            Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
            Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
            Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
            Reg::R12, Reg::R13, Reg::R14, Reg::R15,
        ];
        for &r in &regs {
            // push
            let mut a = X64Assembler::new();
            a.push(r);
            assert!(!a.as_slice().is_empty(), "push {:?} emitted nothing", r);
            assert!(a.as_slice().len() <= 2, "push {:?} > 2 bytes", r);
            // pop
            let mut b = X64Assembler::new();
            b.pop(r);
            assert!(!b.as_slice().is_empty(), "pop {:?} emitted nothing", r);
            assert!(b.as_slice().len() <= 2, "pop {:?} > 2 bytes", r);
        }
    }

    // ── Memory operation tests ──

    #[test]
    fn test_load_mem_rdi_rsi_disp8() {
        let mut asm = X64Assembler::new();
        asm.load_mem(Reg::Rdi, Reg::Rsi, 4);
        // 48 8B 7E 04
        assert_eq!(asm.as_slice(), &[0x48, 0x8B, 0x7E, 0x04]);
    }

    #[test]
    fn test_load_mem_rsi_rdi() {
        let mut asm = X64Assembler::new();
        asm.load_mem(Reg::Rsi, Reg::Rdi, 0);
        // 48 8B 37
        assert_eq!(asm.as_slice(), &[0x48, 0x8B, 0x37]);
    }

    #[test]
    fn test_load_mem_r13_r12_disp32() {
        let mut asm = X64Assembler::new();
        asm.load_mem(Reg::R13, Reg::R12, 0x1000);
        // REX.WB = 0x4D, 0x8B, ModRM mod=10 reg=101 rm=100=SIB, SIB=0x24=[RSP], disp32 0x1000
        assert_eq!(asm.as_slice(), &[0x4D, 0x8B, 0xAC, 0x24, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_mov_qword_rsp_disp_default() {
        let mut asm = X64Assembler::new();
        asm.mov_qword_rsp_disp(0x20, 3);
        // 48 C7 44 24 20 03 00 00 00
        assert_eq!(asm.as_slice(), &[0x48, 0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_mov_qword_rsp_disp_neg() {
        let mut asm = X64Assembler::new();
        asm.mov_qword_rsp_disp(0x28, -1);
        // 48 C7 44 24 28 FF FF FF FF
        assert_eq!(asm.as_slice(), &[0x48, 0xC7, 0x44, 0x24, 0x28, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_movzx_eax_byte_mem_rdx_disp8() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_mem(Reg::Rdx, 0);
        // 0F B6 42 00 — disp8=0
        assert_eq!(asm.as_slice(), &[0x0F, 0xB6, 0x42, 0x00]);
    }

    #[test]
    fn test_movzx_eax_byte_mem_rdx_disp8_neg() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_mem(Reg::Rdx, -128);
        // 0F B6 42 80
        assert_eq!(asm.as_slice(), &[0x0F, 0xB6, 0x42, 0x80]);
    }

    #[test]
    fn test_movzx_eax_byte_mem_rdx_disp32() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_mem(Reg::Rdx, 0x100);
        // 0F B6 82 00 01 00 00
        assert_eq!(asm.as_slice(), &[0x0F, 0xB6, 0x82, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_movzx_eax_byte_mem_r10_disp8() {
        let mut asm = X64Assembler::new();
        asm.movzx_eax_byte_mem(Reg::R10, 4);
        // REX.B: 41, 0F B6, ModRM mod=01 reg=000 rm=010 = 0x42, disp8=4
        // R10 low3 = 2, same as RDX low3, so ModRM is same but with REX.B prefix
        assert_eq!(asm.as_slice(), &[0x41, 0x0F, 0xB6, 0x42, 0x04]);
    }

    #[test]
    fn test_label_fixup_loop() {
        let mut a = X64Assembler::new();
        let loop_start = a.alloc_label();
        a.set_label(loop_start);   // pos 0
        a.emit_u8(0xAA);           // pos 0
        a.emit_u8(0xBB);           // pos 1
        let done = a.alloc_label();
        a.jcc_rel8_label(4, done); // jz .done: now rel32 (6B)
        a.emit_u8(0xCC);           // pos 8
        a.jmp_rel8_label(loop_start); // jmp back to .loop_start: now rel32 (5B)
        a.set_label(done);         // pos 14
        a.emit_u8(0xDD);           // pos 14
        a.resolve_fixups();
        // Expected:
        //   pos 0: AA
        //   pos 1: BB
        //   pos 2: 0F 84 06 00 00 00  (jz .done at pos 14: disp = 14 - 8 = 6)
        //   pos 8: CC
        //   pos 9: E9 F2 FF FF FF     (jmp .loop_start at pos 0: disp = 0 - 14 = -14)
        //   pos 14: DD
        assert_eq!(a.as_slice(), &[0xAA, 0xBB, 0x0F, 0x84, 0x06, 0x00, 0x00, 0x00, 0xCC, 0xE9, 0xF2, 0xFF, 0xFF, 0xFF, 0xDD]);
    }

    #[test]
    fn test_label_fixup_two_forward_jumps() {
        let mut a = X64Assembler::new();
        let skip1 = a.alloc_label();
        let skip2 = a.alloc_label();
        a.emit_u8(0xAA);           // pos 0
        a.jcc_rel8_label(5, skip1); // jne .skip1: now rel32 (6B)
        a.emit_u8(0xBB);           // pos 7
        a.set_label(skip1);        // pos 8
        a.jcc_rel8_label(4, skip2); // je .skip2: now rel32 (6B)
        a.emit_u8(0xCC);           // pos 14
        a.set_label(skip2);        // pos 15
        a.emit_u8(0xDD);           // pos 15
        a.resolve_fixups();
        //   pos 0: AA
        //   pos 1: 0F 85 01 00 00 00  (jne .skip1 at pos 8: disp = 8 - 7 = 1)
        //   pos 7: BB
        //   pos 8: 0F 84 01 00 00 00  (je .skip2 at pos 15: disp = 15 - 14 = 1)
        //   pos 14: CC
        //   pos 15: DD
        assert_eq!(a.as_slice(), &[0xAA, 0x0F, 0x85, 0x01, 0x00, 0x00, 0x00, 0xBB, 0x0F, 0x84, 0x01, 0x00, 0x00, 0x00, 0xCC, 0xDD]);
    }
}
