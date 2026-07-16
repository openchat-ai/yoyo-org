use crate::types::{FixedBuf, IsaResult, Reg};

fn rex(w: bool, r: bool, x: bool, b: bool) -> u8 {
    0x40 | (if w { 0x08 } else { 0 })
         | (if r { 0x04 } else { 0 })
         | (if x { 0x02 } else { 0 })
         | (if b { 0x01 } else { 0 })
}

fn modrm(mod_: u8, reg: u8, rm: u8) -> u8 {
    (mod_ << 6) | ((reg & 7) << 3) | (rm & 7)
}

const STATE_BASE: Reg = Reg::R15;

pub fn movabs<const N: usize>(buf: &mut FixedBuf<N>, reg: Reg, imm: u64) -> IsaResult<()> {
    buf.push(rex(true, false, false, reg.rex_b()))?;
    buf.push(0xB8 | reg.low3())?;
    buf.extend(&imm.to_le_bytes())
}

pub fn add_imm<const N: usize>(buf: &mut FixedBuf<N>, reg: Reg, imm: i32) -> IsaResult<()> {
    let rm = reg.low3();
    if imm >= -128 && imm <= 127 {
        buf.push(rex(true, false, false, reg.rex_b()))?;
        buf.push(0x83)?;
        buf.push(modrm(3, 0, rm))?;
        buf.push(imm as u8)
    } else {
        buf.push(rex(true, false, false, reg.rex_b()))?;
        buf.push(0x81)?;
        buf.push(modrm(3, 0, rm))?;
        buf.extend(&imm.to_le_bytes())
    }
}

pub fn sub_imm<const N: usize>(buf: &mut FixedBuf<N>, reg: Reg, imm: i32) -> IsaResult<()> {
    let rm = reg.low3();
    if imm >= -128 && imm <= 127 {
        buf.push(rex(true, false, false, reg.rex_b()))?;
        buf.push(0x83)?;
        buf.push(modrm(3, 5, rm))?;
        buf.push(imm as u8)
    } else {
        buf.push(rex(true, false, false, reg.rex_b()))?;
        buf.push(0x81)?;
        buf.push(modrm(3, 5, rm))?;
        buf.extend(&imm.to_le_bytes())
    }
}

pub fn add_reg<const N: usize>(buf: &mut FixedBuf<N>, dst: Reg, src: Reg) -> IsaResult<()> {
    buf.push(rex(true, src.rex_r(), false, dst.rex_b()))?;
    buf.push(0x01)?;
    buf.push(modrm(3, src.low3(), dst.low3()))
}

pub fn sub_reg<const N: usize>(buf: &mut FixedBuf<N>, dst: Reg, src: Reg) -> IsaResult<()> {
    buf.push(rex(true, src.rex_r(), false, dst.rex_b()))?;
    buf.push(0x29)?;
    buf.push(modrm(3, src.low3(), dst.low3()))
}

pub fn mul_reg<const N: usize>(buf: &mut FixedBuf<N>, dst: Reg, src: Reg) -> IsaResult<()> {
    buf.push(rex(true, dst.rex_r(), false, src.rex_b()))?;
    buf.push(0x0F)?;
    buf.push(0xAF)?;
    buf.push(modrm(3, dst.low3(), src.low3()))
}

pub fn cmp_reg<const N: usize>(buf: &mut FixedBuf<N>, reg1: Reg, reg2: Reg) -> IsaResult<()> {
    buf.push(rex(true, reg2.rex_r(), false, reg1.rex_b()))?;
    buf.push(0x39)?;
    buf.push(modrm(3, reg2.low3(), reg1.low3()))
}

pub fn mov_r_r<const N: usize>(buf: &mut FixedBuf<N>, dst: Reg, src: Reg) -> IsaResult<()> {
    buf.push(rex(true, src.rex_r(), false, dst.rex_b()))?;
    buf.push(0x89)?;
    buf.push(modrm(3, src.low3(), dst.low3()))
}

pub fn load_state<const N: usize>(buf: &mut FixedBuf<N>, slot: u8, dst: Reg) -> IsaResult<()> {
    let offset = (slot as u16) * 8;
    buf.push(rex(true, dst.rex_r(), false, STATE_BASE.rex_b()))?;
    buf.push(0x8B)?;
    if offset <= 127 {
        buf.push(modrm(1, dst.low3(), STATE_BASE.low3()))?;
        buf.push(offset as u8)
    } else {
        buf.push(modrm(2, dst.low3(), STATE_BASE.low3()))?;
        buf.extend(&(offset as u32).to_le_bytes())
    }
}

/// Emit `mov qword [rsp + disp8], imm32` — write a 32-bit sign-extended
/// immediate into the Win64 shadow/stack-args area. Used to populate the
/// 5th+ stack-passed arguments to kernel32 calls (CreateFileA needs 3).
///
/// Encoding: 48 C7 44 24 dd ii ii ii ii  (10 bytes)
pub fn mov_qword_rsp_disp_imm32<const N: usize>(buf: &mut FixedBuf<N>, disp: u8, imm: i32) -> IsaResult<()> {
    buf.push(0x48)?;              // REX.W
    buf.push(0xC7)?;              // MOV r/m64, imm32
    buf.push(0x44)?;              // ModRM: mod=01 reg=0 r/m=100 (SIB)
    buf.push(0x24)?;              // SIB: rsp
    buf.push(disp)?;              // disp8
    buf.extend(&imm.to_le_bytes()) // imm32
}

pub fn store_state<const N: usize>(buf: &mut FixedBuf<N>, slot: u8, src: Reg) -> IsaResult<()> {
    let offset = (slot as u16) * 8;
    buf.push(rex(true, src.rex_r(), false, STATE_BASE.rex_b()))?;
    buf.push(0x89)?;
    if offset <= 127 {
        buf.push(modrm(1, src.low3(), STATE_BASE.low3()))?;
        buf.push(offset as u8)?;
    } else {
        buf.push(modrm(2, src.low3(), STATE_BASE.low3()))?;
        buf.extend(&(offset as u32).to_le_bytes())?;
    }
    Ok(())
}

pub fn call_rel32<const N: usize>(buf: &mut FixedBuf<N>, offset: i32) -> IsaResult<()> {
    buf.push(0xE8)?;
    buf.extend(&offset.to_le_bytes())
}

pub fn jmp_rel32<const N: usize>(buf: &mut FixedBuf<N>, offset: i32) -> IsaResult<()> {
    buf.push(0xE9)?;
    buf.extend(&offset.to_le_bytes())
}

pub fn jcc_rel32<const N: usize>(buf: &mut FixedBuf<N>, cc: u8, offset: i32) -> IsaResult<()> {
    buf.push(0x0F)?;
    buf.push(0x80 | (cc & 0x0F))?;
    buf.extend(&offset.to_le_bytes())
}

pub fn lea_rsi_rip<const N: usize>(buf: &mut FixedBuf<N>, disp: i32) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0x8D)?;
    buf.push(0x35)?;
    buf.extend(&disp.to_le_bytes())
}

/// v0.4: Emit `lea reg, [r15 + slot*8]` for runtime-path str_slot support.
/// Always disp32 (7B). Caller chooses `reg` (rcx for CreateFileA args, rdi for libyoyo_open).
pub fn lea_reg_r15<const N: usize>(buf: &mut FixedBuf<N>, reg: Reg, slot: u16) -> IsaResult<()> {
    let offset = (slot as u32) * 8;
    buf.push(rex(true, reg.rex_r(), false, STATE_BASE.rex_b()))?;
    buf.push(0x8D)?; // LEA
    buf.push(modrm(2, reg.low3(), STATE_BASE.low3()))?;
    buf.extend(&offset.to_le_bytes())
}

pub fn rep_movsb<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0xF3)?;
    buf.push(0xA4)
}

pub fn ret<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0xC3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_movabs_rax() {
        let mut buf: FixedBuf<16> = FixedBuf::new();
        movabs(&mut buf, Reg::Rax, 0x123456789ABCDEF0).unwrap();
        assert_eq!(buf.as_slice(), &[
            0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
        ]);
    }

    #[test]
    fn test_movabs_r12() {
        let mut buf: FixedBuf<16> = FixedBuf::new();
        movabs(&mut buf, Reg::R12, 0).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_add_imm_rax_5() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        add_imm(&mut buf, Reg::Rax, 5).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x83, 0xC0, 0x05]);
    }

    #[test]
    fn test_add_imm_rax_256() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        add_imm(&mut buf, Reg::Rax, 256).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x81, 0xC0, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_add_imm_r12_neg1() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        add_imm(&mut buf, Reg::R12, -1).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x83, 0xC4, 0xFF]);
    }

    #[test]
    fn test_sub_imm_rbx_7() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        sub_imm(&mut buf, Reg::Rbx, 7).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x83, 0xEB, 0x07]);
    }

    #[test]
    fn test_sub_imm_r12_0x1000() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        sub_imm(&mut buf, Reg::R12, 0x1000).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_add_reg_rax_rdx() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        add_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x01, 0xD0]);
    }

    #[test]
    fn test_add_reg_r12_r13() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        add_reg(&mut buf, Reg::R12, Reg::R13).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x01, 0xEC]);
    }

    #[test]
    fn test_sub_reg_rdi_rsi() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        sub_reg(&mut buf, Reg::Rdi, Reg::Rsi).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x29, 0xF7]);
    }

    #[test]
    fn test_sub_reg_r8_r9() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        sub_reg(&mut buf, Reg::R8, Reg::R9).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x29, 0xC8]);
    }

    #[test]
    fn test_mul_reg_rax_rdx() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        mul_reg(&mut buf, Reg::Rax, Reg::Rdx).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x0F, 0xAF, 0xC2]);
    }

    #[test]
    fn test_mul_reg_r12_r13() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        mul_reg(&mut buf, Reg::R12, Reg::R13).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x0F, 0xAF, 0xE5]);
    }

    #[test]
    fn test_cmp_reg_rax_rbx() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        cmp_reg(&mut buf, Reg::Rax, Reg::Rbx).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x39, 0xD8]);
    }

    #[test]
    fn test_cmp_reg_r8_r9() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        cmp_reg(&mut buf, Reg::R8, Reg::R9).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x39, 0xC8]);
    }

    #[test]
    fn test_mov_r_r_rax_rbx() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        mov_r_r(&mut buf, Reg::Rax, Reg::Rbx).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x89, 0xD8]);
    }

    #[test]
    fn test_mov_r_r_r8_r9() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        mov_r_r(&mut buf, Reg::R8, Reg::R9).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x89, 0xC8]);
    }

    #[test]
    fn test_load_state_slot1() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        load_state(&mut buf, 0x01, Reg::Rax).unwrap();
        // R15 low3=7, REX.WB=0x49, mov rax,[r15+8] = 49 8B 47 08
        assert_eq!(buf.as_slice(), &[0x49, 0x8B, 0x47, 0x08]);
    }

    #[test]
    fn test_load_state_slot0x50() {
        let mut buf: FixedBuf<16> = FixedBuf::new();
        load_state(&mut buf, 0x50, Reg::Rax).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x8B, 0x87, 0x80, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_load_state_slot0_rdi() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        load_state(&mut buf, 0x00, Reg::Rdi).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x8B, 0x7F, 0x00]);
    }

    #[test]
    fn test_load_state_slot0_rsi() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        load_state(&mut buf, 0x00, Reg::Rsi).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x8B, 0x77, 0x00]);
    }

    #[test]
    fn test_store_state_slot1() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        store_state(&mut buf, 0x01, Reg::R12).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x89, 0x67, 0x08]);
    }

    #[test]
    fn test_store_state_slot0x50() {
        let mut buf: FixedBuf<16> = FixedBuf::new();
        store_state(&mut buf, 0x50, Reg::Rax).unwrap();
        assert_eq!(buf.as_slice(), &[0x49, 0x89, 0x87, 0x80, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_store_state_slot0_r14() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        store_state(&mut buf, 0x00, Reg::R14).unwrap();
        assert_eq!(buf.as_slice(), &[0x4D, 0x89, 0x77, 0x00]);
    }

    #[test]
    fn test_call_rel32() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        call_rel32(&mut buf, 0x1234).unwrap();
        assert_eq!(buf.as_slice(), &[0xE8, 0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn test_call_rel32_negative() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        call_rel32(&mut buf, -0x100).unwrap();
        assert_eq!(buf.as_slice(), &[0xE8, 0x00, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_jmp_rel32() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        jmp_rel32(&mut buf, 0x5678).unwrap();
        assert_eq!(buf.as_slice(), &[0xE9, 0x78, 0x56, 0x00, 0x00]);
    }

    #[test]
    fn test_jcc_rel32_je() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        jcc_rel32(&mut buf, 4, 0x100).unwrap();
        assert_eq!(buf.as_slice(), &[0x0F, 0x84, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_jcc_rel32_jl() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        jcc_rel32(&mut buf, 12, -0x80).unwrap();
        assert_eq!(buf.as_slice(), &[0x0F, 0x8C, 0x80, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_lea_rsi_rip() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        lea_rsi_rip(&mut buf, 0x1234).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x8D, 0x35, 0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn test_rep_movsb() {
        let mut buf: FixedBuf<4> = FixedBuf::new();
        rep_movsb(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), &[0xF3, 0xA4]);
    }

    #[test]
    fn test_ret() {
        let mut buf: FixedBuf<4> = FixedBuf::new();
        ret(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), &[0xC3]);
    }

    #[test]
    fn test_store_state_rex_disp8() {
        // Each SET state[slot]=val emit must start with REX.WB (0x49)
        // because RAX -> [r15+disp8] needs both W (64-bit) and B (R15 is in [r8-r15])
        for slot in [0x0Au8, 0x0B, 0x0E, 0x0F, 0x10, 0x18, 0x1F].iter() {
            let mut buf: FixedBuf<16> = FixedBuf::new();
            store_state(&mut buf, *slot, Reg::Rax).unwrap();
            let bytes = buf.as_slice();
            assert_eq!(bytes[0], 0x49, "store_state(slot=0x{:02X}) missing REX.WB prefix, got {:02X?}", slot, bytes);
        }
    }

    #[test]
    fn test_overflow_returns_error() {
        let mut buf: FixedBuf<1> = FixedBuf::new();
        assert!(ret(&mut buf).is_ok());
        assert!(ret(&mut buf).is_err());
    }

    #[test]
    fn test_chain_movabs_add_imm_ret() {
        let mut buf: FixedBuf<32> = FixedBuf::new();
        movabs(&mut buf, Reg::Rax, 42).unwrap();
        add_imm(&mut buf, Reg::Rax, 1).unwrap();
        ret(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), &[
            0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0x83, 0xC0, 0x01,
            0xC3,
        ]);
    }
}
