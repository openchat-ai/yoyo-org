use std::fmt;

pub struct FixedBuf<const N: usize> {
    data: Vec<u8>,
    pos: usize,
}

impl<const N: usize> FixedBuf<N> {
    pub fn new() -> Self {
        let mut data = Vec::with_capacity(N);
        data.resize(N, 0u8);
        FixedBuf { data, pos: 0 }
    }

    pub fn push(&mut self, byte: u8) -> IsaResult<()> {
        if self.pos >= N {
            return Err(IsaError::BufferFull { needed: 1, remaining: 0 });
        }
        self.data[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }

    pub fn extend(&mut self, bytes: &[u8]) -> IsaResult<()> {
        let remaining = N - self.pos;
        if bytes.len() > remaining {
            return Err(IsaError::BufferFull { needed: bytes.len(), remaining });
        }
        self.data[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        N - self.pos
    }

    pub fn clear(&mut self) {
        self.pos = 0;
    }

    /// Overwrite 4 bytes at a previously-written offset (for fixup pass).
    pub fn write_i32_at(&mut self, offset: usize, val: i32) -> IsaResult<()> {
        if offset + 4 > self.pos {
            return Err(IsaError::BufferFull { needed: offset + 4 - self.pos, remaining: 0 });
        }
        self.data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaError {
    BufferFull { needed: usize, remaining: usize },
    InvalidRegister { reg: u8 },
    InvalidSlot { slot: u8 },
    InvalidOpcode { opcode: u16 },
    InvalidOperand { desc: &'static str },
}

impl fmt::Display for IsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsaError::BufferFull { needed, remaining } => {
                write!(f, "buffer full: needed {needed}, remaining {remaining}")
            }
            IsaError::InvalidRegister { reg } => write!(f, "invalid register: {reg:#x}"),
            IsaError::InvalidSlot { slot } => write!(f, "invalid slot: {slot:#x}"),
            IsaError::InvalidOpcode { opcode } => write!(f, "invalid opcode: {opcode:#06x}"),
            IsaError::InvalidOperand { desc } => write!(f, "invalid operand: {desc}"),
        }
    }
}

pub type IsaResult<T> = Result<T, IsaError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
}

impl Reg {
    pub fn code(self) -> u8 {
        match self {
            Reg::Rax => 0,  Reg::Rcx => 1,  Reg::Rdx => 2,  Reg::Rbx => 3,
            Reg::Rsp => 4,  Reg::Rbp => 5,  Reg::Rsi => 6,  Reg::Rdi => 7,
            Reg::R8 => 8,   Reg::R9 => 9,   Reg::R10 => 10, Reg::R11 => 11,
            Reg::R12 => 12, Reg::R13 => 13, Reg::R14 => 14, Reg::R15 => 15,
        }
    }

    pub fn low3(self) -> u8 {
        self.code() & 7
    }

    pub fn rex_r(self) -> bool {
        self.code() >= 8
    }

    pub fn rex_b(self) -> bool {
        self.code() >= 8
    }
}

pub struct Budget {
    remaining: u32,
}

impl Budget {
    pub fn new(limit: u32) -> Self {
        Budget { remaining: limit }
    }

    pub fn decrement(&mut self) -> IsaResult<()> {
        if self.remaining == 0 {
            return Err(IsaError::InvalidOperand { desc: "budget exhausted" });
        }
        self.remaining -= 1;
        Ok(())
    }

    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_buf_push_and_extend() {
        let mut buf: FixedBuf<16> = FixedBuf::new();
        buf.push(0x48).unwrap();
        buf.push(0x89).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x89]);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.remaining(), 14);
    }

    #[test]
    fn fixed_buf_extend_slice() {
        let mut buf: FixedBuf<8> = FixedBuf::new();
        buf.extend(&[0x48, 0x83, 0xC0, 0x05]).unwrap();
        assert_eq!(buf.as_slice(), &[0x48, 0x83, 0xC0, 0x05]);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn fixed_buf_clear() {
        let mut buf: FixedBuf<4> = FixedBuf::new();
        buf.push(1).unwrap();
        buf.push(2).unwrap();
        assert_eq!(buf.len(), 2);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining(), 4);
    }

    #[test]
    fn fixed_buf_buffer_full() {
        let mut buf: FixedBuf<2> = FixedBuf::new();
        buf.push(1).unwrap();
        buf.push(2).unwrap();
        match buf.push(3) {
            Err(IsaError::BufferFull { .. }) => {}
            other => panic!("expected BufferFull, got {other:?}"),
        }
    }

    #[test]
    fn fixed_buf_extend_overflow() {
        let mut buf: FixedBuf<2> = FixedBuf::new();
        match buf.extend(&[1, 2, 3]) {
            Err(IsaError::BufferFull { needed: 3, remaining: 2 }) => {}
            other => panic!("expected BufferFull(3, 2), got {other:?}"),
        }
    }

    #[test]
    fn reg_codes() {
        assert_eq!(Reg::Rax.code(), 0);
        assert_eq!(Reg::R13.code(), 13);
        assert_eq!(Reg::R15.code(), 15);
        assert_eq!(Reg::Rax.low3(), 0);
        assert_eq!(Reg::R13.low3(), 5);
        assert_eq!(Reg::R15.low3(), 7);
        assert!(!Reg::Rax.rex_r());
        assert!(Reg::R8.rex_r());
        assert!(Reg::R8.rex_b());
        assert!(Reg::R13.rex_b());
    }

    #[test]
    fn budget_decrement() {
        let mut b = Budget::new(3);
        assert_eq!(b.remaining(), 3);
        b.decrement().unwrap();
        assert_eq!(b.remaining(), 2);
        b.decrement().unwrap();
        b.decrement().unwrap();
        assert_eq!(b.remaining(), 0);
        assert!(b.decrement().is_err());
    }

    #[test]
    fn budget_zero_limit() {
        let mut b = Budget::new(0);
        assert!(b.decrement().is_err());
    }

    #[test]
    fn isa_error_display() {
        let e = IsaError::BufferFull { needed: 5, remaining: 0 };
        let s = e.to_string();
        assert!(s.contains("buffer full"));
        assert!(s.contains("5"));

        let e = IsaError::InvalidOpcode { opcode: 0x1234 };
        let s = e.to_string();
        assert!(s.contains("0x1234"));
    }
}
