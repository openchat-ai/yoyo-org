use crate::isa;

/// Re-export so existing code using `crate::tir::TirOp` still compiles.
pub use crate::isa::TirOp;

/// Maps jcc index to x64 second opcode byte (used by disasm.rs).
pub const JCC_TABLE: [u8; 10] =
    [0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F, 0x82, 0x83, 0x86, 0x87];

/// Human-readable mnemonic per conditional-jump index.
pub const JCC_MNEMONIC: [&str; 10] =
    ["je", "jne", "jl", "jge", "jle", "jg", "jb", "jae", "jbe", "ja"];

/// Map a yoyo jump opcode to its JCC_TABLE index.
pub fn jcc_index_for_opcode(op: u8) -> Option<u8> {
    match op {
        0x72 => Some(1),
        0x73 => Some(2),
        0x74 => Some(3),
        0x75 => Some(4),
        0x76 => Some(5),
        0x77 => Some(6),
        0x78 => Some(7),
        0x79 => Some(8),
        0x7A => Some(9),
        0x82 => Some(2),
        0x83 => Some(5),
        _ => None,
    }
}

/// One lowered TIR instruction.
#[derive(Debug, Clone)]
pub struct TirInst {
    pub source_line: u32,
    pub op: isa::TirOp,
    pub byte_offset: Option<u32>,
    /// Sub-exp B (2026-07-15): pass-through bytes for 0x12 STR / 0x13 RAW data-def
    /// opcodes. Empty for non-data-def opcodes.
    pub data: Vec<u8>,
}

/// Lower yoyo source lines into TIR instructions.
/// Unrecognized opcodes are silently skipped with a warning.
pub fn lower(source: &[crate::ty_parser::SourceLine]) -> Vec<TirInst> {
    let mut out = Vec::new();
    for line in source {
        let op = match isa::lower_op(line.op, &line.args) {
            Some(op) => op,
            None => {
                eprintln!("warn: line {}: opcode 0x{:02X} not implemented (skipped)", line.line_no, line.op);
                continue;
            }
        };
        out.push(TirInst {
            source_line: line.line_no,
            op,
            byte_offset: None,
            data: line.data.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ty_parser;

    #[test]
    fn lower_set_imm() {
        let lines = ty_parser::parse("30 50 00");
        let tir = lower(&lines);
        assert_eq!(tir.len(), 1);
        match &tir[0].op {
            isa::TirOp::SetImm { slot, imm } => {
                assert_eq!(*slot, 0x50);
                assert_eq!(*imm, 0);
            }
            _ => panic!("expected SetImm"),
        }
    }

    #[test]
    fn lower_call() {
        let lines = ty_parser::parse("41 01");
        let tir = lower(&lines);
        assert_eq!(tir.len(), 1);
        match &tir[0].op {
            isa::TirOp::CallHh { hh } => assert_eq!(*hh, 1),
            _ => panic!("expected CallHh"),
        }
    }

    #[test]
    fn lower_handler_label() {
        let lines = ty_parser::parse("40 03");
        let tir = lower(&lines);
        assert_eq!(tir.len(), 1);
        match &tir[0].op {
            isa::TirOp::HandlerStart { hh } => assert_eq!(*hh, 3),
            _ => panic!("expected HandlerStart"),
        }
    }
}
