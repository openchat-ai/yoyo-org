use crate::disasm::DisasmLine;
use crate::isa::TirOp;
use crate::tir::TirInst;
use crate::ty_parser::SourceLine;

const COL_SOURCE: usize = 30;
const COL_TIR: usize = 35;
const COL_X86: usize = 30;
const TOTAL_WIDTH: usize = COL_SOURCE + COL_TIR + COL_X86 + 6;

pub fn render_three_column(
    source: &[SourceLine],
    tir: &[TirInst],
    disasm: &[DisasmLine],
) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{:<width1$}  {:<width2$}  {:<width3$}\n",
        "SOURCE LAYER", "TIR LAYER", "X86 LAYER",
        width1 = COL_SOURCE, width2 = COL_TIR, width3 = COL_X86,
    ));
    out.push_str(&"-".repeat(TOTAL_WIDTH));
    out.push('\n');

    let mut tir_idx = 0;
    let mut disasm_idx = 0;

    for line in source {
        let source_text = format!("Line {}: {}", line.line_no, hex_line(line));
        let line_tirs: Vec<&TirInst> = tir.iter()
            .skip(tir_idx)
            .take_while(|t| t.source_line == line.line_no)
            .collect();
        let advance_tir = line_tirs.len();

        let tir_text = if !line_tirs.is_empty() {
            tir_op_to_string(&line_tirs[0].op)
        } else {
            String::from("(no TIR)")
        };

        let chunks_for_line = chunks_for_source_line(&line_tirs);
        let disasm_lines: Vec<&DisasmLine> = disasm.iter()
            .skip(disasm_idx)
            .take(chunks_for_line)
            .collect();
        let advance_disasm = disasm_lines.len();

        out.push_str(&format!(
            "{:<width1$}  {:<width2$}  {:<width3$}\n",
            source_text,
            tir_text,
            first_disasm_line(&disasm_lines, disasm_idx),
            width1 = COL_SOURCE, width2 = COL_TIR, width3 = COL_X86,
        ));

        let max_extra = std::cmp::max(
            line_tirs.len().saturating_sub(1),
            disasm_lines.len().saturating_sub(1),
        );
        for i in 1..=max_extra {
            let tir_str = if i < line_tirs.len() {
                tir_op_to_string(&line_tirs[i].op)
            } else {
                String::new()
            };
            let disasm_str = if i < disasm_lines.len() {
                disasm_lines[i].mnemonic.clone()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "{:<width1$}  {:<width2$}  {:<width3$}\n",
                "", tir_str, disasm_str,
                width1 = COL_SOURCE, width2 = COL_TIR, width3 = COL_X86,
            ));
        }

        tir_idx += advance_tir;
        disasm_idx += advance_disasm;
    }

    out
}

fn hex_line(line: &SourceLine) -> String {
    let mut s = format!("{:02X}", line.op);
    for a in &line.args {
        s.push(' ');
        if *a <= 0xFF {
            s.push_str(&format!("{:02X}", a));
        } else if *a <= 0xFFFF {
            s.push_str(&format!("{:04X}", a));
        } else {
            s.push_str(&format!("{:X}", a));
        }
    }
    s
}

fn tir_op_to_string(op: &TirOp) -> String {
    match op {
        TirOp::SetImm { slot, imm } => format!("set state[0x{:02X}], 0x{:X}", slot, imm),
        TirOp::Get { dst, src } => format!("set state[0x{:02X}], state[0x{:02X}]", dst, src),
        TirOp::Inc { slot } => format!("inc state[0x{:02X}]", slot),
        TirOp::Dec { slot } => format!("dec state[0x{:02X}]", slot),
        TirOp::AddImm { slot, imm } => format!("add state[0x{:02X}], 0x{:X}", slot, imm),
        TirOp::SubImm { slot, imm } => format!("sub state[0x{:02X}], 0x{:X}", slot, imm),
        TirOp::AddV { dst, src } => format!("add state[0x{:02X}], state[0x{:02X}]", dst, src),
        TirOp::SubV { dst, src } => format!("sub state[0x{:02X}], state[0x{:02X}]", dst, src),
        TirOp::Imul { dst, src } => format!("imul state[0x{:02X}], state[0x{:02X}]", dst, src),
        TirOp::Cmp { a, b } => format!("cmp state[0x{:02X}], state[0x{:02X}]", a, b),
        TirOp::CallHh { hh } => format!("call H_{:02X}", hh),
        TirOp::JmpHh { hh } => format!("jmp H_{:02X}", hh),
        TirOp::JeHh { hh } => format!("je H_{:02X}", hh),
        TirOp::JneHh { hh } => format!("jne H_{:02X}", hh),
        TirOp::JlHh { hh } => format!("jl H_{:02X}", hh),
        TirOp::JgeHh { hh } => format!("jge H_{:02X}", hh),
        TirOp::JleHh { hh } => format!("jle H_{:02X}", hh),
        TirOp::JgHh { hh } => format!("jg H_{:02X}", hh),
        TirOp::JbHh { hh } => format!("jb H_{:02X}", hh),
        TirOp::JaeHh { hh } => format!("jae H_{:02X}", hh),
        TirOp::JbeHh { hh } => format!("jbe H_{:02X}", hh),
        TirOp::JaHh { hh } => format!("ja H_{:02X}", hh),
        TirOp::HandlerStart { hh } => format!("H_{:02X}:", hh),
        TirOp::Ret => "ret".to_string(),
        TirOp::Ldb { dd, ss, oo } => {
            let oo_s = if *oo < 0 { format!("-0x{:X}", -(*oo)) } else { format!("0x{:X}", oo) };
            format!("ldb state[0x{:02X}], [state[0x{:02X}] + {}]", dd, ss, oo_s)
        }
        TirOp::MemcpyData { dd, off, sz } => {
            format!("memcpy.d state[0x{:02X}], [data+0x{:X}], 0x{:X}", dd, off, sz)
        }
        TirOp::MemcpyState { dd, ss, sz } => {
            format!("memcpy.s state[0x{:02X}], state[0x{:02X}], 0x{:X}", dd, ss, sz)
        }
        TirOp::Alloc { slot, sz } => {
            format!("alloc state[0x{:02X}], 0x{:X}", slot, sz)
        }
        TirOp::LoadFile { slot, str_idx } => {
            format!("loadfile state[0x{:02X}], str_idx={}", slot, str_idx)
        }
        TirOp::WriteFile { id, str_idx, sz } => {
            format!("writefile state[0x{:02X}], str_idx={}, sz=state[0x{:02X}]", id, str_idx, sz)
        }
        TirOp::RawByte { byte } => format!("raw_byte 0x{:02X}", byte),
        TirOp::RawBytes { bytes } => format!("raw_bytes count={}", bytes),
        TirOp::LibyoyoAlloc { slot, sz } => format!("libyoyo_alloc state[0x{:02X}], 0x{:X}", slot, sz),
        TirOp::LibyoyoFree { slot } => format!("libyoyo_free state[0x{:02X}]", slot),
        TirOp::LibyoyoOpen { slot, str_idx } => format!("libyoyo_open state[0x{:02X}], str_idx={}", slot, str_idx),
        TirOp::LibyoyoRead { slot, fd, sz } => format!("libyoyo_read state[0x{:02X}], fd=state[0x{:02X}], sz=0x{:X}", slot, fd, sz),
        TirOp::LibyoyoWrite { fd, slot, sz } => format!("libyoyo_write fd=state[0x{:02X}], state[0x{:02X}], sz=0x{:X}", fd, slot, sz),
        TirOp::LibyoyoClose { fd } => format!("libyoyo_close fd=state[0x{:02X}]", fd),
        TirOp::LibyoyoExit { slot } => format!("libyoyo_exit state[0x{:02X}]", slot),
        TirOp::LibyoyoPrint { slot } => format!("libyoyo_print state[0x{:02X}]", slot),
        TirOp::LibyoyoTime { slot } => format!("libyoyo_time state[0x{:02X}]", slot),
    }
}

fn chunks_for_source_line(line_tirs: &[&TirInst]) -> usize {
    let mut count = 0;
    for inst in line_tirs {
        count += match &inst.op {
            TirOp::SetImm { .. } => 2,
            TirOp::Get { .. } => 2,
            TirOp::Inc { .. } => 3,
            TirOp::Dec { .. } => 3,
            TirOp::AddImm { .. } => 3,
            TirOp::SubImm { .. } => 3,
            TirOp::AddV { .. } => 4,
            TirOp::SubV { .. } => 4,
            TirOp::Imul { .. } => 4,
            TirOp::Cmp { .. } => 3,
            TirOp::CallHh { .. } => 1,
            TirOp::JmpHh { .. } => 1,
            TirOp::JeHh { .. } => 1,
            TirOp::JneHh { .. } => 1,
            TirOp::JlHh { .. } => 1,
            TirOp::JgeHh { .. } => 1,
            TirOp::JleHh { .. } => 1,
            TirOp::JgHh { .. } => 1,
            TirOp::JbHh { .. } => 1,
            TirOp::JaeHh { .. } => 1,
            TirOp::JbeHh { .. } => 1,
            TirOp::JaHh { .. } => 1,
            TirOp::HandlerStart { .. } => 0,
            TirOp::Ret => 1,
            TirOp::Ldb { .. } => 3,
            TirOp::MemcpyData { .. } => 4,
            TirOp::MemcpyState { .. } => 4,
            TirOp::Alloc { .. } => 8,
            TirOp::LoadFile { .. } => 24,
            TirOp::WriteFile { .. } => 20,
            TirOp::RawByte { .. } => 1,
            TirOp::RawBytes { .. } => 1,
            // libyoyo_* call sizes (Phase 4c):
            // alloc: movabs rdi imm(10) + call_iat_thunk(6) + store_state(7) = 23
            // free/close: load_state(7) + call_iat_thunk(6) = 13
            // open: lea(7) + call_iat_thunk(6) + store_state(7) = 20
            // read: load_state(7) + load_state(7) + movabs(10) + call_iat_thunk(6) + store_state(7) = 37
            // write: load_state(7) + load_state(7) + movabs(10) + call_iat_thunk(6) = 30
            // exit: load_state(7) + call_iat_thunk(6) + ret(1) = 14
            // print: load_state(7) + call_iat_thunk(6) = 13
            // time: call_iat_thunk(6) + store_state(7) = 13
            TirOp::LibyoyoAlloc { .. } => 23,
            TirOp::LibyoyoFree { .. } => 13,
            TirOp::LibyoyoOpen { .. } => 20,
            TirOp::LibyoyoRead { .. } => 37,
            TirOp::LibyoyoWrite { .. } => 30,
            TirOp::LibyoyoClose { .. } => 13,
            TirOp::LibyoyoExit { .. } => 14,
            TirOp::LibyoyoPrint { .. } => 13,
            TirOp::LibyoyoTime { .. } => 13,
        };
    }
    count
}

fn first_disasm_line(lines: &[&DisasmLine], _base_idx: usize) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("[0x{:04X}] {}", lines[0].byte_offset, lines[0].mnemonic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::DisasmLine;
    use crate::isa::TirOp as T;
    use crate::tir::TirInst;

    #[test]
    fn hex_line_simple() {
        let line = SourceLine { line_no: 1, op: 0x30, args: vec![0x50, 0x00] };
        assert_eq!(hex_line(&line), "30 50 00");
    }

    #[test]
    fn tir_op_to_string_setimm() {
        let op = T::SetImm { slot: 0x50, imm: 0x3ff8000000000000 };
        let s = tir_op_to_string(&op);
        assert!(s.contains("state[0x50]"));
    }
}
