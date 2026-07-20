use crate::isa::TirOp;
use crate::tir::TirInst;

pub struct FixupTable {
    handlers: [(u8, u32); 256],
    count: usize,
}

impl FixupTable {
    pub fn new() -> Self {
        FixupTable {
            handlers: [(0, 0); 256],
            count: 0,
        }
    }

    pub fn record(&mut self, hh: u8, offset: u32) {
        for i in 0..self.count {
            if self.handlers[i].0 == hh {
                self.handlers[i].1 = offset;
                return;
            }
        }
        if self.count < 256 {
            self.handlers[self.count] = (hh, offset);
            self.count += 1;
        }
    }

    pub fn resolve(&self, hh: u8) -> Option<u32> {
        for i in 0..self.count {
            if self.handlers[i].0 == hh {
                return Some(self.handlers[i].1);
            }
        }
        None
    }

    pub fn find_hh_for_source_line(tir: &[TirInst], source_line: u32) -> Option<u8> {
        for inst in tir {
            if inst.source_line == source_line {
                match &inst.op {
                    TirOp::CallHh { hh }
                    | TirOp::JmpHh { hh }
                    | TirOp::JeHh { hh }
                    | TirOp::JneHh { hh }
                    | TirOp::JlHh { hh }
                    | TirOp::JgeHh { hh }
                    | TirOp::JleHh { hh }
                    | TirOp::JgHh { hh }
                    | TirOp::JbHh { hh }
                    | TirOp::JaeHh { hh }
                    | TirOp::JbeHh { hh }
                    | TirOp::JaHh { hh } => return Some(*hh),
                    _ => {}
                }
            }
        }
        None
    }
}
