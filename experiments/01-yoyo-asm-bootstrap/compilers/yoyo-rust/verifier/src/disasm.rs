//! Layer 3.5: x86 byte disassembly for human-readable output.
//!
//! M1 scope: recognize just the instruction patterns emitted by Layer 3. We
//! do NOT implement a full x86 decoder — only the patterns we ourselves emit.
//! This keeps the tool honest and self-contained.
//!
//! The recognized patterns are:
//!   - REX.W + B8 + imm64    → mov rax, imm64
//!   - 49 89 87 + disp32     → mov [r15+disp32], rax
//!   - 48 8B 87 + disp32     → mov rax, [r15+disp32]
//!   - 48 8B 97 + disp32     → mov rdx, [r15+disp32]
//!   - 48 83 C0 01           → add rax, 1
//!   - 48 39 D0              → cmp rax, rdx
//!   - E8 + rel32            → call H_<resolved>
//!   - E9 + rel32            → jmp H_<resolved>
//!   - 0F 84 + rel32         → je H_<resolved>
//!   - C3                    → ret
//!
//! Anything else is reported as `<unknown XX...>`.

/// One disassembled instruction.
#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub byte_offset: u32,
    pub mnemonic: String,
    /// For backward references (mov rax, X; add rax, 1; mov [X], rax) the
    /// rendered slots are derived from emit context. This is a free-form
    /// comment that may carry the decoded operand(s) like "state[0x50]".
    pub note: String,
}

/// Disassemble the bytes emitted by Layer 3.
/// `base_offset` is added to the byte position of each instruction (use 0 if
/// the .text section starts at offset 0 in your view).
pub fn disasm(bytes: &[u8]) -> Vec<DisasmLine> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let (consumed, line) = decode_at(&bytes[i..], i as u32);
        if consumed == 0 {
            // safety net: emit one byte as "unknown"
            out.push(DisasmLine {
                byte_offset: i as u32,
                mnemonic: format!("<unknown 0x{:02X}>", bytes[i]),
                note: String::new(),
            });
            i += 1;
        } else {
            out.push(line);
            i += consumed;
        }
    }
    out
}

fn decode_at(b: &[u8], offset: u32) -> (usize, DisasmLine) {
    // Patterns are checked in order; first match wins.
    // All patterns include REX.W (0x48) or REX.WB (0x49) since emit only produces 64-bit.

    if b.len() >= 2 && b[0] == 0x48 && b[1] == 0xB8 && b.len() >= 10 {
        // mov rax, imm64
        let imm = u64::from_le_bytes(b[2..10].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rax, 0x{:016X}", imm),
            note: String::new(),
        };
        return (10, line);
    }

    if b.len() >= 7 && b[0] == 0x49 && b[1] == 0x89 && b[2] == 0x87 {
        // mov [r15+disp32], rax
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov [r15+0x{:04X}], rax", disp),
            note: format!("state[0x{:02X}] = rax", slot),
        };
        return (7, line);
    }

    if b.len() >= 4 && b[0] == 0x49 && b[1] == 0x89 && b[2] == 0x47 {
        // mov [r15+disp8], rax  (mod=01 disp8)
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov [r15+0x{:02X}], rax", disp),
            note: format!("state[0x{:02X}] = rax", slot),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x87 {
        // mov rax, [r15+disp32]
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rax, [r15+0x{:04X}]", disp),
            note: format!("rax = state[0x{:02X}]", slot),
        };
        return (7, line);
    }

if b.len() >= 7 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x97 {
        // mov rdx, [r15 + disp32]
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rdx, [r15+0x{:04X}]", disp),
            note: format!("rdx = state[0x{:02X}]", slot),
        };
        return (7, line);
    }

    if b.len() >= 4 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x57 {
        // mov rdx, [r15 + disp8]  (mod=01 disp8)
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rdx, [r15+0x{:02X}]", disp),
            note: format!("rdx = state[0x{:02X}]", slot),
        };
        return (4, line);
    }

    if b.len() >= 4 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x47 {
        // mov rax, [r15 + disp8]  (mod=01 disp8)
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rax, [r15+0x{:02X}]", disp),
            note: format!("rax = state[0x{:02X}]", slot),
        };
        return (4, line);
    }

    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xC0 {
        // add rax, imm8
        let imm = b[3];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("add rax, {}", imm),
            note: String::new(),
        };
        return (4, line);
    }

    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xE8 {
        // sub rax, imm8
        let imm = b[3];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("sub rax, {}", imm),
            note: String::new(),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xC0 {
        // add rax, imm32
        let imm = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("add rax, 0x{:X}", imm),
            note: String::new(),
        };
        return (7, line);
    }

    if b.len() >= 7 && b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xE8 {
        // sub rax, imm32
        let imm = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("sub rax, 0x{:X}", imm),
            note: String::new(),
        };
        return (7, line);
    }

    if b.len() >= 3 && b[0] == 0x48 && b[1] == 0x01 && b[2] == 0xD0 {
        return (3, DisasmLine {
            byte_offset: offset,
            mnemonic: "add rax, rdx".to_string(),
            note: String::new(),
        });
    }

    if b.len() >= 3 && b[0] == 0x48 && b[1] == 0x29 && b[2] == 0xD0 {
        return (3, DisasmLine {
            byte_offset: offset,
            mnemonic: "sub rax, rdx".to_string(),
            note: String::new(),
        });
    }

    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x0F && b[2] == 0xAF && b[3] == 0xC2 {
        return (4, DisasmLine {
            byte_offset: offset,
            mnemonic: "imul rax, rdx".to_string(),
            note: String::new(),
        });
    }

    if b.len() >= 3 && b[0] == 0x48 && b[1] == 0x39 && b[2] == 0xD0 {
        // cmp rax, rdx
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "cmp rax, rdx".to_string(),
            note: "set flags for next Jcc".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 5 && b[0] == 0xE8 {
        // call H_<hh> with rel32
        let rel = i32::from_le_bytes(b[1..5].try_into().unwrap());
        let target = (offset as i64 + 5 + rel as i64) as u32;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("call H_??  ; rel={}, target=0x{:04X}", rel, target),
            note: "H_<hh> resolved from rel32".to_string(),
        };
        return (5, line);
    }

    if b.len() >= 5 && b[0] == 0xE9 {
        // jmp H_<hh> with rel32
        let rel = i32::from_le_bytes(b[1..5].try_into().unwrap());
        let target = (offset as i64 + 5 + rel as i64) as u32;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("jmp H_??  ; rel={}, target=0x{:04X}", rel, target),
            note: String::new(),
        };
        return (5, line);
    }

    if b.len() >= 6 && b[0] == 0x0F && (0x80..=0x8F).contains(&b[1]) {
        // conditional near jump: je/jne/jl/... with rel32
        let rel = i32::from_le_bytes(b[2..6].try_into().unwrap());
        let target = (offset as i64 + 6 + rel as i64) as u32;
        let mnem = crate::tir::JCC_TABLE
            .iter()
            .position(|&op2| op2 == b[1])
            .map(|idx| crate::tir::JCC_MNEMONIC[idx])
            .unwrap_or("jcc");
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("{} H_??  ; rel={}, target=0x{:04X}", mnem, rel, target),
            note: String::new(),
        };
        return (6, line);
    }

    if b.len() >= 1 && b[0] == 0xC3 {
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "ret".to_string(),
            note: String::new(),
        };
        return (1, line);
    }

    // Phase 1.A: memory opcodes

    if b.len() >= 4 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x7F {
        // mov rdi, [r15 + disp8]  (REX.WB + 8B + modrm(0x7F=mod01,rm7) + disp8)
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rdi, [r15+0x{:02X}]", disp),
            note: format!("rdi = state[0x{:02X}]", slot),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0xBF {
        // mov rdi, [r15 + disp32]  (mod=10, rm=7)
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rdi, [r15+0x{:04X}]", disp),
            note: format!("rdi = state[0x{:02X}]", slot),
        };
        return (7, line);
    }

    if b.len() >= 4 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0x77 {
        // mov rsi, [r15 + disp8]
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rsi, [r15+0x{:02X}]", disp),
            note: format!("rsi = state[0x{:02X}]", slot),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x49 && b[1] == 0x8B && b[2] == 0xB7 {
        // mov rsi, [r15 + disp32]
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov rsi, [r15+0x{:04X}]", disp),
            note: format!("rsi = state[0x{:02X}]", slot),
        };
        return (7, line);
    }

    if b.len() >= 7 && b[0] == 0x48 && b[1] == 0x8D && b[2] == 0x35 {
        // lea rsi, [rip + disp32]  (RIP-relative addressing, mod=00 rm=5)
        let disp = i32::from_le_bytes(b[3..7].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("lea rsi, [rip+{}]", disp),
            note: "data_base + literal_off (RIP-relative)".to_string(),
        };
        return (7, line);
    }

    if b.len() >= 10 && b[0] == 0x48 && b[1] == 0xB9 {
        // movabs rcx, imm64
        let imm = u64::from_le_bytes(b[2..10].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movabs rcx, 0x{:016X}", imm),
            note: format!("rcx = literal sz (0x{:X})", imm),
        };
        return (10, line);
    }

    if b.len() >= 2 && b[0] == 0xF3 && b[1] == 0xA4 {
        // rep movsb
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "rep movsb".to_string(),
            note: "memcpy([rdi], [rsi], rcx bytes)".to_string(),
        };
        return (2, line);
    }

    // Phase 1.C: alloc (VirtualAlloc) + IAT thunk emit

    if b.len() >= 10 && b[0] == 0x48 && b[1] == 0xBA {
        // movabs rdx, imm64
        let imm = u64::from_le_bytes(b[2..10].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movabs rdx, 0x{:016X}", imm),
            note: String::new(),
        };
        return (10, line);
    }

    if b.len() >= 10 && b[0] == 0x49 && b[1] == 0xB8 {
        // movabs r8, imm64
        let imm = u64::from_le_bytes(b[2..10].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movabs r8, 0x{:016X}", imm),
            note: String::new(),
        };
        return (10, line);
    }

    if b.len() >= 10 && b[0] == 0x49 && b[1] == 0xB9 {
        // movabs r9, imm64
        let imm = u64::from_le_bytes(b[2..10].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movabs r9, 0x{:016X}", imm),
            note: String::new(),
        };
        return (10, line);
    }

    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC {
        // sub rsp, imm8
        let imm = b[3];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("sub rsp, 0x{:X}", imm),
            note: "shadow space for Win64 call".to_string(),
        };
        return (4, line);
    }

    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xC4 {
        // add rsp, imm8
        let imm = b[3];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("add rsp, 0x{:X}", imm),
            note: "restore stack after Win64 call".to_string(),
        };
        return (4, line);
    }

    if b.len() >= 6 && b[0] == 0xFF && b[1] == 0x15 {
        // call [rip + disp32]
        let disp = i32::from_le_bytes(b[2..6].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("call [rip+{}]", disp),
            note: "IAT thunk call (e.g. VirtualAlloc)".to_string(),
        };
        return (6, line);
    }

    if b.len() >= 7 && b[0] == 0x48 && b[1] == 0x8D && b[2] == 0x0D {
        // lea rcx, [rip + disp32]  (REX.W + 8D /r with mod=00, rm=5)
        let disp = i32::from_le_bytes(b[3..7].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("lea rcx, [rip+{}]", disp),
            note: "filename from data section (RIP-relative)".to_string(),
        };
        return (7, line);
    }

    if b.len() >= 3 && b[0] == 0x4D && b[1] == 0x31 && b[2] == 0xC0 {
        // xor r8, r8
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "xor r8, r8".to_string(),
            note: "dwShareMode = 0".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x4D && b[1] == 0x31 && b[2] == 0xC9 {
        // xor r9, r9
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "xor r9, r9".to_string(),
            note: "lpSecurityAttributes = NULL".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x49 && b[1] == 0x89 && b[2] == 0xC5 {
        // mov r13, rax  (REX.WB, reg=5 → r13)
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "mov r13, rax".to_string(),
            note: "save hFile in callee-saved register".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x4C && b[1] == 0x89 && b[2] == 0xE9 {
        // mov rcx, r13  (REX.WR, rm=5 + B=1 → r13)
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "mov rcx, r13".to_string(),
            note: "restore hFile for next call".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 5 && b[0] == 0x48 && b[1] == 0x89 && b[2] == 0x44 && b[3] == 0x24 {
        // mov [rsp + disp8], rax  (ModRM=0x44, SIB=0x24, disp8 follows)
        let disp = b[4];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov [rsp+0x{:02X}], rax", disp),
            note: format!("arg via stack (offset 0x{:X})", disp),
        };
        return (5, line);
    }

    if b.len() >= 5 && b[0] == 0x4C && b[1] == 0x8D && b[2] == 0x4C && b[3] == 0x24 {
        // lea r9, [rsp + disp8]  (REX.WR, ModRM=0x4C, SIB=0x24, disp8 follows)
        let disp = b[4];
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("lea r9, [rsp+0x{:02X}]", disp),
            note: format!("&arg pointer (offset 0x{:X})", disp),
        };
        return (5, line);
    }

    if b.len() >= 4 && b[0] == 0x4D && b[1] == 0x8B && b[2] == 0x47 {
        // mov r8, [r15 + disp8]  (REX.WRB, mod=01, reg=0 → r8, rm=7 → r15)
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov r8, [r15+0x{:02X}]", disp),
            note: format!("r8 = state[0x{:02X}]", slot),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x4D && b[1] == 0x8B && b[2] == 0x87 {
        // mov r8, [r15 + disp32]
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov r8, [r15+0x{:04X}]", disp),
            note: format!("r8 = state[0x{:02X}]", slot),
        };
        return (7, line);
    }

    if b.len() >= 3 && b[0] == 0x48 && b[1] == 0x31 && b[2] == 0xD2 {
        // xor rdx, rdx
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "xor rdx, rdx".to_string(),
            note: "lpFileSizeHigh = NULL".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x49 && b[1] == 0x89 && b[2] == 0xC4 {
        // mov r12, rax
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "mov r12, rax".to_string(),
            note: "save fileSize in callee-saved register".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x4C && b[1] == 0x89 && b[2] == 0xE2 {
        // mov rdx, r12
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "mov rdx, r12".to_string(),
            note: "restore fileSize for VirtualAlloc/ReadFile".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 3 && b[0] == 0x4D && b[1] == 0x89 && b[2] == 0xE0 {
        // mov r8, r12
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "mov r8, r12".to_string(),
            note: "nNumberOfBytesToRead = fileSize".to_string(),
        };
        return (3, line);
    }

    if b.len() >= 4 && b[0] == 0x4D && b[1] == 0x89 && b[2] == 0x67 {
        // mov [r15 + disp8], r12
        let disp = b[3] as u32;
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov [r15+0x{:02X}], r12", disp),
            note: format!("state[0x{:02X}] = fileSize (r12)", slot),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x4D && b[1] == 0x89 && b[2] == 0xA7 {
        // mov [r15 + disp32], r12
        let disp = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let slot = disp / 8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("mov [r15+0x{:04X}], r12", disp),
            note: format!("state[0x{:02X}] = fileSize (r12)", slot),
        };
        return (7, line);
    }

    if b.len() >= 3 && b[0] == 0x0F && b[1] == 0xB6 && b[2] == 0x02 {
        // movzx eax, byte [rdx]  (no displacement)
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: "movzx eax, byte [rdx]".to_string(),
            note: String::new(),
        };
        return (3, line);
    }

    if b.len() >= 4 && b[0] == 0x0F && b[1] == 0xB6 && b[2] == 0x42 {
        // movzx eax, byte [rdx + disp8]
        let disp = b[3] as i8;
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movzx eax, byte [rdx{}{}]", if disp < 0 { "-" } else { "+" }, disp.abs()),
            note: String::new(),
        };
        return (4, line);
    }

    if b.len() >= 7 && b[0] == 0x0F && b[1] == 0xB6 && b[2] == 0x82 {
        // movzx eax, byte [rdx + disp32]
        let disp = i32::from_le_bytes(b[3..7].try_into().unwrap());
        let line = DisasmLine {
            byte_offset: offset,
            mnemonic: format!("movzx eax, byte [rdx+{}]", disp),
            note: String::new(),
        };
        return (7, line);
    }

    // Unknown — caller will emit `<unknown XX>` and skip one byte
    (0, DisasmLine {
        byte_offset: offset,
        mnemonic: String::new(),
        note: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disasm_mov_rax_imm() {
        let bytes = vec![0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0];
        let lines = disasm(&bytes);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].mnemonic.contains("mov rax"));
    }

    #[test]
    fn disasm_ret() {
        let bytes = vec![0xC3];
        let lines = disasm(&bytes);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].mnemonic, "ret");
    }
}