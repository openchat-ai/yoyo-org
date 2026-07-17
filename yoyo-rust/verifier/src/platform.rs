use std::fmt::Debug;
use crate::assembler::X64Assembler;
use crate::types::{IsaResult, Reg};

/// IAT thunk indices embedded in `FF 15 ii 00 00 00` placeholders.
/// The linker extracts `ii` to determine which IAT entry to patch.
///
/// Layout:
/// - 0..5:  legacy Win32 API calls (VirtualAlloc, CreateFileA, etc.)
/// - 6..14: libyoyo_* calls (Phase 4c)
/// - 15:    GetCommandLineA (v0.4 argv support, Phase 4c)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IatThunk {
    VirtualAlloc = 0,
    CreateFileA = 1,
    GetFileSize = 2,
    ReadFile = 3,
    WriteFile = 4,
    CloseHandle = 5,
    LibyoyoAlloc = 6,
    LibyoyoFree = 7,
    LibyoyoOpen = 8,
    LibyoyoRead = 9,
    LibyoyoWrite = 10,
    LibyoyoClose = 11,
    LibyoyoExit = 12,
    LibyoyoPrint = 13,
    LibyoyoTime = 14,
    GetCommandLineA = 15,
}

pub const NUM_IAT_THUNKS: usize = 16;

pub const IAT_THUNK_NAMES: [&str; NUM_IAT_THUNKS] = [
    "VirtualAlloc",
    "CreateFileA",
    "GetFileSize",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "VirtualAlloc",              // libyoyo_alloc → kernel32
    "VirtualFree",               // libyoyo_free  → kernel32
    "CreateFileA",               // libyoyo_open  → kernel32
    "ReadFile",                  // libyoyo_read  → kernel32
    "WriteFile",                 // libyoyo_write → kernel32
    "CloseHandle",               // libyoyo_close → kernel32
    "ExitProcess",               // libyoyo_exit  → kernel32
    "WriteFile",                 // libyoyo_print → kernel32
    "GetSystemTimeAsFileTime",   // libyoyo_time  → kernel32
    "GetCommandLineA",
];

// Backward-compat alias - old code uses Win32Api name
pub type Win32Api = IatThunk;
pub const NUM_WIN32_APIS: usize = NUM_IAT_THUNKS;
pub const WIN32_API_NAMES: [&str; NUM_WIN32_APIS] = IAT_THUNK_NAMES;

/// Offset within emitted code of a `FF 15 ii 00 00 00` placeholder
/// that the PE linker must patch with a RIP-relative IAT displacement.
#[derive(Debug, Clone, Copy)]
pub struct IatFixup {
    /// File-offset of the `FF` byte (start of the 6-byte call [rip+0]).
    pub code_offset: u32,
    pub api: Win32Api,
}

/// Platform abstraction: defines syscall thunks and startup blob.
pub trait Platform: Debug {
    fn name(&self) -> &'static str;

    fn emit_alloc(&self, asm: &mut X64Assembler, slot: u16, sz: u64) -> IsaResult<()>;
    /// v0.4: `str_slot` (runtime state slot holding the path PSTR),
    /// replacing legacy `str_idx` (compile-time string-table index).
    fn emit_loadfile(&self, asm: &mut X64Assembler, slot: u16, str_slot: u16) -> IsaResult<()>;
    fn emit_writefile(&self, asm: &mut X64Assembler, id: u16, str_slot: u16, sz: u16) -> IsaResult<()>;
    /// H_00 entry handler: hardcoded load "input.ky", write "output.exe".
    /// Default: emit only `ret` (C3) for platforms without a defined H_00.
    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        asm.ret();
        Ok(())
    }
    fn startup_blob(&self) -> Vec<u8>;
}

// ── Dispatch enum ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum PlatformKind {
    Win32,
    Linux,
    Stub,
}

impl Platform for PlatformKind {
    fn name(&self) -> &'static str {
        match self {
            PlatformKind::Win32 => "win32",
            PlatformKind::Linux => "linux",
            PlatformKind::Stub => "stub",
        }
    }

    fn emit_alloc(&self, asm: &mut X64Assembler, slot: u16, sz: u64) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_alloc(asm, slot, sz),
            PlatformKind::Linux => LinuxPlatform.emit_alloc(asm, slot, sz),
            PlatformKind::Stub => StubPlatform.emit_alloc(asm, slot, sz),
        }
    }

    fn emit_loadfile(&self, asm: &mut X64Assembler, slot: u16, str_slot: u16) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_loadfile(asm, slot, str_slot),
            PlatformKind::Linux => LinuxPlatform.emit_loadfile(asm, slot, str_slot),
            PlatformKind::Stub => StubPlatform.emit_loadfile(asm, slot, str_slot),
        }
    }

    fn emit_writefile(&self, asm: &mut X64Assembler, id: u16, str_slot: u16, sz: u16) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_writefile(asm, id, str_slot, sz),
            PlatformKind::Linux => LinuxPlatform.emit_writefile(asm, id, str_slot, sz),
            PlatformKind::Stub => StubPlatform.emit_writefile(asm, id, str_slot, sz),
        }
    }

    fn startup_blob(&self) -> Vec<u8> {
        match self {
            PlatformKind::Win32 => Win32Platform.startup_blob(),
            PlatformKind::Linux => LinuxPlatform.startup_blob(),
            PlatformKind::Stub => StubPlatform.startup_blob(),
        }
    }

    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_h00_code(asm),
            PlatformKind::Linux => LinuxPlatform.emit_h00_code(asm),
            PlatformKind::Stub => StubPlatform.emit_h00_code(asm),
        }
    }
}

// ── Stub Platform ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct StubPlatform;

impl Platform for StubPlatform {
    fn name(&self) -> &'static str { "stub" }

    fn emit_alloc(&self, asm: &mut X64Assembler, _slot: u16, _sz: u64) -> IsaResult<()> {
        // stub: set state[slot] = 0 (no real alloc) — rax must hold 0
        asm.store_state(_slot as u8, Reg::Rax);
        asm.store_state((_slot + 1) as u8, Reg::Rax);
        Ok(())
    }
    fn emit_loadfile(&self, asm: &mut X64Assembler, slot: u16, _str_slot: u16) -> IsaResult<()> {
        asm.store_state(slot as u8, Reg::Rax);
        asm.store_state((slot + 1) as u8, Reg::Rax);
        Ok(())
    }
    fn emit_writefile(&self, _asm: &mut X64Assembler, _id: u16, _str_slot: u16, _sz: u16) -> IsaResult<()> {
        // stub: no-op (success)
        Ok(())
    }
    fn startup_blob(&self) -> Vec<u8> { Vec::new() }
}

// ── libyoyo_* call emitters (Phase 4c) ───────────────────────────────

/// Place a placeholder for a libyoyo call fixup, return offset of the rel32
pub fn emit_libyoyo_call_marker(asm: &mut X64Assembler) -> u32 {
    let off = asm.bytes.len() as u32;
    asm.call_rip_placeholder();
    off
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Emit `FF 15 ii 00 00 00` into `asm`: call [rip+ii].
/// The linker patches bytes 2..6 with the correct RIP-relative displacement.
pub fn call_iat_thunk(asm: &mut X64Assembler, api: Win32Api) {
    asm.call_iat_thunk(api as u8);
}

/// Public version — emit libyoyo call thunk into an assembler.
impl Win32Api {
    pub fn emit_call(&self, asm: &mut X64Assembler) {
        asm.call_iat_thunk(*self as u8);
    }
}

/// Emit `lea rdi, [rip+str_offset_placeholder]` — load address of str_idx string.
pub fn emit_str_idx_addr(asm: &mut X64Assembler) {
    asm.lea_rdi_rip_placeholder();
}

// ── Win32 Platform ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct Win32Platform;

impl Platform for Win32Platform {
    fn name(&self) -> &'static str { "win32" }

    fn emit_alloc(&self, asm: &mut X64Assembler, slot: u16, sz: u64) -> IsaResult<()> {
        asm.mov_imm64(Reg::Rcx, 0);
        asm.mov_imm64(Reg::Rdx, sz);
        asm.mov_imm64(Reg::R8, 0x3000);
        asm.mov_imm64(Reg::R9, 0x40);
        asm.shadow_frame();
        asm.call_iat_thunk(Win32Api::VirtualAlloc as u8);
        asm.shadow_ret();
        asm.store_state(slot as u8, Reg::Rax);
        Ok(())
    }

    fn emit_loadfile(&self, asm: &mut X64Assembler, _slot: u16, _str_slot: u16) -> IsaResult<()> {
        asm.push(Reg::R12);
        asm.push(Reg::R13);
        asm.push(Reg::R14);
        asm.mov_rr(Reg::Rcx, Reg::Rsi);
        asm.mov_imm64(Reg::Rdx, 0x8000_0000);
        asm.mov_imm64(Reg::R8, 1);
        asm.mov_imm64(Reg::R9, 0);
        asm.mov_imm64(Reg::Rax, 3);
        asm.sub_imm(Reg::Rsp, 0x40);  // 0x20 shadow + 3×8 stack = 0x38, padded to 16-byte boundary
        asm.mov_qword_rsp_disp(0x20, 3);
        asm.mov_qword_rsp_disp(0x28, 0x80);
        asm.mov_qword_rsp_disp(0x30, 0);
        asm.call_iat_thunk(Win32Api::CreateFileA as u8);
        asm.add_imm(Reg::Rsp, 0x40);
        asm.mov_rr(Reg::R12, Reg::Rax);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.mov_imm64(Reg::Rdx, 0);
        asm.shadow_frame();
        asm.call_iat_thunk(Win32Api::GetFileSize as u8);
        asm.shadow_ret();
        asm.mov_rr(Reg::R13, Reg::Rax);
        asm.mov_imm64(Reg::Rcx, 0);
        asm.mov_rr(Reg::Rdx, Reg::R13);
        asm.mov_imm64(Reg::R8, 0x3000);
        asm.mov_imm64(Reg::R9, 0x40);
        asm.shadow_frame();
        asm.call_iat_thunk(Win32Api::VirtualAlloc as u8);
        asm.shadow_ret();
        asm.mov_rr(Reg::R14, Reg::Rax);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.mov_rr(Reg::Rdx, Reg::R14);
        asm.mov_rr(Reg::R8, Reg::R13);
        asm.mov_imm64(Reg::R9, 0);
        asm.sub_imm(Reg::Rsp, 0x30);  // 0x20 shadow + 1×8 stack = 0x28, padded to 16-byte boundary
        asm.mov_qword_rsp_disp(0x20, 0);
        asm.call_iat_thunk(Win32Api::ReadFile as u8);
        asm.add_imm(Reg::Rsp, 0x30);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.shadow_frame();
        asm.call_iat_thunk(Win32Api::CloseHandle as u8);
        asm.shadow_ret();
        asm.mov_rr(Reg::Rax, Reg::R14);
        asm.mov_rr(Reg::Rdx, Reg::R13);
        asm.pop(Reg::R14);
        asm.pop(Reg::R13);
        asm.pop(Reg::R12);
        Ok(())
    }

    fn emit_writefile(&self, asm: &mut X64Assembler, _id: u16, _str_slot: u16, _sz: u16) -> IsaResult<()> {
        asm.push(Reg::R12);
        asm.push(Reg::R13);
        asm.push(Reg::R14);
        asm.mov_rr(Reg::R13, Reg::Rdx);
        asm.mov_rr(Reg::R14, Reg::R8);
        asm.mov_rr(Reg::Rcx, Reg::Rsi);
        asm.mov_imm64(Reg::Rdx, 0x4000_0000);
        asm.mov_imm64(Reg::R8, 0);
        asm.mov_imm64(Reg::R9, 0);
        asm.mov_imm64(Reg::Rax, 2);
        asm.sub_imm(Reg::Rsp, 0x40);  // 0x20 shadow + 3×8 stack = 0x38, padded to 16-byte boundary
        asm.mov_qword_rsp_disp(0x20, 2);
        asm.mov_qword_rsp_disp(0x28, 0);
        asm.mov_qword_rsp_disp(0x30, 0);
        asm.call_iat_thunk(Win32Api::CreateFileA as u8);
        asm.add_imm(Reg::Rsp, 0x40);
        asm.mov_rr(Reg::R12, Reg::Rax);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.mov_rr(Reg::Rdx, Reg::R13);
        asm.mov_rr(Reg::R8, Reg::R14);
        asm.sub_imm(Reg::Rsp, 0x30);
        asm.mov_qword_rsp_disp(0x28, 0);
        asm.lea_rsp_sib32(Reg::R9, 0x28);
        asm.mov_qword_rsp_disp(0x20, 0);
        asm.call_iat_thunk(Win32Api::WriteFile as u8);
        asm.add_imm(Reg::Rsp, 0x30);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.shadow_frame();
        asm.call_iat_thunk(Win32Api::CloseHandle as u8);
        asm.shadow_ret();
        asm.pop(Reg::R14);
        asm.pop(Reg::R13);
        asm.pop(Reg::R12);
        Ok(())
    }

    fn startup_blob(&self) -> Vec<u8> {
        // Win32 startup: set up stack state area, call H_00, clean up and return.
        // Registers saved per x64 calling convention (r12-r15, rbx, rsi are callee-saved).
        // r15 = stack-based state area pointer (lea r15, [rsp+0x808]).
        //
        // Layout: push 6 regs, sub rsp, lea r15, call H_00, add rsp, pop 6 regs, ret
        let mut a = X64Assembler::new();
        a.push(Reg::R12);
        a.push(Reg::R13);
        a.push(Reg::R14);
        a.push(Reg::Rbx);
        a.push(Reg::R15);
        a.push(Reg::Rsi);
        a.sub_imm(Reg::Rsp, 0x1008);
        a.lea_rsp_sib32(Reg::R15, 0x808);
        a.call_rel32_placeholder(); // → H_00 (patched by pe_link)
        a.add_imm(Reg::Rsp, 0x1008);
        a.pop(Reg::Rsi);
        a.pop(Reg::R15);
        a.pop(Reg::Rbx);
        a.pop(Reg::R14);
        a.pop(Reg::R13);
        a.pop(Reg::R12);
        a.ret();
        a.into_bytes()
    }

    /// H_00 entry handler: hardcoded pipeline that reads "input.ky",
    /// copies its contents to "output.exe". Mirrors the legacy yoy0 v0.4
    /// main(): argv parsing is skipped, both paths are constants.
    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        // ── 1. Load "input.ky" ──────────────────────────────────────
        // Push null padding FIRST, then the string, so that after both
        // pushes, [RSP+0] = "input.ky" and [RSP+8] = 0 (null terminator).
        asm.mov_imm64(Reg::Rax, 0);
        asm.push(Reg::Rax); // [RSP] = 0 (null padding)
        asm.mov_imm64(Reg::Rax, 0x796B2E7475706E69); // "input.ky" (LE: 69 6E 70 75 74 2E 6B 79)
        asm.push(Reg::Rax); // [RSP] = "input.ky"
        asm.lea_mem(Reg::Rsi, Reg::Rsp, 0); // RSI → "input.ky"
        // emit_loadfile: RAX=buffer, RDX=size on return
        self.emit_loadfile(asm, 0, 0)?;
        // Save buffer/size in callee-saved regs (R12-R14 are restored
        // across emit_loadfile, so we can use them safely afterwards).
        asm.mov_rr(Reg::R12, Reg::Rax); // R12 = buffer ptr
        asm.mov_rr(Reg::R13, Reg::Rdx); // R13 = file size
        // Pop the input path string (16 bytes)
        asm.add_imm(Reg::Rsp, 16);

        // ── 2. Write "output.exe" ───────────────────────────────────
        // Push null terminator FIRST, then "output.e" + "xe\0..."
        // "output.exe" = 10 chars: o u t p u t . e x e
        // First 8 chars: "output.e" = 6F 75 74 70 75 74 2E 65
        // Next 2 chars + padding: "xe\0\0\0\0\0\0" = 78 65 00 ...
        asm.mov_imm64(Reg::Rax, 0); // null padding
        asm.push(Reg::Rax);
        asm.mov_imm64(Reg::Rax, 0x0000000000006578); // "xe\0\0\0\0\0\0"
        asm.push(Reg::Rax);
        asm.mov_imm64(Reg::Rax, 0x652E74757074756F); // "output.e" LE: 6F 75 74 70 75 74 2E 65
        asm.push(Reg::Rax);
        asm.lea_mem(Reg::Rsi, Reg::Rsp, 0); // RSI → "output.exe"
        // emit_writefile expects: RSI=path, RDX=buffer, R8=size
        asm.mov_rr(Reg::Rdx, Reg::R12);
        asm.mov_rr(Reg::R8, Reg::R13);
        self.emit_writefile(asm, 0, 0, 0)?;
        // Pop the output path string (24 bytes: 3 pushes)
        asm.add_imm(Reg::Rsp, 24);

        asm.ret();
        Ok(())
    }
}

// ── Linux Platform ──────────────────────────────────────────────────
#[derive(Debug)]
pub struct LinuxPlatform;

fn linux_syscall(asm: &mut X64Assembler, sysno: u64) {
    asm.mov_imm64(Reg::Rax, sysno);
    asm.emit_u8(0x0F);
    asm.emit_u8(0x05);
}

impl Platform for LinuxPlatform {
    fn name(&self) -> &'static str { "linux" }

    fn emit_alloc(&self, asm: &mut X64Assembler, slot: u16, sz: u64) -> IsaResult<()> {
        asm.mov_imm64(Reg::Rdi, 0);
        asm.mov_imm64(Reg::Rsi, sz);
        asm.mov_imm64(Reg::Rdx, 3);
        asm.mov_imm64(Reg::R10, 0x22);
        asm.mov_imm64(Reg::R8, (-1i64) as u64);
        asm.mov_imm64(Reg::R9, 0);
        linux_syscall(asm, 9);
        asm.store_state(slot as u8, Reg::Rax);
        Ok(())
    }

    fn emit_loadfile(&self, asm: &mut X64Assembler, slot: u16, str_slot: u16) -> IsaResult<()> {
        asm.lea_mem(Reg::Rdi, Reg::R15, (str_slot as i32) * 8);
        asm.mov_imm64(Reg::Rsi, 0);
        linux_syscall(asm, 2);
        asm.store_state(0, Reg::Rax);
        asm.mov_rr(Reg::Rdi, Reg::Rax);
        asm.mov_imm64(Reg::Rsi, 0);
        asm.mov_imm64(Reg::Rdx, 2);
        linux_syscall(asm, 8);
        asm.store_state((slot + 1) as u8, Reg::Rax);
        asm.load_state(Reg::Rdi, 0);
        asm.mov_imm64(Reg::Rsi, 0);
        asm.mov_imm64(Reg::Rdx, 0);
        linux_syscall(asm, 8);
        asm.mov_imm64(Reg::Rdi, 0);
        asm.load_state(Reg::Rsi, (slot + 1) as u8);
        asm.mov_imm64(Reg::Rdx, 1);
        asm.mov_imm64(Reg::R10, 2);
        asm.load_state(Reg::R8, 0);
        asm.mov_imm64(Reg::R9, 0);
        linux_syscall(asm, 9);
        asm.store_state(slot as u8, Reg::Rax);
        asm.load_state(Reg::Rdi, 0);
        linux_syscall(asm, 3);
        Ok(())
    }

    fn emit_writefile(&self, asm: &mut X64Assembler, id: u16, str_slot: u16, sz: u16) -> IsaResult<()> {
        asm.lea_mem(Reg::Rdi, Reg::R15, (str_slot as i32) * 8);
        asm.mov_imm64(Reg::Rsi, 0x241);
        asm.mov_imm64(Reg::Rdx, 0x1A4);
        linux_syscall(asm, 2);
        asm.store_state(0, Reg::Rax);
        asm.mov_rr(Reg::Rdi, Reg::Rax);
        asm.load_state(Reg::Rsi, id as u8);
        asm.load_state(Reg::Rdx, sz as u8);
        linux_syscall(asm, 1);
        asm.load_state(Reg::Rdi, 0);
        linux_syscall(asm, 3);
        Ok(())
    }

    fn startup_blob(&self) -> Vec<u8> {
        // Linux startup: set up stack state area, then jmp to H_00.
        // ELF entry point — no return address, H_00 exits via syscall.
        let mut a = X64Assembler::new();
        a.sub_imm(Reg::Rsp, 0x1008);
        a.lea_rsp_sib32(Reg::R15, 0x808);
        a.jmp_rel32_placeholder(); // → H_00 (patched by pe_link)
        a.into_bytes()
    }

    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        // Linux H_00: minimal stub (no I/O yet)
        asm.ret();
        Ok(())
    }
}
