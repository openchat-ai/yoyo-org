use std::fmt::Debug;
use crate::assembler::X64Assembler;
use crate::executor;
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
    "VirtualAlloc",              // libyoyo_alloc   ?kernel32
    "VirtualFree",               // libyoyo_free    ?kernel32
    "CreateFileA",               // libyoyo_open    ?kernel32
    "ReadFile",                  // libyoyo_read    ?kernel32
    "WriteFile",                 // libyoyo_write   ?kernel32
    "CloseHandle",               // libyoyo_close   ?kernel32
    "ExitProcess",               // libyoyo_exit    ?kernel32
    "WriteFile",                 // libyoyo_print   ?kernel32
    "GetSystemTimeAsFileTime",   // libyoyo_time    ?kernel32
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

//        Dispatch enum                                                                                                                                                          

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

//        Stub Platform                                                                                                                                                          

#[derive(Debug)]
pub struct StubPlatform;

impl Platform for StubPlatform {
    fn name(&self) -> &'static str { "stub" }

    fn emit_alloc(&self, asm: &mut X64Assembler, _slot: u16, _sz: u64) -> IsaResult<()> {
        // stub: set state[slot] = 0 (no real alloc)   ?rax must hold 0
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

//        libyoyo_* call emitters (Phase 4c)                                                                                              

/// Place a placeholder for a libyoyo call fixup, return offset of the rel32
pub fn emit_libyoyo_call_marker(asm: &mut X64Assembler) -> u32 {
    let off = asm.bytes.len() as u32;
    asm.call_rip_placeholder();
    off
}

//        Helpers                                                                                                                                                                            

/// Emit `FF 15 ii 00 00 00` into `asm`: call [rip+ii].
/// The linker patches bytes 2..6 with the correct RIP-relative displacement.
pub fn call_iat_thunk(asm: &mut X64Assembler, api: Win32Api) {
    asm.call_iat_thunk(api as u8);
}

/// Public version   ?emit libyoyo call thunk into an assembler.
impl Win32Api {
    pub fn emit_call(&self, asm: &mut X64Assembler) {
        asm.call_iat_thunk(*self as u8);
    }
}

/// Emit `lea rdi, [rip+str_offset_placeholder]`   ?load address of str_idx string.
pub fn emit_str_idx_addr(asm: &mut X64Assembler) {
    asm.lea_rdi_rip_placeholder();
}

//        Win32 Platform                                                                                                                                                       

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
        // sub rsp must be 16-byte aligned: 0x20 shadow + 3  8 args = 0x38   ?0x40
        asm.sub_imm(Reg::Rsp, 0x40);
        asm.mov_qword_rsp_disp(0x20, 3);   // 5th: dwCreationDisposition = OPEN_EXISTING
        asm.mov_qword_rsp_disp(0x28, 0x80); // 6th: dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
        asm.mov_qword_rsp_disp(0x30, 0);   // 7th: hTemplateFile
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
        // 4 args in regs + lpNumberOfBytesRead on stack = shadow + 1 slot
        // 0x20 shadow + 1  8 = 0x28; round up to 0x30 for 16-byte alignment
        asm.sub_imm(Reg::Rsp, 0x30);
        asm.lea_rsp_sib32(Reg::R9, 0x28);   // R9 = &bytesRead slot
        asm.mov_qword_rsp_disp(0x28, 0);    // bytesRead slot
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
        // sub rsp must be 16-byte aligned: 0x20 shadow + 3  8 args = 0x38   ?0x40
        asm.sub_imm(Reg::Rsp, 0x40);
        asm.mov_qword_rsp_disp(0x20, 2);  // 5th: dwCreationDisposition = CREATE_ALWAYS
        asm.mov_qword_rsp_disp(0x28, 0);  // 6th: dwFlagsAndAttributes
        asm.mov_qword_rsp_disp(0x30, 0);  // 7th: hTemplateFile
        asm.call_iat_thunk(Win32Api::CreateFileA as u8);
        asm.add_imm(Reg::Rsp, 0x40);
        asm.mov_rr(Reg::R12, Reg::Rax);
        asm.mov_rr(Reg::Rcx, Reg::R12);
        asm.mov_rr(Reg::Rdx, Reg::R13);
        asm.mov_rr(Reg::R8, Reg::R14);
        // 4 args in regs + lpNumberOfBytesWritten on stack = shadow + 1 slot
        // 0x20 shadow + 1  8 = 0x28; round up to 0x30 for 16-byte alignment
        asm.sub_imm(Reg::Rsp, 0x30);
        asm.lea_rsp_sib32(Reg::R9, 0x28);   // R9 = &bytesWritten slot
        asm.mov_qword_rsp_disp(0x28, 0);    // bytesWritten slot
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
        // Win32 startup: set up stack state area, call H_00, then ExitProcess.
        // Critical: we MUST call ExitProcess rather than ret. When the
        // entry function just 'ret's, the kernel wraps things in NtWait
        // on inherited CONIN$/CONOUT$ handles (= 0x400) and the process
        // hangs forever waiting for them to close (parent never closes).
        //
        // Layout: push 6 regs, sub rsp, lea r15, call H_00, pop 6 regs,
        //         add rsp, call ExitProcess(R8 = exit code), hlt
        let mut a = X64Assembler::new();
        a.push(Reg::R12);
        a.push(Reg::R13);
        a.push(Reg::R14);
        a.push(Reg::Rbx);
        a.push(Reg::R15);
        a.push(Reg::Rsi);
        a.sub_imm(Reg::Rsp, 0x1008);
        a.lea_rsp_sib32(Reg::R15, 0x808);
        a.call_rel32_placeholder(); // -> H_00 (patched by pe_link)
        a.add_imm(Reg::Rsp, 0x1008);
        a.pop(Reg::Rsi);
        a.pop(Reg::R15);
        a.pop(Reg::Rbx);
        a.pop(Reg::R14);
        a.pop(Reg::R13);
        a.pop(Reg::R12);
        // H_00's return value is already in RAX (typically CloseHandle's
        // success/failure). Pass as ExitProcess's uExitCode.
        a.mov_rr(Reg::Rcx, Reg::Rax);
        a.call_iat_thunk(Win32Api::LibyoyoExit as u8);
        a.ret(); // unreachable; ExitProcess never returns
        a.into_bytes()
    }

    /// H_00 entry handler: hardcoded pipeline that reads "input.ky",
    /// copies its contents to "output.exe". Mirrors the legacy yoy0 v0.4
    /// main(): argv parsing is skipped, both paths are constants.
    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        // V4: Simplified pipeline — hardcoded "input.ky" and "output.exe" on stack.

        asm.push(Reg::R12);
        asm.push(Reg::R13);
        asm.push(Reg::R14);
        asm.push(Reg::Rbx);
        asm.push(Reg::R15);
        asm.push(Reg::Rsi);
        asm.sub_imm(Reg::Rsp, 0x1020); // stack buffer + slack for I/O sub-frames

        // Write "input.ky\0" at [RSP+0x1000]
        asm.lea_rsp_sib32(Reg::Rdi, 0x1000);
        for &b in b"input.ky" {
            asm.mov_byte_mem_imm(Reg::Rdi, b); asm.inc(Reg::Rdi);
        }
        asm.mov_byte_mem_imm(Reg::Rdi, 0);
        asm.lea_rsp_sib32(Reg::R12, 0x1000); // R12 = "input.ky"

        // Write "output.exe\0" at [RSP+0x1010]
        asm.lea_rsp_sib32(Reg::Rdi, 0x1010);
        for &b in b"output.exe" {
            asm.mov_byte_mem_imm(Reg::Rdi, b); asm.inc(Reg::Rdi);
        }
        asm.mov_byte_mem_imm(Reg::Rdi, 0);
        asm.lea_rsp_sib32(Reg::R13, 0x1010); // R13 = "output.exe"

        // Pipeline: loadfile + V3 executor + writefile
        asm.mov_rr(Reg::Rsi, Reg::R12);
        self.emit_loadfile(asm, 0, 0)?;

        // V3 executor: R12=buf, RDX=size
        asm.mov_rr(Reg::R12, Reg::Rax);
        executor::emit_v3_executor(asm)?;

        // Write output: RAX=output_size, RDX=output_buf, R13=output filename
        asm.mov_rr(Reg::R8, Reg::Rax);
        asm.mov_rr(Reg::Rsi, Reg::R13);
        self.emit_writefile(asm, 0, 0, 0)?;

        // epilogue
        asm.add_imm(Reg::Rsp, 0x1020);
        asm.pop(Reg::Rsi);
        asm.pop(Reg::R15);
        asm.pop(Reg::Rbx);
        asm.pop(Reg::R14);
        asm.pop(Reg::R13);
        asm.pop(Reg::R12);
        asm.resolve_fixups();
        asm.ret();
        Ok(())
    }
}

//        Linux Platform
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
        // ELF entry point   ?no return address, H_00 exits via syscall.
        let mut a = X64Assembler::new();
        a.sub_imm(Reg::Rsp, 0x1008);
        a.lea_rsp_sib32(Reg::R15, 0x808);
        a.jmp_rel32_placeholder(); //   ?H_00 (patched by pe_link)
        a.into_bytes()
    }

    fn emit_h00_code(&self, asm: &mut X64Assembler) -> IsaResult<()> {
        // Linux H_00: minimal stub (no I/O yet)
        asm.ret();
        Ok(())
    }
}
