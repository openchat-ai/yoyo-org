use std::fmt::Debug;
use crate::primitives::*;
use crate::types::{FixedBuf, IsaResult, Reg};

/// Win32 API indices embedded in `FF 15 ii 00 00 00` placeholders.
/// The linker extracts `ii` to determine which IAT entry to patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Win32Api {
    VirtualAlloc = 0,
    CreateFileA = 1,
    GetFileSize = 2,
    ReadFile = 3,
    WriteFile = 4,
    CloseHandle = 5,
}

pub const NUM_WIN32_APIS: usize = 6;

pub const WIN32_API_NAMES: [&str; NUM_WIN32_APIS] = [
    "VirtualAlloc",
    "CreateFileA",
    "GetFileSize",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
];

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

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, sz: u64) -> IsaResult<()>;
    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_idx: u8) -> IsaResult<()>;
    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_idx: u8, sz: u16) -> IsaResult<()>;
    fn startup_blob(&self) -> &[u8];
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

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, sz: u64) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_alloc(buf, slot, sz),
            PlatformKind::Linux => LinuxPlatform.emit_alloc(buf, slot, sz),
            PlatformKind::Stub => StubPlatform.emit_alloc(buf, slot, sz),
        }
    }

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_idx: u8) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_loadfile(buf, slot, str_idx),
            PlatformKind::Linux => LinuxPlatform.emit_loadfile(buf, slot, str_idx),
            PlatformKind::Stub => StubPlatform.emit_loadfile(buf, slot, str_idx),
        }
    }

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_idx: u8, sz: u16) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_writefile(buf, id, str_idx, sz),
            PlatformKind::Linux => LinuxPlatform.emit_writefile(buf, id, str_idx, sz),
            PlatformKind::Stub => StubPlatform.emit_writefile(buf, id, str_idx, sz),
        }
    }

    fn startup_blob(&self) -> &[u8] {
        match self {
            PlatformKind::Win32 => Win32Platform.startup_blob(),
            PlatformKind::Linux => LinuxPlatform.startup_blob(),
            PlatformKind::Stub => StubPlatform.startup_blob(),
        }
    }
}

// ── Stub Platform ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct StubPlatform;

impl Platform for StubPlatform {
    fn name(&self) -> &'static str { "stub" }

    fn emit_alloc<const N: usize>(&self, _buf: &mut FixedBuf<N>, _slot: u16, _sz: u64) -> IsaResult<()> {
        unimplemented!("StubPlatform does not support alloc")
    }
    fn emit_loadfile<const N: usize>(&self, _buf: &mut FixedBuf<N>, _slot: u16, _str_idx: u8) -> IsaResult<()> {
        unimplemented!("StubPlatform does not support loadfile")
    }
    fn emit_writefile<const N: usize>(&self, _buf: &mut FixedBuf<N>, _id: u16, _str_idx: u8, _sz: u16) -> IsaResult<()> {
        unimplemented!("StubPlatform does not support writefile")
    }
    fn startup_blob(&self) -> &[u8] { &[] }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Emit `FF 15 ii 00 00 00`: call [rip+ii]. The linker patches bytes 2..6
/// with the correct RIP-relative displacement to the IAT entry for `api`.
fn call_iat_thunk<const N: usize>(buf: &mut FixedBuf<N>, api: Win32Api) -> IsaResult<()> {
    buf.push(0xFF)?;
    buf.push(0x15)?;
    buf.push(api as u8)?; // API index (placeholder; will be overwritten)
    buf.push(0x00)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    Ok(())
}

/// Emit `lea rcx, [rip+0]` — placeholder for string address.
/// The linker patches the disp32 to point to the string in the data section.
fn lea_rcx_rip_placeholder<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0x8D)?;
    buf.push(0x0D)?;
    buf.extend(&0i32.to_le_bytes())?;
    Ok(())
}

fn lea_rdi_rip_placeholder<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0x8D)?;
    buf.push(0x3D)?;
    buf.extend(&0i32.to_le_bytes())?;
    Ok(())
}

/// Frame setup/teardown for kernel32 API calls: sub rsp, 0x28 / add rsp, 0x28
fn shadow_frame<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    sub_imm(buf, Reg::Rsp, 0x28)
}
fn shadow_ret<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    add_imm(buf, Reg::Rsp, 0x28)
}

// ── Win32 Platform ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct Win32Platform;

impl Platform for Win32Platform {
    fn name(&self) -> &'static str { "win32" }

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, sz: u64) -> IsaResult<()> {
        // VirtualAlloc(0, sz, 0x3000, 0x40)
        movabs(buf, Reg::Rcx, 0)?;
        movabs(buf, Reg::Rdx, sz)?;
        movabs(buf, Reg::R8, 0x3000)?;  // MEM_RESERVE|MEM_COMMIT
        movabs(buf, Reg::R9, 0x40)?;    // PAGE_EXECUTE_READWRITE
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::VirtualAlloc)?;
        shadow_ret(buf)?;
        store_state(buf, slot as u8, Reg::Rax)?;
        Ok(())
    }

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, _str_idx: u8) -> IsaResult<()> {
        // state[slot]   = pointer to file content
        // state[slot+1] = file size
        //
        // Sequence:
        //   1. lea rcx, [rip+str]   (placeholder)
        //   2. CreateFileA → hFile
        //   3. GetFileSize  → fileSize
        //   4. VirtualAlloc → contentBuf
        //   5. ReadFile
        //   6. CloseHandle

        let hfile_slot = (slot + 2) as u8;  // temp slot for hFile
        let size_slot = (slot + 1) as u8;

        // 1. Load filename pointer (placeholder, linker-patched)
        lea_rcx_rip_placeholder(buf)?;

        // 2. CreateFileA(rcx=filename, GENERIC_READ=0x80000000, FILE_SHARE_READ=1, NULL, OPEN_EXISTING=3, 0, NULL)
        movabs(buf, Reg::Rdx, 0x8000_0000u64)?;
        movabs(buf, Reg::R8, 1)?;
        movabs(buf, Reg::R9, 0)?;
        // 5th arg OPEN_EXISTING (3) goes on stack
        // push 3; sub rsp, 0x28; call; add rsp, 0x28; add rsp, 8
        movabs(buf, Reg::Rax, 3)?;
        buf.push(0x50)?; // push rax
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CreateFileA)?;
        shadow_ret(buf)?;
        add_imm(buf, Reg::Rsp, 8)?; // undo push
        store_state(buf, hfile_slot, Reg::Rax)?; // state[hfile] = hFile

        // 3. GetFileSize(rcx=hFile, rdx=NULL)
        load_state(buf, hfile_slot, Reg::Rcx)?;
        movabs(buf, Reg::Rdx, 0)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::GetFileSize)?;
        shadow_ret(buf)?;
        store_state(buf, size_slot, Reg::Rax)?; // state[slot+1] = fileSize

        // 4. VirtualAlloc(0, fileSize, MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_READWRITE=4)
        movabs(buf, Reg::Rcx, 0)?;
        load_state(buf, size_slot, Reg::Rdx)?;
        movabs(buf, Reg::R8, 0x3000)?;
        movabs(buf, Reg::R9, 4)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::VirtualAlloc)?;
        shadow_ret(buf)?;
        store_state(buf, slot as u8, Reg::Rax)?; // state[slot] = buf

        // 5. ReadFile(rcx=hFile, rdx=buf, r8=fileSize, r9=&bytesRead, NULL)
        load_state(buf, hfile_slot, Reg::Rcx)?;
        load_state(buf, slot as u8, Reg::Rdx)?;
        load_state(buf, size_slot, Reg::R8)?;
        // r9 = stack-based &bytesRead: sub rsp, 4; lea r9, [rsp]; but simpler: r9=0, ignore bytesRead
        movabs(buf, Reg::R9, 0)?;
        // 5th arg NULL
        movabs(buf, Reg::Rax, 0)?;
        buf.push(0x50)?; // push rax
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::ReadFile)?;
        shadow_ret(buf)?;
        add_imm(buf, Reg::Rsp, 8)?; // undo push

        // 6. CloseHandle(rcx=hFile)
        load_state(buf, hfile_slot, Reg::Rcx)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CloseHandle)?;
        shadow_ret(buf)?;

        Ok(())
    }

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, _str_idx: u8, sz: u16) -> IsaResult<()> {
        // state[id] = buffer to write
        // state[sz] = number of bytes
        //
        // Sequence:
        //   1. lea rcx, [rip+str] (placeholder)
        //   2. CreateFileA → hFile
        //   3. WriteFile
        //   4. CloseHandle

        let hfile_slot = (id + 1) as u8;

        // 1. Load filename (placeholder)
        lea_rcx_rip_placeholder(buf)?;

        // 2. CreateFileA(filename, GENERIC_WRITE=0x40000000, 0, NULL, CREATE_ALWAYS=2, 0, NULL)
        movabs(buf, Reg::Rdx, 0x4000_0000u64)?;
        movabs(buf, Reg::R8, 0)?;
        movabs(buf, Reg::R9, 0)?;
        movabs(buf, Reg::Rax, 2)?; // CREATE_ALWAYS
        buf.push(0x50)?; // push rax
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CreateFileA)?;
        shadow_ret(buf)?;
        add_imm(buf, Reg::Rsp, 8)?; // undo push
        store_state(buf, hfile_slot, Reg::Rax)?;

        // 3. WriteFile(rcx=hFile, rdx=state[id], r8=state[sz], r9=0, NULL)
        load_state(buf, hfile_slot, Reg::Rcx)?;
        load_state(buf, id as u8, Reg::Rdx)?;
        load_state(buf, sz as u8, Reg::R8)?;
        movabs(buf, Reg::R9, 0)?;
        movabs(buf, Reg::Rax, 0)?;
        buf.push(0x50)?; // push rax
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::WriteFile)?;
        shadow_ret(buf)?;
        add_imm(buf, Reg::Rsp, 8)?;

        // 4. CloseHandle(rcx=hFile)
        load_state(buf, hfile_slot, Reg::Rcx)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CloseHandle)?;
        shadow_ret(buf)?;

        Ok(())
    }

    fn startup_blob(&self) -> &[u8] {
        &[
            0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
            0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 (patched to H_00)
            0x48, 0x83, 0xC4, 0x08, // add rsp, 8
            0xC3, // ret
        ]
    }
}

// ── Linux Platform ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct LinuxPlatform;

impl LinuxPlatform {
    fn linux_syscall<const N: usize>(buf: &mut FixedBuf<N>, sysno: u64) -> IsaResult<()> {
        movabs(buf, Reg::Rax, sysno)?;
        buf.push(0x0F)?;
        buf.push(0x05)?;
        Ok(())
    }
}

impl Platform for LinuxPlatform {
    fn name(&self) -> &'static str { "linux" }

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, sz: u64) -> IsaResult<()> {
        movabs(buf, Reg::Rdi, 0)?;
        movabs(buf, Reg::Rsi, sz)?;
        movabs(buf, Reg::Rdx, 3)?; // PROT_READ|PROT_WRITE
        movabs(buf, Reg::R10, 0x22)?; // MAP_PRIVATE|MAP_ANONYMOUS
        movabs(buf, Reg::R8, (-1i64) as u64)?;
        movabs(buf, Reg::R9, 0)?;
        Self::linux_syscall(buf, 9)?; // mmap
        store_state(buf, slot as u8, Reg::Rax)?;
        Ok(())
    }

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, _str_idx: u8) -> IsaResult<()> {
        lea_rdi_rip_placeholder(buf)?; // filename placeholder
        movabs(buf, Reg::Rsi, 0)?; // O_RDONLY
        Self::linux_syscall(buf, 2)?; // open
        store_state(buf, 0, Reg::Rax)?; // state[0] = fd

        mov_r_r(buf, Reg::Rdi, Reg::Rax)?;
        movabs(buf, Reg::Rsi, 0)?;
        movabs(buf, Reg::Rdx, 2)?; // SEEK_END
        Self::linux_syscall(buf, 8)?;
        store_state(buf, (slot + 1) as u8, Reg::Rax)?; // state[slot+1] = size

        load_state(buf, 0, Reg::Rdi)?;
        movabs(buf, Reg::Rsi, 0)?;
        movabs(buf, Reg::Rdx, 0)?; // SEEK_SET
        Self::linux_syscall(buf, 8)?;

        movabs(buf, Reg::Rdi, 0)?;
        load_state(buf, (slot + 1) as u8, Reg::Rsi)?;
        movabs(buf, Reg::Rdx, 1)?; // PROT_READ
        movabs(buf, Reg::R10, 2)?; // MAP_PRIVATE
        load_state(buf, 0, Reg::R8)?;
        movabs(buf, Reg::R9, 0)?;
        Self::linux_syscall(buf, 9)?;
        store_state(buf, slot as u8, Reg::Rax)?;

        load_state(buf, 0, Reg::Rdi)?;
        Self::linux_syscall(buf, 3)?; // close
        Ok(())
    }

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, _str_idx: u8, sz: u16) -> IsaResult<()> {
        lea_rdi_rip_placeholder(buf)?; // filename placeholder
        movabs(buf, Reg::Rsi, 0x241)?; // O_WRONLY|O_CREAT|O_TRUNC
        movabs(buf, Reg::Rdx, 0x1A4)?; // 0644
        Self::linux_syscall(buf, 2)?;
        store_state(buf, 0, Reg::Rax)?;

        mov_r_r(buf, Reg::Rdi, Reg::Rax)?;
        load_state(buf, id as u8, Reg::Rsi)?;
        load_state(buf, sz as u8, Reg::Rdx)?;
        Self::linux_syscall(buf, 1)?;

        load_state(buf, 0, Reg::Rdi)?;
        Self::linux_syscall(buf, 3)?;
        Ok(())
    }

    fn startup_blob(&self) -> &[u8] {
        &[0xE9, 0x00, 0x00, 0x00, 0x00] // jmp H_00 (rel32 placeholder)
    }
}
