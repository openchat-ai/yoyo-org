use std::fmt::Debug;
use crate::primitives::*;
use crate::types::{FixedBuf, IsaResult, Reg};

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
    "libyoyo_alloc",
    "libyoyo_free",
    "libyoyo_open",
    "libyoyo_read",
    "libyoyo_write",
    "libyoyo_close",
    "libyoyo_exit",
    "libyoyo_print",
    "libyoyo_time",
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

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, sz: u64) -> IsaResult<()>;
    /// v0.4: `str_slot` (runtime state slot holding the path PSTR),
    /// replacing legacy `str_idx` (compile-time string-table index).
    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_slot: u16) -> IsaResult<()>;
    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_slot: u16, sz: u16) -> IsaResult<()>;
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

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_slot: u16) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_loadfile(buf, slot, str_slot),
            PlatformKind::Linux => LinuxPlatform.emit_loadfile(buf, slot, str_slot),
            PlatformKind::Stub => StubPlatform.emit_loadfile(buf, slot, str_slot),
        }
    }

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_slot: u16, sz: u16) -> IsaResult<()> {
        match self {
            PlatformKind::Win32 => Win32Platform.emit_writefile(buf, id, str_slot, sz),
            PlatformKind::Linux => LinuxPlatform.emit_writefile(buf, id, str_slot, sz),
            PlatformKind::Stub => StubPlatform.emit_writefile(buf, id, str_slot, sz),
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

    fn emit_alloc<const N: usize>(&self, buf: &mut FixedBuf<N>, _slot: u16, _sz: u64) -> IsaResult<()> {
        // stub: set state[slot] = 0 (no real alloc)
        emit_st_loadfile(buf, 0, _slot)
    }
    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, _str_slot: u16) -> IsaResult<()> {
        emit_st_loadfile(buf, 0, slot)
    }
    fn emit_writefile<const N: usize>(&self, _buf: &mut FixedBuf<N>, _id: u16, _str_slot: u16, _sz: u16) -> IsaResult<()> {
        // stub: no-op (success)
        Ok(())
    }
    fn startup_blob(&self) -> &[u8] { &[] }
}

/// Emit stub code: state[slot] = rax, state[slot+1] = rax
/// Matches yoy-asm's loadfile stub (just two stores, no xor).
/// NOTE: yoy-asm does NOT emit `xor eax, eax` here, so we don't either.
/// Caller must arrange for rax to be 0 before calling this stub.
fn emit_st_loadfile<const N: usize>(buf: &mut FixedBuf<N>, _val: u64, slot: u16) -> IsaResult<()> {
    // mov [r15+slot*8], rax  (caller must ensure rax holds the desired value)
    store_r15(buf, slot)?;
    // mov [r15+(slot+1)*8], rax
    store_r15(buf, slot + 1)?;
    Ok(())
}

/// Emit `49 89 47 XX` (disp8) or `49 89 87 XX XX XX XX` (disp32)
fn store_r15<const N: usize>(buf: &mut FixedBuf<N>, slot: u16) -> IsaResult<()> {
    buf.push(0x49)?;
    buf.push(0x89)?;
    if slot < 16 {
        buf.push(0x47)?;
        buf.push(slot as u8)?;
    } else {
        buf.push(0x87)?;
        buf.extend(&(slot as u32).to_le_bytes())?;
    }
    Ok(())
}

// ── libyoyo_* call emitters (Phase 4c) ───────────────────────────────

/// Emit `lea rdi, [r15 + slot*8]` (load path/arg from state)
fn load_state_addr_rdi<const N: usize>(buf: &mut FixedBuf<N>, slot: u16) -> IsaResult<()> {
    // lea rdi, [r15 + slot*8]
    buf.push(0x48)?;
    buf.push(0x8D)?;
    buf.push(0xBF)?;
    buf.extend(&(slot as u32).to_le_bytes())?;
    Ok(())
}

/// Emit `mov rdi, <imm64>` - load 64-bit immediate into rdi
fn movabs_rdi_imm<const N: usize>(buf: &mut FixedBuf<N>, imm: u64) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0xBF)?;
    buf.extend(&imm.to_le_bytes())?;
    Ok(())
}

/// Emit `mov rsi, <imm64>` - load 64-bit immediate into rsi
fn movabs_rsi_imm<const N: usize>(buf: &mut FixedBuf<N>, imm: u64) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0xBE)?;
    buf.extend(&imm.to_le_bytes())?;
    Ok(())
}

/// Emit `mov rdx, <imm64>` - load 64-bit immediate into rdx
fn movabs_rdx_imm<const N: usize>(buf: &mut FixedBuf<N>, imm: u64) -> IsaResult<()> {
    buf.push(0x48)?;
    buf.push(0xBA)?;
    buf.extend(&imm.to_le_bytes())?;
    Ok(())
}

/// Emit `E8 <rel32>` (near call) with placeholder for later fixup
fn call_rel32_placeholder<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0xE8)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    Ok(())
}

/// Emit `call [rip+rel32]` (FF 15 ...) with placeholder for later fixup
fn call_indirect_rip_placeholder<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<()> {
    buf.push(0xFF)?;
    buf.push(0x15)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    buf.push(0x00)?;
    Ok(())
}

/// Place a placeholder for a libyoyo call fixup, return offset of the rel32
pub fn emit_libyoyo_call_marker<const N: usize>(buf: &mut FixedBuf<N>) -> IsaResult<u32> {
    // Emit `call [rip + rel32_placeholder]`, return offset of rel32 (after FF 15)
    call_indirect_rip_placeholder(buf)?;
    // The rel32 starts at buf.len() - 4
    Ok(buf.len() as u32 - 4)
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

/// Public version of call_iat_thunk - used by emit.rs for libyoyo_* opcodes.
impl Win32Api {
    pub fn emit_call<const N: usize>(&self, buf: &mut FixedBuf<N>) -> IsaResult<()> {
        call_iat_thunk(buf, *self)
    }
}

/// Emit `lea rdi, [rip+str_offset_placeholder]` - load address of str_idx string.
/// The linker patches the rel32 to point to the actual string in .data section.
/// For libyoyo_open, str_idx is an index into the .tyo string table.
pub fn emit_str_idx_addr<const N: usize>(buf: &mut FixedBuf<N>, _str_idx: u8) -> IsaResult<()> {
    // For now, emit lea rdi, [rip+rel32] with placeholder rel32=0
    // The linker should patch this. (TODO: implement in pe_link.rs)
    buf.push(0x48)?;  // REX.W
    buf.push(0x8D)?;  // LEA
    buf.push(0x3D)?;  // ModRM: mod=00 reg=rdi(111) r/m=101 (RIP-relative)
    buf.push(0x00)?;  // rel32[0]
    buf.push(0x00)?;  // rel32[1]
    buf.push(0x00)?;  // rel32[2]
    buf.push(0x00)?;  // rel32[3]
    Ok(())
}

/// Emit `lea rcx, [rip+0]` - placeholder for string address.
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

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_slot: u16) -> IsaResult<()> {
        // v0.4 sequence (path from RSI register, BSS unwritable on Win10):
        //   0. caller (yoy0.ty v0.4) sets RSI = PSTR path before CALL H_50
        //   1. mov rcx, rsi  ; path from caller (Win64 ABI: rsi is non-volatile)
        //   2. CreateFileA → hFile (in r12, non-volatile callee-saved)
        //   3. GetFileSize  → fileSize (in r13)
        //   4. VirtualAlloc → contentBuf (in r14)
        //   5. ReadFile → contentBuf
        //   6. CloseHandle
        //   7. return: rax = contentBuf, rdx = fileSize
        //
        // yoy0.ty v0.4 H_00 must push r12/r13/r14 on entry, pop on return.
        // str_slot argument is kept in TIR for future state-based paths; ignored here.

        let _ = str_slot;
        let _ = slot;

        // Push callee-saved (r12, r13, r14 used internally as scratch)
        // Win64 ABI requires callee to preserve these.
        buf.push(0x41)?; buf.push(0x54)?; // push r12
        buf.push(0x41)?; buf.push(0x55)?; // push r13
        buf.push(0x41)?; buf.push(0x56)?; // push r14

        // 1. Path from RSI
        mov_r_r(buf, Reg::Rcx, Reg::Rsi)?;

        // 2. CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
        //    CreateFileA is a 7-arg Win32 API. The 5th, 6th, 7th args are stack-passed
        //    and must be written to [rsp+0x20], [rsp+0x28], [rsp+0x30] explicitly —
        //    shadow_frame(0x28) alone leaves them uninitialized (Windows loader then
        //    uses random caller-stack values for hTemplateFile → CreateFileA AV).
        movabs(buf, Reg::Rdx, 0x8000_0000u64)?;
        movabs(buf, Reg::R8, 1)?;
        movabs(buf, Reg::R9, 0)?;
        movabs(buf, Reg::Rax, 3)?; // OPEN_EXISTING  (also written to stack below)
        sub_imm(buf, Reg::Rsp, 0x38)?; // 56 = 32 shadow + 24 (3 stack args × 8)
        mov_qword_rsp_disp_imm32(buf, 0x20, 3)?;    // 5th arg = OPEN_EXISTING
        mov_qword_rsp_disp_imm32(buf, 0x28, 0x80)?; // 6th arg = FILE_ATTRIBUTE_NORMAL
        mov_qword_rsp_disp_imm32(buf, 0x30, 0)?;    // 7th arg = NULL hTemplateFile
        call_iat_thunk(buf, Win32Api::CreateFileA)?;
        add_imm(buf, Reg::Rsp, 0x38)?;
        mov_r_r(buf, Reg::R12, Reg::Rax)?;

        // 3. GetFileSize(hFile=r12, NULL)
        mov_r_r(buf, Reg::Rcx, Reg::R12)?;
        movabs(buf, Reg::Rdx, 0)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::GetFileSize)?;
        shadow_ret(buf)?;
        mov_r_r(buf, Reg::R13, Reg::Rax)?;

        // 4. VirtualAlloc(0, fileSize, 0x3000, 0x40)
        movabs(buf, Reg::Rcx, 0)?;
        mov_r_r(buf, Reg::Rdx, Reg::R13)?;
        movabs(buf, Reg::R8, 0x3000)?;
        movabs(buf, Reg::R9, 0x40)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::VirtualAlloc)?;
        shadow_ret(buf)?;
        mov_r_r(buf, Reg::R14, Reg::Rax)?;

        // 5. ReadFile(hFile=r12, contentBuf=r14, fileSize=r13, NULL, NULL)
        //    5-arg call, 5th arg (lpOverlapped) is stack at [rsp+0x20]
        mov_r_r(buf, Reg::Rcx, Reg::R12)?;
        mov_r_r(buf, Reg::Rdx, Reg::R14)?;
        mov_r_r(buf, Reg::R8, Reg::R13)?;
        movabs(buf, Reg::R9, 0)?;       // NULL lpNumberOfBytesRead
        sub_imm(buf, Reg::Rsp, 0x28)?;
        mov_qword_rsp_disp_imm32(buf, 0x20, 0)?; // 5th arg = NULL lpOverlapped
        call_iat_thunk(buf, Win32Api::ReadFile)?;
        add_imm(buf, Reg::Rsp, 0x28)?;

        // 6. CloseHandle(hFile=r12)
        mov_r_r(buf, Reg::Rcx, Reg::R12)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CloseHandle)?;
        shadow_ret(buf)?;

        // 7. Return: rax = contentBuf, rdx = fileSize (fall through, no ret — inline code)
        mov_r_r(buf, Reg::Rax, Reg::R14)?;
        mov_r_r(buf, Reg::Rdx, Reg::R13)?;
        // Pop callee-saved (no ret — inline code falls through to next instruction)
        buf.push(0x41)?; buf.push(0x5E)?; // pop r14
        buf.push(0x41)?; buf.push(0x5D)?; // pop r13
        buf.push(0x41)?; buf.push(0x5C)?; // pop r12
        Ok(())
    }

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_slot: u16, sz: u16) -> IsaResult<()> {
        // v0.4 sequence (path from RSI, content from r8, size from rdx):
        //   0. caller sets RSI = path, R8 = contentBuf, RDX = fileSize
        //   1. mov rcx, rsi  ; path
        //   2. CreateFileA → hFile (in r12, callee-saved)
        //   3. WriteFile(hFile, contentBuf, fileSize)
        //   4. CloseHandle
        //
        // yoy0.ty v0.4 H_00 must push r12 on entry, pop on return.
        // Uses r12 instead of state[slot] because BSS is unwritable on Win10.

        let _ = str_slot; // ignored
        let _ = id;       // ignored
        let _ = sz;       // ignored

        // Push callee-saved (r12=hFile, r13=contentBuf, r14=fileSize)
        buf.push(0x41)?; buf.push(0x54)?; // push r12
        buf.push(0x41)?; buf.push(0x55)?; // push r13
        buf.push(0x41)?; buf.push(0x56)?; // push r14

        // Save caller's contentBuf (rdx) and fileSize (r8) before CreateFileA clobbers them
        mov_r_r(buf, Reg::R13, Reg::Rdx)?; // r13 = contentBuf
        mov_r_r(buf, Reg::R14, Reg::R8)?;  // r14 = fileSize

        // 1. Path from RSI
        mov_r_r(buf, Reg::Rcx, Reg::Rsi)?;

        // 2. CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)
        //    Same 7-arg problem as H_50: write stack args explicitly.
        movabs(buf, Reg::Rdx, 0x4000_0000u64)?;
        movabs(buf, Reg::R8, 0)?;  // dwShareMode = 0
        movabs(buf, Reg::R9, 0)?;
        movabs(buf, Reg::Rax, 2)?; // CREATE_ALWAYS
        sub_imm(buf, Reg::Rsp, 0x38)?; // 56 = 32 shadow + 24 (3 stack args × 8)
        mov_qword_rsp_disp_imm32(buf, 0x20, 2)?;    // 5th arg = CREATE_ALWAYS
        mov_qword_rsp_disp_imm32(buf, 0x28, 0)?;    // 6th arg = 0 (no special flags)
        mov_qword_rsp_disp_imm32(buf, 0x30, 0)?;    // 7th arg = NULL hTemplateFile
        call_iat_thunk(buf, Win32Api::CreateFileA)?;
        add_imm(buf, Reg::Rsp, 0x38)?;
        // hFile in r12
        mov_r_r(buf, Reg::R12, Reg::Rax)?;

        // 3. WriteFile(hFile=r12, contentBuf=r13, fileSize=r14, NULL, NULL)
        //    5-arg call, 5th arg (lpOverlapped) is stack at [rsp+0x20]
        mov_r_r(buf, Reg::Rcx, Reg::R12)?;
        mov_r_r(buf, Reg::Rdx, Reg::R13)?;  // contentBuf from saved r13
        mov_r_r(buf, Reg::R8, Reg::R14)?;   // fileSize from saved r14
        movabs(buf, Reg::R9, 0)?;            // NULL lpNumberOfBytesRead
        sub_imm(buf, Reg::Rsp, 0x28)?;
        mov_qword_rsp_disp_imm32(buf, 0x20, 0)?; // 5th arg = NULL lpOverlapped
        call_iat_thunk(buf, Win32Api::WriteFile)?;
        add_imm(buf, Reg::Rsp, 0x28)?;

        // 4. CloseHandle(hFile=r12)
        mov_r_r(buf, Reg::Rcx, Reg::R12)?;
        shadow_frame(buf)?;
        call_iat_thunk(buf, Win32Api::CloseHandle)?;
        shadow_ret(buf)?;

        // Pop callee-saved
        buf.push(0x41)?; buf.push(0x5E)?; // pop r14
        buf.push(0x41)?; buf.push(0x5D)?; // pop r13
        buf.push(0x41)?; buf.push(0x5C)?; // pop r12
        Ok(())
    }

    fn startup_blob(&self) -> &[u8] {
        // Win32 v0.4 startup (48 bytes — stack-argv pivot, BSS-backed state):
        //   [0..1]     mov r15 prefix 0x49 0xBF
        //   [2..9]     IMM64 placeholder (BSS_RVA — v0.4 H_00 immediately overwrites via lea r15)
        //   [10..13]   sub rsp, 0x28 (4B) — shadow space for GetCommandLineA
        //   [14..19]   call [rip+rel] idx=15 GetCommandLineA (6B) → rax = PSTR cmdline
        //   [20..24]   mov [rsp+0x20], rax (5B) — save cmdline at rsp+0x20 in shadow frame
        //   [25..28]   add rsp, 0x28 (4B) — pop shadow frame (rsp restored)
        //   [29..33]   lea rdi, [rsp+0x18] (5B) — rdi = &save_slot (which is at rsp+0x20 right
        //              before adding 0x28, i.e. now rsp+0x18 because rsp already restored)
        //              Actually simpler: the save_slot location was rsp+0x20 when rsp was
        //              shadow-frame size below. After add rsp 0x28, save_slot is at
        //              rsp+0x20 - 0x28 = rsp - 0x08. So `lea rdi, [rsp - 8]`.
        //   [34..37]   sub rsp, 0x08 (4B)
        //   [38..42]   call rel32 (H_00); E8 at 38, rel32 at 39 — push return addr
        //   [43..46]   NO add rsp, 0x08 — REMOVED: the sub rsp 0x08 was for Win64 ABI
        //              16-byte stack alignment before call (call requires aligned rsp).
        //              After the call, rsp was X-0x18 (call push ret) and H_00 ret
        //              left rsp at X-0x18+8 = X-0x10. Restoring original sub means
        //              X - 0x10 + 0x08 = X - 0x08. But we want rsp = X (entry).
        //              **So don't sub rsp, 0x08 in the first place**, OR balance it.
        //              Cleaner fix: don't sub at all.
        //   [43..46]   ... actually replace with same `add rsp 0x08` to undo
        //   [47]       ret
        //
        // KNOWN BUG in v3 startup: the `sub rsp, 0x08 / add rsp, 0x08` pair leaves rsp
        // at X-0x08 instead of X when control reaches `ret`. The cmdline ptr saved in
        // [X-0x10] via `mov [rsp+0x20], rax` then gets popped as RIP by the final `ret`,
        // causing AV. Fix: drop the sub rsp, 0x08 + add rsp, 0x08 pair entirely.
        //
        // WIN64 ABI alignment: when calling H_00, rsp must be 16-byte aligned.
        // The push rsp - 8 from `sub rsp, 0x28` ensures [rsp+0x20] sits on a 16-aligned
        // boundary. We skip sub rsp, 0x08; the `call H_00` itself pushes 8 bytes
        // (return addr), making rsp 16-aligned within H_00 if it was 16-aligned before.
        // The PE loader transfers control to the entrypoint with rsp 16-byte aligned
        // minus 8, so after `sub rsp, 0x28` (40-byte frame) rsp stays 16-byte aligned
        // because 40 is a multiple of 16. After `add rsp, 0x28` and before any further
        // sub, rsp is again 16-aligned. Adding 8-byte ret-push inside H_00 keeps alignment.

        // Layout (48 bytes, padded with NOPs):
        //   [0..9]   mov r15, BSS_RVA (imm64 patched by pe_link at [2..10])
        //   [10..15] call [rip+rel] GetCommandLineA → rax = PSTR cmdline
        //   [16]     push rax        (save cmdline ptr at [rsp], survives call H_00)
        //   [17..19] mov rdi, rsp    (rdi = &save_slot; H_00 reads [rdi] = cmdline PSTR)
        //   [20..24] call rel32 (H_00) — E8 at 20, rel32 at 21..24 (patched by pe_link E8 scan)
        //   [25]     pop rcx         (discard saved cmdline, restore rsp to entry value)
        //   [26]     ret             (pop original return addr)
        &[
            0x49, 0xBF, 0x00, 0x00, 0x00, 0x00, // mov r15, BSS_RVA (placeholder)
            0x00, 0x00, 0x00, 0x00,             //
            0xFF, 0x15, 0x0F, 0x00, 0x00, 0x00, // call [rip+rel] GetCommandLineA
            0x50,                               // push rax  (cmdline ptr on stack)
            0x48, 0x89, 0xE7,                   // mov rdi, rsp (rdi = &cmdline ptr)
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call rel32 (H_00) — E8 at offset 20
            0x59,                               // pop rcx (unwind stack)
            0xC3,                               // ret
            0x90, 0x90, 0x90, 0x90, 0x90,       // pad NOPs to 48 bytes
            0x90, 0x90, 0x90, 0x90, 0x90,       //
            0x90, 0x90, 0x90, 0x90, 0x90,       //
            0x90, 0x90, 0x90, 0x90, 0x90,       //
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, //
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

    fn emit_loadfile<const N: usize>(&self, buf: &mut FixedBuf<N>, slot: u16, str_slot: u16) -> IsaResult<()> {
        lea_reg_r15(buf, Reg::Rdi, str_slot)?; // filename from runtime state
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

    fn emit_writefile<const N: usize>(&self, buf: &mut FixedBuf<N>, id: u16, str_slot: u16, sz: u16) -> IsaResult<()> {
        lea_reg_r15(buf, Reg::Rdi, str_slot)?; // filename from runtime state
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
