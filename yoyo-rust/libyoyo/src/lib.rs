//! # libyoyo - YOYO Standard Library
//!
// libyoyo is a small standard library that abstracts platform operations
//! for portable `.ty` programs. The 9 functions below are the complete
//! surface that `.ty` source code can call into.
//!
//! ## Design
//!
//! Every `.ty` program is linked with libyoyo. When `.ty` calls
//! `0x20 ALLOC`, the yoyo.js compiler emits a call through a **function
//! table** at a known offset. The function table is the only
//! platform-specific part.
//!
//! ```text
//! yoyo.ty (portable source)
//!    �?yoyo.js compile
//! call [libyoyo_table + 0x00]  ; yoyo_alloc
//! call [libyoyo_table + 0x08]  ; yoyo_free
//! call [libyoyo_table + 0x10]  ; yoyo_open
//! ...
//! ```
//!
//! ## Function Table Layout
//!
//! The function table is 9 entries × 8 bytes = **72 bytes**:
//!
//! | Offset | Function | Signature |
//! |--------|----------|------------|
//! | 0x00 | `yoyo_alloc` | `(size: u64) -> *mut u8` |
//! | 0x08 | `yoyo_free` | `(ptr: *mut u8)` |
//! | 0x10 | `yoyo_open` | `(path: *const u8) -> i32` |
//! | 0x18 | `yoyo_read` | `(fd: i32, buf: *mut u8, len: u64) -> i64` |
//! | 0x20 | `yoyo_write` | `(fd: i32, buf: *const u8, len: u64) -> i64` |
//! | 0x28 | `yoyo_close` | `(fd: i32)` |
//! | 0x30 | `yoyo_exit` | `(code: i32)` |
//! | 0x38 | `yoyo_print` | `(s: *const u8)` |
//! | 0x40 | `yoyo_time` | `() -> u64` |
//!
//! ## Why 9 functions and not more?
//!
//! These 9 cover everything `.ty` programs need: memory, file I/O, exit.
//! More functions = more audit surface = less trustworthy. Keep minimal.

#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![cfg_attr(test, allow(dead_code))]

#[cfg(not(test))]
mod panic_handler {
    use core::panic::PanicInfo;
    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        // libyoyo never panics. If we do, it's a bug.
        // On baremetal, just halt. On hosted, the loader will catch this.
        loop {}
    }
}

/// Function table offsets. Used by `.ty` programs to call libyoyo.
///
/// These constants are written into the `.ty` source by yoyo.js when it
/// emits a libyoyo call. They are **architecture offsets**, not absolute
/// addresses �?the linker (or startup code) resolves them at load time.
pub const YOYO_ALLOC_OFFSET: u32 = 0x00;
pub const YOYO_FREE_OFFSET: u32 = 0x08;
pub const YOYO_OPEN_OFFSET: u32 = 0x10;
pub const YOYO_READ_OFFSET: u32 = 0x18;
pub const YOYO_WRITE_OFFSET: u32 = 0x20;
pub const YOYO_CLOSE_OFFSET: u32 = 0x28;
pub const YOYO_EXIT_OFFSET: u32 = 0x30;
pub const YOYO_PRINT_OFFSET: u32 = 0x38;
pub const YOYO_TIME_OFFSET: u32 = 0x40;

/// Total function table size: 9 entries × 8 bytes.
pub const TABLE_SIZE: usize = 9 * 8;  // 72 bytes

/// The function table itself. This is the platform-specific part.
///
/// On Linux/Windows: populated by the dynamic linker at load time.
/// On baremetal: populated by the startup code.
///
/// **Layout** (each entry is a function pointer, 8 bytes on x86-64):
/// ```text
/// offset 0x00: yoyo_alloc
/// offset 0x08: yoyo_free
/// offset 0x10: yoyo_open
/// offset 0x18: yoyo_read
/// offset 0x20: yoyo_write
/// offset 0x28: yoyo_close
/// offset 0x30: yoyo_exit
/// offset 0x38: yoyo_print
/// offset 0x40: yoyo_time
/// ```
#[repr(C, align(64))]
pub struct YoyoTable {
    pub yoyo_alloc: unsafe extern "C" fn(u64) -> *mut u8,
    pub yoyo_free:  unsafe extern "C" fn(*mut u8),
    pub yoyo_open:  unsafe extern "C" fn(*const u8) -> i32,
    pub yoyo_read:  unsafe extern "C" fn(i32, *mut u8, u64) -> i64,
    pub yoyo_write: unsafe extern "C" fn(i32, *const u8, u64) -> i64,
    pub yoyo_close: unsafe extern "C" fn(i32),
    pub     yoyo_exit:  unsafe extern "C" fn(i32) -> (),
    pub yoyo_print: unsafe extern "C" fn(*const u8),
    pub yoyo_time:  unsafe extern "C" fn() -> u64,
}

/// Symbol name embedded in the binary so the dynamic linker can find us.
#[link_section = ".rodata"]
pub static YOYO_TABLE_SYMBOL: [u8; 19] = [
    b'l', b'i', b'b', b'y', b'o', b'y', b'o', b'_',
    b't', b'a', b'b', b'l', b'e', 0, 0, 0, 0, 0, 0,
];

/// The actual function table. Filled in by the platform-specific init code.
#[cfg(not(test))]
#[link_section = ".data"]
pub static mut YOYO_TABLE_INSTANCE: YoyoTable = YoyoTable {
    yoyo_alloc: platform::yoyo_alloc,
    yoyo_free:  platform::yoyo_free,
    yoyo_open:  platform::yoyo_open,
    yoyo_read:  platform::yoyo_read,
    yoyo_write: platform::yoyo_write,
    yoyo_close: platform::yoyo_close,
    yoyo_exit:  platform::yoyo_exit,
    yoyo_print: platform::yoyo_print,
    yoyo_time:  platform::yoyo_time,
};

/// For tests: a placeholder table with null pointers
#[cfg(test)]
#[link_section = ".data"]
pub static mut YOYO_TABLE_INSTANCE: YoyoTable = YoyoTable {
    yoyo_alloc: dummy_alloc,
    yoyo_free:  dummy_free,
    yoyo_open:  dummy_open,
    yoyo_read:  dummy_read,
    yoyo_write: dummy_write,
    yoyo_close: dummy_close,
    yoyo_exit:  dummy_exit,
    yoyo_print: dummy_print,
    yoyo_time:  dummy_time,
};

#[cfg(test)]
unsafe extern "C" fn dummy_alloc(_: u64) -> *mut u8 { core::ptr::null_mut() }
#[cfg(test)]
unsafe extern "C" fn dummy_free(_: *mut u8) {}
#[cfg(test)]
unsafe extern "C" fn dummy_open(_: *const u8) -> i32 { -1 }
#[cfg(test)]
unsafe extern "C" fn dummy_read(_: i32, _: *mut u8, _: u64) -> i64 { -1 }
#[cfg(test)]
unsafe extern "C" fn dummy_write(_: i32, _: *const u8, _: u64) -> i64 { -1 }
#[cfg(test)]
unsafe extern "C" fn dummy_close(_: i32) {}
#[cfg(test)]
unsafe extern "C" fn dummy_exit(_: i32) {}
#[cfg(test)]
unsafe extern "C" fn dummy_print(_: *const u8) {}
#[cfg(test)]
unsafe extern "C" fn dummy_time() -> u64 { 0 }

// === Public API for `.ty` programs (via yoyo.js emit) ===

/// Allocate `size` bytes of executable memory.
/// Returns null pointer on failure.
///
/// `ty` mapping: opcode 0x20 ALLOC
///               �? call [YOYO_TABLE + 0x00]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_alloc(size: u64) -> *mut u8 {
    (YOYO_TABLE_INSTANCE.yoyo_alloc)(size)
}

/// Free memory previously allocated by `yoyo_alloc`.
///
/// `ty` mapping: opcode 0x20 with FREE flag, or implicit at exit
///               �? call [YOYO_TABLE + 0x08]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_free(ptr: *mut u8) {
    (YOYO_TABLE_INSTANCE.yoyo_free)(ptr)
}

/// Open a file. Returns file descriptor (�?0) or -1 on error.
///
/// `ty` mapping: opcode 0x50 LOAD_FILE
///               �? call [YOYO_TABLE + 0x10]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_open(path: *const u8) -> i32 {
    (YOYO_TABLE_INSTANCE.yoyo_open)(path)
}

/// Read from a file into a buffer. Returns bytes read or -1 on error.
///
/// `ty` mapping: opcode 0x50 LOAD_FILE (continuation)
///               �? call [YOYO_TABLE + 0x18]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_read(fd: i32, buf: *mut u8, len: u64) -> i64 {
    (YOYO_TABLE_INSTANCE.yoyo_read)(fd, buf, len)
}

/// Write a buffer to a file. Returns bytes written or -1 on error.
///
/// `ty` mapping: opcode 0x51 WRITE_FILE
///               �? call [YOYO_TABLE + 0x20]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_write(fd: i32, buf: *const u8, len: u64) -> i64 {
    (YOYO_TABLE_INSTANCE.yoyo_write)(fd, buf, len)
}

/// Close a file.
///
/// `ty` mapping: implicit on program exit, or explicit H_xx
///               �? call [YOYO_TABLE + 0x28]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_close(fd: i32) {
    (YOYO_TABLE_INSTANCE.yoyo_close)(fd)
}

/// Exit the program with the given exit code.
///
/// `ty` mapping: opcode 0xFF RET at end of program
///               �? call [YOYO_TABLE + 0x30] with code
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_exit(code: i32) {
    (YOYO_TABLE_INSTANCE.yoyo_exit)(code)
}

/// Print a null-terminated string to stdout.
///
/// `ty` mapping: opcode 0x?? PRINT (TBD, not in current ISA)
///               �? call [YOYO_TABLE + 0x38]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_print(s: *const u8) {
    (YOYO_TABLE_INSTANCE.yoyo_print)(s)
}

/// Get current time in milliseconds since Unix epoch.
///
/// `ty` mapping: opcode 0x?? TIME (TBD)
///               �? call [YOYO_TABLE + 0x40]
#[cfg(not(test))]
pub unsafe extern "C" fn yoyo_time() -> u64 {
    (YOYO_TABLE_INSTANCE.yoyo_time)()
}

// === Platform-specific implementations ===

#[cfg(target_os = "windows")]
mod platform {
    use core::arch::asm;

    // Windows bindings (FFI to kernel32.dll)
    extern "system" {
        fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut u8;
        fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
        fn CreateFileA(lpFileName: *const u8, dwDesiredAccess: u32, dwShareMode: u32,
                       lpSecurityAttributes: *mut u8, dwCreationDisposition: u32,
                       dwFlagsAndAttributes: u32, hTemplateFile: *mut u8) -> i32;
        fn ReadFile(hFile: i32, lpBuffer: *mut u8, nNumberOfBytesToRead: u32,
                    lpNumberOfBytesRead: *mut u32, lpOverlapped: *mut u8) -> i32;
        fn WriteFile(hFile: i32, lpBuffer: *const u8, nNumberOfBytesToWrite: u32,
                     lpNumberOfBytesWritten: *mut u32, lpOverlapped: *mut u8) -> i32;
        fn CloseHandle(hObject: i32) -> i32;
        fn ExitProcess(uExitCode: u32) -> !;
        // WriteFile_StdOut: removed (use WriteFile with GetStdHandle(-11) instead)
        fn GetStdHandle(nStdHandle: i32) -> *mut u8;
        fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut u8) -> i32;
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const MEM_RELEASE: u32 = 0x8000;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_READ: u32 = 0x1;
    const OPEN_EXISTING: u32 = 0x3;
    const CREATE_ALWAYS: u32 = 0x2;

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_alloc(size: u64) -> *mut u8 {
        VirtualAlloc(core::ptr::null_mut(), size as usize,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_free(ptr: *mut u8) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_open(path: *const u8) -> i32 {
        CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, core::ptr::null_mut(),
                    OPEN_EXISTING, 0x80, core::ptr::null_mut())
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_read(fd: i32, buf: *mut u8, len: u64) -> i64 {
        let mut bytes_read: u32 = 0;
        let result = ReadFile(fd, buf, len as u32, &mut bytes_read, core::ptr::null_mut());
        if result == 0 { -1 } else { bytes_read as i64 }
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_write(fd: i32, buf: *const u8, len: u64) -> i64 {
        let mut bytes_written: u32 = 0;
        let result = WriteFile(fd, buf, len as u32, &mut bytes_written, core::ptr::null_mut());
        if result == 0 { -1 } else { bytes_written as i64 }
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_close(fd: i32) {
        CloseHandle(fd);
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_exit(code: i32) {
        ExitProcess(code as u32);
    }

    #[no_mangle]
    #[cfg(not(test))]
    pub unsafe extern "C" fn yoyo_print(s: *const u8) {
        // Find length
        let mut len = 0;
        while *s.add(len) != 0 { len += 1; }
        // Get stdout handle (simplified �?use STD_OUTPUT_HANDLE = -11)
        // In real impl: GetStdHandle(-11)
        let stdout = GetStdHandle(-11i32) as i32;
        WriteFile(stdout, s, len as u32, 0 as *mut u32, 0 as *mut u8);
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_time() -> u64 {
        let mut ft: u64 = 0;
        GetSystemTimeAsFileTime(&mut ft as *mut _ as *mut u8);
        // Convert FILETIME (100ns since 1601) to ms since 1970
        (ft / 10_000) - 11_644_473_600_000
    }
}

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
mod platform {
    // Linux syscall numbers (x86-64)
    const SYS_READ: u64 = 0;
    const SYS_WRITE: u64 = 1;
    const SYS_OPEN: u64 = 2;
    const SYS_CLOSE: u64 = 3;
    const SYS_MMAP: u64 = 9;
    const SYS_EXIT: u64 = 60;

    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;
    const MAP_PRIVATE: u64 = 0x2;
    const MAP_ANONYMOUS: u64 = 0x20;

    const O_RDONLY: u64 = 0;
    const O_WRONLY: u64 = 1;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_alloc(size: u64) -> *mut u8 {
        let ptr: u64;
        asm!(
            "syscall",
            in("rax") SYS_MMAP,
            in("rdi") 0u64,           // addr
            in("rsi") size,           // length
            in("rdx") PROT_READ | PROT_WRITE | PROT_EXEC,
            in("r10") MAP_PRIVATE | MAP_ANONYMOUS,
            in("r8") 0xffff_ffff_ffffu64,  // fd = -1
            in("r9") 0u64,           // offset
            lateout("rax") ptr,
            out("rcx") _,
            out("r11") _,
        );
        if ptr > 0x7fff_ffff_0000u64 { core::ptr::null_mut() } else { ptr as *mut u8 }
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_free(ptr: *mut u8) {
        let _ret: u64;
        asm!(
            "syscall",
            in("rax") SYS_MMAP,  // munmap is syscall 11
            in("rdi") ptr as u64,
            in("rsi") 0u64,
            lateout("rax") _ret,
        );
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_open(path: *const u8) -> i32 {
        // Find length of null-terminated string
        let mut len = 0;
        while *path.add(len) != 0 { len += 1; }
        let fd: u64;
        asm!(
            "syscall",
            in("rax") SYS_OPEN,
            in("rdi") path as u64,
            in("rsi") O_RDONLY,
            in("rdx") 0u64,
            lateout("rax") fd,
        );
        fd as i32
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_read(fd: i32, buf: *mut u8, len: u64) -> i64 {
        let ret: u64;
        asm!(
            "syscall",
            in("rax") SYS_READ,
            in("rdi") fd as u64,
            in("rsi") buf as u64,
            in("rdx") len,
            lateout("rax") ret,
        );
        ret as i64
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_write(fd: i32, buf: *const u8, len: u64) -> i64 {
        let ret: u64;
        asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") fd as u64,
            in("rsi") buf as u64,
            in("rdx") len,
            lateout("rax") ret,
        );
        ret as i64
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_close(fd: i32) {
        let _ret: u64;
        asm!(
            "syscall",
            in("rax") SYS_CLOSE,
            in("rdi") fd as u64,
            lateout("rax") _ret,
        );
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_exit(code: i32) {
        asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") code as u64,
        );
        loop {}  // should not reach
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_print(s: *const u8) {
        // Find length
        let mut len = 0;
        while *s.add(len) != 0 { len += 1; }
        // Write to stdout (fd = 1)
        let _ret: u64;
        asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") 1u64,           // stdout
            in("rsi") s as u64,
            in("rdx") len as u64,
            lateout("rax") _ret,
        );
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_time() -> u64 {
        // clock_gettime(CLOCK_REALTIME, &ts)
        // Simplified: read /proc/uptime or use rdtsc
        // For now, return 0 (TBD)
        0
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod platform {
    // Baremetal / unknown platform
    #[allow(unused_imports)]
    use core::arch::asm;

    /// Static heap allocator (bump allocator)
    static mut HEAP_NEXT: usize = 0x100000;  // Start at 1MB
    static mut HEAP_END: usize = 0x200000;   // 1MB heap

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_alloc(size: u64) -> *mut u8 {
        let next = HEAP_NEXT;
        let aligned = (next + 15) & !15;  // 16-byte align
        if aligned + size as usize > HEAP_END {
            return core::ptr::null_mut();
        }
        HEAP_NEXT = aligned + size as usize;
        aligned as *mut u8
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_free(_ptr: *mut u8) {
        // No-op for bump allocator
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_open(_path: *const u8) -> i32 {
        -1  // Not supported on baremetal yet
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_read(_fd: i32, _buf: *mut u8, _len: u64) -> i64 {
        -1
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_write(_fd: i32, _buf: *const u8, _len: u64) -> i64 {
        -1
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_close(_fd: i32) {
        // No-op
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_exit(code: i32) {
        // Halt the CPU
        let _ = code;
        loop {
            unsafe {
                asm!("hlt");
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_print(s: *const u8) {
        // Write to VGA text buffer at 0xB8000
        let mut len = 0;
        while *s.add(len) != 0 { len += 1; }
        let vga = 0xb8000 as *mut u16;
        for i in 0..len {
            unsafe {
                *vga.add(i) = 0x0F00 | (*s.add(i) as u16);
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn yoyo_time() -> u64 {
        // Read PIT counter (simplified)
        let lo: u8;
        let hi: u8;
        unsafe {
            asm!("out 0x40, al", in("al") 0u8);
            asm!("in al, 0x40", out("al") lo);
            asm!("in al, 0x40", out("al") hi);
        }
        ((hi as u64) << 8) | (lo as u64)
    }
}

// === Tests ===

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_size_is_72_bytes() {
        assert_eq!(TABLE_SIZE, 72);
    }

    #[test]
    fn offsets_are_8_bytes_apart() {
        assert_eq!(YOYO_FREE_OFFSET, 8);
        assert_eq!(YOYO_OPEN_OFFSET, 16);
        assert_eq!(YOYO_READ_OFFSET, 24);
        assert_eq!(YOYO_WRITE_OFFSET, 32);
        assert_eq!(YOYO_CLOSE_OFFSET, 40);
        assert_eq!(YOYO_EXIT_OFFSET, 48);
        assert_eq!(YOYO_PRINT_OFFSET, 56);
        assert_eq!(YOYO_TIME_OFFSET, 64);
    }
}
