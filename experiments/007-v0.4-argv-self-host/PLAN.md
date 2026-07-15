# v0.4 argv-aware self-host — Plan (3 days)

## 目标

`yoy0.exe input.ty output.exe` 不再用 `input.ky` 中间文件，且产出 yoy0-ty-compatible v0.4。

V3 Part 7.6 libyoyo_ API 严格守约。

## 路线（rust 优先单链通）

### T1: 调研（已完成）
- verifier 不依赖 libyoyo crate — 独立 IAT 表
- emit_loadfile/writefile 当前用 `str_idx` (compile-time 字符串常量)
- Win32Platform::startup_blob 24 bytes，缺 argv 入口

### T2: IAT thunk 新增 GetCommandLineA（1 enum + IAT 表项）
```rust
// platform.rs
pub enum IatThunk {
    // ... 现有 15 个
    GetCommandLineA = 15,    // Win32 API
    // LibyoyoArgv = 16,      // 不需要；yoy0.ty 自己 parser
}
```

### T5: Platform trait str_idx → str_slot

```rust
// platform.rs
pub trait Platform {
    // 改签名
    fn emit_loadfile<const N: usize>(&self, buf, slot: u16, str_slot: u16) -> IsaResult<()>;
    fn emit_writefile<const N: usize>(&self, buf, id: u16, str_slot: u16, sz: u16) -> IsaResult<()>;
}

// Win32Platform::emit_loadfile 内部
lea rcx_addr_r15(buf, str_slot)?;   // = `48 8D 8D <disp32>` (7B)
// 不再用 lea_rcx_rip_placeholder
```

### T6: startup_blob 拓字节（24→40 bytes）

当前 24 bytes:
```asm
sub rsp, 8              ; 48 83 EC 08
mov r15, BSS_RVA        ; 48 B8 <imm64>  (8B placeholder)
call H_00               ; E8 <rel32>     (5B placeholder)
add rsp, 8              ; 48 83 C4 08
ret                     ; C3
```

新 40 bytes:
```asm
; === NEW: argv capture ===
sub rsp, 0x28           ; 48 81 EC 28 00 00 00  (7B)
mov rcx, 0              ; 48 C7 C1 00 00 00 00 (7B)  ; arg1 placeholder for GetCommandLineA
call [rip+rel32]        ; FF 15 <rel32>         (6B)  ; GetCommandLineA IAT
mov [r15+0x2A0], rax    ; 49 89 87 A0 02 00 00  (7B)  ; state[0x54] = PSTR cmdline
add rsp, 0x28           ; 48 81 C4 28 00 00 00  (7B)
                        ; 小计: 7+7+6+7+7 = 34 B ≈ 40 B (含对齐)
; === 原 startup ===
sub rsp, 8              ; 48 83 EC 08
mov r15, BSS_RVA        ; 48 B8 <imm64>
call H_00               ; E8 <rel32>
add rsp, 8              ; 48 83 C4 08
ret                     ; C3
```

新增 fixup：
- `BSS_RVA` placeholder（已存在）— bytes for pe_link patch
- `FF 15 <rel32>` GetCommandLineA — new IAT fixup entry

### T7: yoy0.ty v0.4 — 启动 sequence + argv parser

```asm
; === constants ===
00 00 30 54 00          ; state[0x54] = cmdline ptr (filled by startup)
00 00 30 5A 00          ; state[0x5A] = argv[1] ptr (input.ty)
00 00 30 5B 00          ; state[0x5B] = argv[2] ptr (output.exe)
00 00 30 5C 00          ; state[0x5C] = parser cursor
00 00 30 5D 00          ; state[0x5D] = current arg index (0=yoy0.exe, 1=input, 2=output)

; === H_00: arg-parse entry ===
00 00 40 00             ; H_00
00 00 30 18 00          ; state[0x18] = budget
00 00 61 5A 54          ; state[0x5A] = state[0x54]   (initial argv[1] = start of cmdline)
00 00 30 5C 5A          ; state[0x5C] = state[0x5A]   (cursor = argv[1])
00 00 30 5D 00          ; state[0x5D] = 0
00 00 A1 65 6c 6c 6f 00 ; add "hello\0"  (scratch)

; ... parse loop: skip spaces, identify argv[1]/argv[2]...
00 00 70 XX             ; jmp H_50 (load input)
00 00 70 YY             ; jmp H_30 (emit)
00 00 70 ZZ             ; jmp H_51 (write output)
00 00 FF                ; ret
```

(具体 250 行规划待 T7 时落实)

### T8–T11: 测试 + DDC + commit
- T8: rust 链 link yoy0.ty v0.4 → M1 (byte-equal with js prototype? 可能不，因为 emit 签 名变了)
- T9: `M1.exe yoy0.ty output.exe` 跑通 (no input.ky)
- T10: M1≡M2≡M3 (rust chain 内部 byte-equal)
- T11: git commit, 不锁 (留 v1.0)

## 文件改动清单

| 文件 | 改动 |
|------|------|
| yoyo-rust/verifier/src/platform.rs | T2 (IAT), T5 (str_slot), T6 (startup_blob) |
| yoyo-rust/verifier/src/isa.rs | T5 (LOADFILE/WRITEFILE 文档注释) |
| yoyo-rust/verifier/src/emit.rs | T5 (TirOp match arm `str_idx` → `str_slot`) |
| yoyo-rust/verifier/src/ty_parser.rs | T5 (LOADFILE/WRITEFILE 字节解析) |
| yoyo-rust/verifier/src/pe_link.rs | T6 (new IAT fixup: GetCommandLineA) |
| yoyo/projects/yoy0.ty | v0.4: T7 (replaced completely, ~250 行) |
| yoyo-rust/verifier/src/render.rs | 更新 disasm 注释 |

## DDC byte-equal 目标

v0.4 不锁。内部链 (rust) M1≡M2≡M3 byte-equal 必须达成。
三链 (js / rust / asm) byte-equal **不强求** v0.4 完成 — 留 v1.0 lockdown 收敛。

## 测试 checklist

1. `cargo build --release -p verifier` — 编译通过
2. `node tests/test-yoy0-v0.4.ty` → M1.exe — yoy0.ty v0.4 编译测试
3. `M1.exe yoy0-ty/ty/v0.4/yoy0.ty output.exe` — 跑通 exit 0
4. `M2 = M1 跑出的 output.exe`
5. `M2.exe yoy0-ty/ty/v0.4/yoy0.ty output2.exe` — M3
6. SHA(M1) ≡ SHA(M2) ≡ SHA(M3) — 链 byte-equal
7. `M3.exe yoy0-ty/ty/v0.4/yoy0.ty output3.exe` — M4 (再一代, 不要求 SHA)

## 风险 + 缓解

| 风险 | 缓解 |
|------|------|
| yoy0.ty v0.4 argv parser bug | 先写 standalone parse test (test-argv.ty), 跑通再合 |
| Win64 GetCommandLineA 在 entry 还没设置时调用 | PE entry 之后才能用 kernel32 — OK |
| str_slot 改动破坏现有 yoy0.ty v0.1 | yoy0.ty v0.4 完全替 v0.1, 老版本独立 commit |
| pe_link.rs 加 IAT fixup — fixup pass 出错 | 跟 Sub-D 一样的 fixup pass, 复用模式 |
