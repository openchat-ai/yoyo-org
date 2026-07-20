# v0.4 status (2026-07-16)

## ✅ Working (verified)

### T2+T5+T6 (verifier 改造, 7/15)
- GetCommandLineA 调通 (startup 调 kernel32 IAT, rax = PSTR cmdline)
- pe_link 5 bug 修:INT/IAT 8B、build_idata var-length、IAT scan arm、REX.B (mov r15)、RVA 变量名交换
- IatThunk +GetCommandLineA=15
- str_idx → str_slot (u8→u16):ISA + emit + platform + render 全同步
- Win32 startup 48 字节:GetCommandLineA + 栈存 + rdi=&save_slot 传 H_00
- H_50/H_51 改 rsi-arg:路径从 RSI 寄存器,状态用 r12/r13/r14,返回 rax=contentBuf/rdx=fileSize

### T7.5 (PE 装载器实验, 7/15)
- 实验 A: r15 + BSS_RVA (AV)
- 实验 B: r15 + INITIALIZED_DATA + FSize=0x1000 + file content (AV)
- 实验 C: SizeOfUninitializedData=0x1000 + DllCharacteristics=0x40 (DYNAMIC_BASE) + Subsystem=6.2 (AV)
- **结论:Win10 minimal PE 不认 BSS** (多个变体都 AV) → BSS 弃用,v0.4 改用栈

### T7.6 (yoy0.ty v0.4 MVP, 7/15-7/16)
- 写了 212 行 .ty:argv parser + copy cmdline to stack + H_50 + H_51 + cleanup
- rust 链 link 成功:141 TIR ops → 562 x64 bytes (含 48B startup)
- 7/16 修了 4 个 .ty bug:
  1. H_50 字节 4C 89 F4 → 4C 89 E6 (F4 是 mov rsp, r14;E6 才是 mov rsi, r12)
  2. H_51 字节 4C 89 F5 → 4C 89 B6 (F5 是 mov rbp, r14;B6 才是 mov rsi, r13)
  3. H_51 caller line 188 字节 C2 → D0 (C2 是 mov r10, rax;D0 才是 mov r8, rdx)
  4. `jz .copy_done` disp 0x02 → 0x08 (原值跳过 .copy_done 死循环越界读 OS heap)
  5. `.scan0` 加 null 检查 (argv[0] 没空格如 "yoy0-v0.4-rs.exe" 死循环越界读 OS heap)
- 7/16 修了 2 个 rust emit 错:
  6. emit_writefile line 429 `0x5D` (pop r13) → `0x55` (push r13):注释说 push 但字节 0x5D 是 pop r13,栈不平衡
  7. emit_loadfile/emit_writefile 的 CreateFileA 缺 stack args (7-arg Win32 调用):
     - shadow_frame 0x28 不够 (Win32 7-arg 需要 0x38 = 32 shadow + 24 stack args)
     - 显式 mov qword [rsp+0x20], 3 / [rsp+0x28], 0x80 / [rsp+0x30], 0
  8. emit_loadfile/emit_writefile 的 ReadFile/WriteFile 缺 stack arg (5-arg, 5th = lpOverlapped):
     - 显式 mov qword [rsp+0x20], 0
- 7/16 加 disasm subcommand (告别盲猜):
  - AGENTS.md 的 "yoy0-rust disasm 命令有 bug" 是误诊,根本不存在 disasm 命令
  - 加新 subcommand 用 read_text_section_auto + extract_text_slice + disasm::disasm 流水线
  - 支持 --from=N 跳过 startup

## ❌ Still broken

- **yoy0-v0.4-rs.exe 跑还是 AV (0xC0000005)** — 修了 3 个 bug 后,exit 仍 0xC0000005
- yoy0-rust `disasm` 命令有 bug (`cannot read disasm: 系统找不到指定的文件` 即使文件存在) — 没办法反汇编 .exe 找下一处 AV
- 推测:argv[1] 路径不对,或 H_51 emit 字节错 (line 178-180: 注释 "mov r8, rdx" 但字节 `49 89 C2` 实际是 mov r10, rax)
- v0.4 不锁 (用户选)

## 已 commit

- `9aef423` exp/007: yoy0.ty v0.4 fix 3 .ty bugs (H_50/H_51 bytes, jz disp, .scan0 null) — still AV
- `e97d81f` exp/007: add test-h50-stack.ty for future debug
- `cd1d99f` exp/007: yoy0.ty v0.4 H_50+H_51 wired, H_50 works, H_51 path-bug
- `c301922` exp/007: H_50/H_51 push callee-saved (r12/r13/r14) + remove null-terminate
- `3426580` exp/007: yoy0.ty v0.4 stack-state argv parser + H_50+H_51 wired (DEBUG)
- `2f43347` exp/007: yoy0.ty v0.4 starter (incomplete)
- `493c4dd` experiments/007 plan
- `48e0e42` T2+T5+T6 (verifier 改造)
- `a558835` H_50/H_51 rsi-arg 改造
- `63b1b75` C-route 实验 (BSS 仍然 AV)

## 决策

- v0.4 不锁 (用户选 7/15)
- yoy0.ty v0.4 完整版 deferred 到下次 session (1-2 天工作量)

## 下次继续

1. **修第 4 个 bug** — H_51 caller 字节错 (`49 89 C2` 应该是 `49 89 C6` = mov r8, rdx)
2. **找 yoy0-rust disasm bug** 或写 standalone disasm 工具 — 当前阻塞反汇编
3. 写 yoy0.ty v0.4 完整版 (H_30 emitter + H_01 scanner) — 1-2 天
4. 测试 M1.exe input.ty output.exe 跑通
5. yoy0-js DDC 对齐 (Sub-005)
6. yoy0-asm DDC 对齐 (Sub-006)
