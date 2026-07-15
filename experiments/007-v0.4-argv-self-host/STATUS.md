# v0.4 status (2026-07-15)

## 完成

### T2+T5+T6：verifier 改造
- pe_link 5 bug 修：INT/IAT 8B、build_idata layout (var-length)、IAT scan arm、REX.B、dll_name_rva 变量名交换
- IatThunk +GetCommandLineA=15
- str_idx → str_slot (u8→u16)：ISA 表 + emit + platform + render
- Win32 startup 调用 GetCommandLineA：
  - mov r15, BSS_RVA (虽然 BSS 不可写但 r15 作为兼容)
  - sub rsp, 0x28 (shadow 0x20 + save slot 0x08)
  - call [rip+rel] GetCommandLineA → rax = PSTR cmdline
  - mov [rsp+0x20], rax (save in save slot — below caller's retaddr)
  - add rsp, 0x28; lea rdi, [rsp-8] (rdi = &save_slot)
  - sub rsp, 8; call rel32 H_00; add rsp, 8
- **验证**：单 ret .ty 跑 exit = PSTR cmdline 地址（4998272 = 0x4C4E40 等）

### H_50/H_51 emit 改造（rsi-arg path）
- emit_loadfile: 路径从 RSI 寄存器取（不再是 state[slot]）
- emit_writefile: 路径从 RSI，内容从 r8，大小从 rdx
- 内部状态用 r12/r13/r14（非易失 callee-saved）：
  - r12 = hFile
  - r13 = fileSize
  - r14 = contentBuf
- 返回：rax = contentBuf, rdx = fileSize
- yoy0.ty v0.4 H_00 必须 push r12/r13/r14 on entry，pop on return

## 未完成（剩余工作）

### BSS 不可写（Win10 minimal PE）
- 即使 `INITIALIZED_DATA + FSize=0x1000 + file content zeros` 仍 AV
- Win10 loader 对 minimal PE 的 BSS 处理严格

### yoy0.ty v0.4 未写
- 需要 stack-relative state（不是 r15-based）
- 需要 rsi 路径传递
- 需要 cmdline 解析（"yoy0.exe input.ty output.exe" → argv[1], argv[2]）
- 需要 H_50/H_51 调用的 register setup (rsi=path, push r12-r14, set r8=content, rdx=size)
- ~150 行 .ty

### 子项目
- yoy0-js DDC 对齐 (Sub-005)
- yoy0-asm DDC 对齐 (Sub-006)
- M0→M1→M2 真实自举 (Sub-007 T7.4)

## 决策

- v0.4 不锁（用户选 2026-07-15）
- Phase A GetCommandLineA 工作（基线）
- H_50/H_51 路径从 rsi 取（避开 BSS）
