# v0.4 FINAL status (2026-07-15)

## ✅ Working

### T2+T5+T6 (verifier 改造)
- GetCommandLineA 调通 (startup 调 kernel32 IAT, rax = PSTR cmdline)
- pe_link 5 bug 修：INT/IAT 8B、build_idata var-length、IAT scan arm、REX.B (mov r15)、RVA 变量名交换
- IatThunk +GetCommandLineA=15
- str_idx → str_slot (u8→u16)：ISA + emit + platform + render 全同步
- Win32 startup 48 字节: GetCommandLineA + 栈存 + rdi=&save_slot 传 H_00
- H_50/H_51 改 rsi-arg: 路径从 RSI 寄存器，状态用 r12/r13/r14，返回 rax=contentBuf/rdx=fileSize
- 测试 .ty 跑 exit = PSTR cmdline 地址

### T7.5 (PE 装载器实验)
- 实验 A: r15 + BSS_RVA (BSS 不可写 AV)
- 实验 B: r15 + INITIALIZED_DATA + FSize=0x1000 + file content (AV)
- 实验 C: SizeOfUninitializedData=0x1000 + DllCharacteristics=0x40 (DYNAMIC_BASE) + Subsystem=6.2 (AV)
- **结论：Win10 minimal PE 不认 BSS**（多个变体都 AV）

## ❌ 未完成

### T7.6 (yoy0.ty v0.4)
MVP 需要：
1. push r12, r13, r14 (H_50 clobbers them)
2. sub rsp, 0x1000 (state buffer in stack)
3. lea r15, [rsp+0x800] (state base in stack)
4. parse cmdline to find argv[1] and argv[2]
5. set rsi=argv[1], call H_50
6. set rsi=argv[2], r8=contentBuf, rdx=fileSize, call H_51
7. add rsp, 0x1000; pop r12, r13, r14; ret

yoy0.ty v0.4 需 ~150 行 .ty 含 raw x86 bytes (00 00 A0 xx for each byte)。

## 已 commit

- `493c4dd` experiments/007 plan
- `48e0e42` T2+T5+T6 (verifier 改造)
- `a558835` H_50/H_51 rsi-arg 改造
- `63b1b75` C-route 实验 (BSS 仍然 AV)

## 决策

- v0.4 不锁 (用户选)
- yoy0.ty v0.4 完整版 deferred 到下次 session (1-2 天)

## 下次继续

1. 写 yoy0.ty v0.4 MVP (50-100 行 .ty，raw bytes 实现)
2. 测试 M1.exe input.ty output.exe 跑通
3. (如果时间) M0→M1→M2 byte-equal 验证
4. yoy0-js DDC 对齐 (Sub-005)
5. yoy0-asm DDC 对齐 (Sub-006)
