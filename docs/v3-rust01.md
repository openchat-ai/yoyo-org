# v3-rust01: platform.rs + emit.rs 裸字节 → X64Assembler

## 状态：✅ 完成（2026-07-16）

D3 写回至 yoy0 v0.4 独立项目（`yoy0/projects/yoy0-v0.4.ty`）继续追踪。

## 前置：补齐 X64Assembler 缺少的方法

| # | 方法 | 用途 | 已完 |
|---|------|------|------|
| 0.1 | `mov_qword_rsp_disp(disp: u8, imm: i32)` | CreateFileA 5-7号堆栈参数 | ✅ |
| 0.2 | `mov_rsi_rdi_ptr()` | `mov rsi, [rdi]` | ✅ 已有 |
| 0.3 | `movzx_eax_byte_mem(base: Reg, disp: i32)` | LDB 指令 | ✅ |
| — | `load_mem(reg, base, disp)` | 通用内存→寄存器加载 | ✅ |

## Phase A: platform.rs 辅助函数 → X64Assembler（纯机械替换）

每个步骤：删掉原函数，直接调用 X64Assembler 同名方法。改完 `cargo test -p verifier`。

| # | 原函数 | 替换为 | 文件:行 |
|---|--------|--------|---------|
| A1 | `load_state_addr_rdi(buf, slot)` | `asm.lea_state(rdi, slot)` | platform.rs:196 |
| A2 | `movabs_rdi_imm(buf, imm)` | `asm.mov_imm64(rdi, imm)` | platform.rs:206 |
| A3 | `movabs_rsi_imm(buf, imm)` | `asm.mov_imm64(rsi, imm)` | platform.rs:214 |
| A4 | `movabs_rdx_imm(buf, imm)` | `asm.mov_imm64(rdx, imm)` | platform.rs:222 |
| A5 | `call_rel32_placeholder(buf)` | `asm.call_rel32_placeholder()` | platform.rs:230 |
| A6 | `call_indirect_rip_placeholder(buf)` | `asm.call_rip_placeholder()` | platform.rs:240 |
| A7 | `call_iat_thunk(buf, api)` | `asm.call_iat_thunk(api)` | platform.rs:262 |
| A8 | `emit_str_idx_addr(buf, _)` | `asm.lea_rdi_rip_placeholder()` | platform.rs:282 |
| A9 | `lea_rcx_rip_placeholder(buf)` | `asm.lea_rcx_rip_placeholder()` | platform.rs:297 |
| A10 | `lea_rdi_rip_placeholder(buf)` | `asm.lea_rdi_rip_placeholder()` | platform.rs:305 |
| A11 | `store_r15(buf, slot)` | `asm.store_state(slot, rax)` | platform.rs:180 |
| A12 | `shadow_frame(buf)` + `shadow_ret(buf)` | `asm.shadow_frame()` / `asm.shadow_ret()` | platform.rs:314 |

## Phase B: platform.rs H_00/H_50/H_51 内联裸字节 → X64Assembler

B1-B6: emit_loadfile / emit_writefile 的 push/mov_r_r/pop 替换为 asm.push() / asm.mov_rr() / asm.pop()  ✅
B7-B13: emit_h00_code 全部内联字节 → X64Assembler（含 label/fixup 系统）                  ✅
B14: startup_blob 48字节数组 → X64Assembler 生成（Win32 + Linux）                         ✅

## Phase C: emit.rs 裸字节 → X64Assembler

C1: Ldb 的 movzx 手动编码 → `asm.movzx_eax_byte_mem(rdx, oo)`                         ✅
C2-C3: emit_inner 签名改为用 X64Assembler + Platform trait 全部去 `<const N>`/FixedBuf    ✅

## Phase D: 集成测试

D1: cargo test -p verifier 全过                                                          ✅ 138 passed
D2: yoyo-rust link 产出 valid PE                                                          ✅
D3: yoy0-v0.4-rs.exe input.ky output.exe 文件拷贝正确                                    ⏳ **写回 yoy0 v0.4 项目追踪**
D4: 多轮自举哈希比对                                                                      ⏳ 依赖 yoyo.ty 修 v3 数据 bug（line 121 LIBYOYO_READ 等）

## Phase E: yoyo.ty 高层 opcode 化（独立任务）

E1: 扫描 yoyo.ty 里所有 A0/A1 块
E2: 逐个替换成 30 SET / 60 GET / 65 CMP 等
E3: 验证编译输出一致

## v3-rust01 重构最终状态（独立于 D3/E）

- `emit.rs` / `platform.rs` 零 `buf.push(0x??)` 原始字节
- `primitives.rs` 模块已删除
- Platform trait 全部用 `&mut X64Assembler`（无 FixedBuf 依赖）
- Win32 startup blob byte-identical to 旧版（pe_link patch 字段除外）
- 81 assembler tests + 138 总 tests pass
- 集成 pipeline (.ty → TIR → x64 → PE) 端到端工作
- yoy0-v0.4-rs.exe (6KB, argv-aware) 与 JS yoy0-v0.4-js.exe (100KB, libyoyo) 都因 yoy0 v0.4 自身 bug 跑不通 — **pre-existing，与本次重构无关**
