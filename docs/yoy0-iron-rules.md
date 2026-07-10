# YOY0 编译器铁律 (Iron Rules)

> yoy0.ty 必须遵守的 12 条铁律。每条可由实验或形式化方法证明。

## 范畴与禁止

1. **零引用 input.ky 既有内容** — yoy0.ty 的所有逻辑都从设计原理出发。input.ky 不可作为参考实现来源。
2. **零自动重写** — 不存在 yoy0.ty 的 generator 工具。yoy0.ty 一旦锁定，唯一修改路径是人工 git commit。

## DDD (Domain-Driven Design) 范畴

3. **4 个 bounded context** — yoy0.ty 严格分为 4 个 context：Loader (L)、Scanner (S)、Emitter (E)、Output (O)。每个 context 通过明确的 state 字段交互。
4. **聚合根 = CompilerState** — 整个 256-slot 内存是聚合根，状态变化只通过显式 update 函数。
5. **统一语言** — yoy0.ty 的所有变量名、操作名、handler 名遵循统一词汇表（compile/emit/scan/load/handler/ret/state 等）。

## 24 位指令格式

6. **每条指令 = 3 字节 opcode** — 第 1 字节 = OPCODE[23:16]，第 2 字节 = OPCODE[15:8]，第 3 字节 = OPCODE[7:0]。38 个有效 opcode 全部在低字节，hi=mid=0。
7. **1-arg 变长** — args 跟在 3 字节 opcode 后面，长度由 opcode 类型决定。字符串前加 `s` 前缀。

## 内存指针 (Memory Pointers)

8. **slot index = pointer** — yoy0 的所有内存访问通过 slot 索引（0-255）。slot 0x0E * 8 = byte 0x70 是 yoy0 的指针运算。
9. **R15 = 状态基址** — 启动代码将 R15 设为 state 区域基址。所有 load/store 经由 R15+offset。

## 零内存泄漏 (0 Memory Leaks)

10. **静态分配 only** — yoy0.ty 不调用 malloc/free。所有 buffer 在编译期固定大小（1MB code, 64KB data, 4KB heap）。state[256] 是编译期固定。
11. **关闭 = 释放** — yoy0 是单进程 OS 工具。进程退出 = 全部状态释放。物理上不可能 leak。

## 永不崩溃 (Never Crashes)

12. **Result 链** — 每个 emit/scan/load 操作返回 Result。错误传递用 state_17（Trit sentinel，0/1/2 表示错误码）。无 panic，无 exception。

## 抗压 / 耐操

13. **缓冲区边界检查** — 每个 emit 前检查 budget（state_18），归零即停。固定大小 buffer 写满即停。
14. **Self-test on startup** — yoy0.ty 启动时验证：slot 范围、handler ID 唯一、data pointer 对齐。失败即返回错误。

## 三进制 (Ternary)

15. **3-态编码** — 错误码用三进制 trit (0/1/2)，不是 boolean。Scanner 状态用 trit (READY/IN_NUMBER/IN_IDENT)。允许前向/同/后向三态逻辑。
16. **Trit-aware 算术** — 涉及 trit 的运算（CMP/JE 等）天然支持 3 态，不需要先转换。

## 验证 (Verification)

17. **3-chain DDC** — yoy0.ty 编译后，yoy0.exe 输出必须与 yoy0 (Rust) 和 yoy0 (asm) 的输出 byte-equal。
18. **可审计** — yoy0.ty 目标 < 1500 行 (v3 spec)。每周都能读完全部代码。

## 24 位 + 三进制 协同

19. **Trit 在 24 位指令内编码** — 当 24 位 opcode 用于 trit 操作时，结果天然是 3 态，不需要额外位。

---

## 违反的检测方法

| 铁律 | 违反检测 |
|------|---------|
| 1, 2 | git 历史 + grep "yoy0-gen\|regenerate" |
| 3, 4, 5 | 代码审查 + context boundary check |
| 6, 7 | 字节解析器：每个 opcode 行 3 字节 |
| 8, 9 | emit 代码：仅 R15+offset 寻址 |
| 10, 11 | grep "malloc\|free\|new " — 应 0 命中 |
| 12 | grep "throw\|panic\|.unwrap()" — 应 0 命中 |
| 13, 14 | grep "budget\|bounds" — 每次 emit 前存在 |
| 15, 16 | 状态机检查：3 态而非 2 态 |
| 17, 18 | 3-chain DDC + 行数 < 1500 |
| 19 | trit 操作指令集中 |

---

## v0.1 范围 (符合所有铁律)

### 4 个 bounded context 骨架

```
1. Loader  (L)  : H_50 load input.ky
2. Scanner (S)  : H_01 scan bytes, classify, dispatch
3. Emitter (E)  : H_30 dispatch by opcode, then H_3x emit
4. Output   (O)  : H_51 write output.exe
```

### 内存模型

- 256 slot × 8 byte = 2048 bytes
- R15 = state base
- slot 0x0E * 8 = byte 0x70 (pointer example)

### v0.1 必有的不变量

- ✅ 24 位格式 (3 字节 opcode)
- ✅ R15+slot 寻址 (无其他 base reg)
- ✅ 静态分配 (无 malloc)
- ✅ Result 链 (无 panic)
- ✅ Self-test on startup
- ✅ 三进制状态机 (scanner 3 态)
- ✅ 0 内存泄漏（物理上不可能）
- ✅ 永不崩溃 (所有错误传递)

### v0.1 暂不实现的

- 完整 38 opcode emit 逻辑 (v0.1 只 emit 1 个: SET)
- 完整 file I/O (v0.1 用 hardcoded 4-byte input)
- 完整 output 写入 (v0.1 stub write)
- 启动代码 (v0.1 hardcoded 4 byte header)

### v0.1 必须 compile 通过

yoy0.js 编译 yoy0.ty v0.1 → yoy0.exe
yoy0.exe 包含 SET (0x30) 和 RET (0xFF) 的 emit 字节

### 实验步骤

1. 写铁律本文档 ✓ (此文件)
2. 写 yoy0.ty v0.1 (短小, 24 位, 4 context shells)
3. 验证 yoy0.js 24 位 parser 已支持 (v3 Part 4.1)
4. 编译 v0.1 → 输出 yoy0.exe
5. 字节验证 (检查 SET/RET 字节模式)
6. 通过 → v0.1 锁定为基线

---

*此文档是 yoy0.ty v0.1 的宪法。所有后续 v0.X 必须遵守。*
