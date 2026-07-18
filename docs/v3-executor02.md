# v3-executor02: 24-bit TIR Executor (gen2.exe H_00)

## Status

| 阶段 | 计划 | 实际 |
|------|------|------|
| Scanner | scan_token 式 (产 token 边界) | sw+rh 子程序 (单字节级) |
| Hex 表 | 256B, 编译时嵌入 | ✅ hex_table() + xlatb 替换 (2026-07-18: `movzx eax,al; movzx rdx,[rbx+rax]; mov al,dl`) |
| Opcode handler | 14 个 | 3 个 (SET=0x30, HANDLER=0x40, RET=0xFF) |
| 算术 opcode | GET/ADD/SUB/CMP/INC/DEC/ADDV/SUBV | ❌ 未实现 |
| 分支 opcode | CALL/JMP+10 JCC | ❌ 未实现 (rel32 fixup 未集成) |
| Fixup 表 | 两遍+写 rel32 | ❌ 无 |
| PE 输出 | 完整 PE 构建 | ❌ 直接写原始字节 |
| 输入输出 | LoadFile → V3 exec → WriteFile | ✅ pass-through + V3 executor 链路完整 |

## 已实现技术点

### 踩坑记录 (2026-07-18)

| 问题 | 根因 | 修复 |
|------|------|------|
| `xlatb` (0xD7) 指令在 AMD Zen 3+ 被移除 | CPU 不识别 0xD7 → `STATUS_ILLEGAL_INSTRUCTION` | 替换为 `movzx eax,al; movzx rdx,byte[rbx+rax]; mov al,dl` |
| xlatb 替换 `mov al, dil` 写错寄存器 | `mov al, dil` 用 RDI 低8位，RDI已改 (R14+0x800) → AL被清零 | 改为 `mov al, dl` |
| xlatb 替换 ModRM 编码错误 | `48 0F B6 06 03` 解码为 `movzx rax,[rsi]` (rm=110=Rsi)，不是 `[rbx+rax]` | 改为 `48 0F B6 04 03` (rm=100=SIB, index=000=RAX, base=011=RBX) |
| jcc_rel8/jmp_rel8 距离溢出 | 前向跳转 >127B → rel8 溢出成负值，跳回 prologue | 全部改为 rel32 形式 (jcc 6B, jmp 5B) |
| 输出偏移错误 | writefile 从 R14 (output buf base) 写，不是 R14+0x800 | p2_done 改为 `lea rdx, [r14+0x800]` |
| 输出大小多 0x800 | `RDI - R14` 含 prefix 区域 0x800 | p2_done 加 `sub rax, 0x800` |
| VirtualAlloc 返回 NULL | 参数错误 (非直接问题) | 确认 R9=0x40, R8=0x3000 正确 |
| R13 在 prologue 中被破坏 | `add_rr(R13, Rdx)` 后 Rdx 被 `mov_imm64(Rdx, 0x40000)` 覆盖 | `add_rr` 在 `mov_imm64` 之前执行，R13 已保存 |
| argv 扫描 null 检查 | scan 循环只检查 0x20 不检查 0x00 | 加 `test al,al; je` + 硬编码回退路径 |

### 实际实现架构

```
emit_v3_executor():
  1. prologue: push regs, VirtualAlloc → R14, hex_table → RBX
  2. main_start: fill [R14+0..0x400) = -1, pass_flag=0, fixup_count=0
  3. pass1 loop (p1_loop):
     - emit_prefix_read(sw,rh,skip1,p1_done) → AL=opcode
     - dispatch: cmp 0x30/0x40/0xFF → h_set1/h_hand1/h_ret1
  4. pass1→pass2: pass_flag=1, RSI=R12, RDI=R14+0x800
  5. pass2 loop (p2_loop):
     - emit_prefix_read(sw,rh,skip2,p2_done) → AL=opcode
     - dispatch: cmp → h_set2/h_hand2/h_ret2
  6. p2_done: RDX=R14+0x800, RAX=RDI-R14-0x800

寄存器约定:
  R12 = input buffer
  R13 = end of input
  R14 = output buffer (VirtualAlloc, 0x40000)
  RBX = hex table
  RSI = input cursor
  RDI = output cursor (starts at R14+0x800)
  R8  = (pass1) output byte counter
  R9B = (pass2 set) slot
  R8B = (pass2 set) value
```

### 输出缓冲区布局
```
[R14+0x000..0x400) = handler_offsets (256×i32, -1 init)
[R14+0x400]        = pass_flag (u32)
[R14+0x404]        = fixup_count (u32)
[R14+0x408..0x800) = fixups (未用)
[R14+0x800..]      = emitted code (WriteFile 输出从此开始)
```

## 待实现

| 优先级 | 功能 | 工作量 |
|--------|------|--------|
| P0 | arg parse: 从 hex token 读取 slot/value 的 off-by-one 修复 | 小 (~10行) |
| P0 | 加更多 opcode handler (CALL/JMP 优先，需 rel32 fixup) | 大 |
| P1 | handler_offsets 表 + handler dispatch | 中 |
| P1 | Custom PE 输出 (startup_blob + IAT) | 中 |
| P2 | 完整 14 opcode + 算术指令 | 大 |

## Input Format

```
00 00 30 0e 00         # SET slot=0x0e imm=0x00
00 00 41 01            # CALL hh=0x01
00 00 ff               # RET
00 00 12 s6572726f7200 # STRING_DEF data bytes
```

- 24-bit opcode = `00 00 xx` (低字节是实际 opcode)
- Token 用 0x20 分隔, 行尾 0x0A
- 注释 `;` 或 `#` 到行尾
- `s<hex>` = data token (STRING_DEF, RAW_DEF)
- 参数: 2-16 hex digits, 按 big-endian 解析为 u64

## 14 Opcodes (设计参考, 未实现)

| Op | Name | Args | x64 emit |
|----|------|------|----------|
| 0x40 | HANDLER hh | 1 | 无 emit，记录 handler_offsets[hh] |
| 0x41 | CALL hh | 1 | `E8 00 00 00 00` (5B) 第二遍fixup |
| 0x70 | JMP hh | 1 | `E9 00 00 00 00` (5B) fixup |
| 0x71-0x7A | JCC hh | 1 | `0F 8x 00 00 00 00` (6B) fixup |
| 0xFF | RET | 0 | `C3` (1B) |
| 0x30 | SET slot imm | 2 | `48 B8 <imm64> ; 49 89 47 <slot*8>` |
| 0x60 | GET dst src | 2 | 算术类 (未实现) |
| 0x80 | LDB dd ss oo | 3 | 内存类 (未实现) |
| 0x12/0x13 | STRING/RAW_DEF | data | 跳过 |

### x64 JCC Map (yoyo opcode → x64 0F opcode)

```
0x71→0x84  0x72→0x85  0x73→0x8C  0x74→0x8D
0x75→0x8E  0x76→0x8F  0x77→0x82  0x78→0x83
0x79→0x86  0x7A→0x87
```

## 固定长度规则 (设计参考)

| Opcode | 固定长度 | 备注 |
|--------|----------|------|
| CALL/JMP | 5B | `E8/E9 00 00 00 00` |
| JCC | 6B | `0F 8? 00 00 00 00` |
| RET | 1B | `C3` |
| SET | 14+4 或 14+7 | imm 统一用 10B imm64 |
| 算术类 | 11-24B | 取决于 slot disp8/disp32 |

**slot < 16 → disp8, slot ≥ 16 → disp32**。

## 实现顺序 (设计参考)

### Phase 1: Scanner + 最小发射 (6 ops) ← 当前进度约 20%
实现: scan_token, hex_value_table, args_table, main_scanner loop
实现: RET(C3), SET(mov imm64 + store), INC/DEC, CMP
实现: JMP/JE placeholder (E9/E8, 第二遍 fixup 跳过)
实现: H_00 pipeline (LoadFile → scan+emit → WriteFile)

### Phase 2: 全部算术 + 分支
添加: GET, ADD, SUB, ADDV, SUBV, LDB
添加: 全部 10 个 JCC + fixup

### Phase 3: PE 输出
添加: startup_blob + PE header template + IAT