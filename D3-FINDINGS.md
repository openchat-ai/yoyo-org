# D3 FINDINGS: yoy0-v0.4-rs.exe exit 1, no output.exe

## 三层拆解

### 第一层：源码级（platform.rs）

**emit_h00_code()** (line 330-412): 主要逻辑：
1. 6 push + sub rsp 0x1000 → 栈帧建立
2. lea r15, [rsp+0x800] → stack-state base
3. mov rsi, [rdi] → 从栈取 cmdline 指针
4. copy loop: cmdline → 栈 buffer
5. scan0: 跳过 argv[0] 找到 argv[1] → r12
6. scan1: 跳过 argv[1] 找到 argv[2] → r13
7. mov rsi, r12 → emit_loadfile 读 input.ky
8. mov rsi, r13 → emit_writefile 写 output.exe
9. epilogue + ret

**emit_loadfile()** (line 221-268): 调用 CreateFileA → GetFileSize → VirtualAlloc → ReadFile → CloseHandle

**emit_writefile()** (line 271-304): 调用 CreateFileA → WriteFile → CloseHandle

**startup_blob()** (line 307-328):
1. mov r15, 0 (placeholder, linker 补丁为 0)
2. call [GetCommandLineA] → rax = cmdline
3. push rax → mov rdi, rsp → rdi = &cmdline ptr
4. call H_00 → 调用 handler
5. pop rcx → ret → exit code = rax

### 第二层：TIR 级（yoy0-v0.4.ty）

yoy0-v0.4.ty 只有 2 行：
```
00 00 40 40  → 24-bit opcode: hi=00 mid=00 low=40 (HANDLER), arg=40 (hh=0x40)
00 00 FF     → 24-bit opcode: hi=00 mid=00 low=FF (RET)
```

TIR lowering:
- HandlerStart {hh: 0x40} → 触发 Rust emit_h00_code() (emit.rs:56 `*hh == 0x40`)
- Ret → 被 skip_body=true 跳过 (emit.rs:70)

### 第三层：机器码级（hex dump 分析）

PE 结构：
- .text: RVA 0x1000, file offset 0x400, size 0x400
- .idata: RVA 0x2000, file offset 0x800, size 0x400
- IMAGE_BASE: 0x140_0000_0000

Startup blob (48 bytes at file offset 0x400):
```
49 BF 00 00 00 00 00 00 00 00  ; mov r15, 0
FF 15 58 10 00 00               ; call [GetCommandLineA] → 0x1010+0x1058=0x2068
50                              ; push rax
48 89 E7                        ; mov rdi, rsp
E8 17 00 00 00                  ; call H_00 → 0x1019+0x17=0x1030
59                              ; pop rcx
C3                              ; ret
```

H_00 code (starts at file offset 0x430):
```
41 54 41 55 41 56 53 41 57 56  ; push r12, r13, r14, rbx, r15, rsi
48 81 EC 08 10 00 00            ; sub rsp, 0x1008
4C 8D BC 24 08 08 00 00         ; lea r15, [rsp+0x808]
48 8B 37                        ; mov rsi, [rdi]
48 8D BC 24 00 01 00 00         ; lea rdi, [rsp+0x100]
8A 06 88 38 84 C0 74 08        ; copy loop: mov al,[rsi]; mov [rdi],al; test al,al; jz
48 FF C6 48 FF C7 EB F0        ; inc rsi, inc rdi, jmp
48 8D B4 24 00 01 00 00        ; lea rsi, [rsp+0x100]
80 3E 20 74 0A                  ; scan0: cmp byte [rsi],0x20; jz
80 3E 00 74 0B                  ; cmp byte [rsi],0; jz
48 FF C6 EB F1                  ; inc rsi, jmp
C6 06 00 48 FF C6               ; null0: mov byte [rsi],0; inc rsi
49 89 F4                        ; argv1_start: mov r12, rsi
80 3E 20 74 0A                  ; scan1: cmp byte [rsi],0x20; jz
80 3E 00 74 0B                  ; cmp byte [rsi],0; jz
48 FF C6 EB F1                  ; inc rsi, jmp
C6 06 00 48 FF C6               ; null1: mov byte [rsi],0; inc rsi
49 89 F5                        ; no_argv2: mov r13, rsi
4C 89 E6                        ; mov rsi, r12
...emit_loadfile...             ; 读 input.ky
4C 89 EE 49 89 D0 48 89 C2     ; mov rsi,r13; mov r8,rdx; mov rdx,rax
...emit_writefile...            ; 写 output.exe
48 81 C4 08 10 00 00            ; add rsp, 0x1008
5E 41 5F 5B 41 5E 41 5D 41 5C  ; pop rsi, r15, rbx, r14, r13, r12
C3                              ; ret
```

## 关键发现

### 1. CloseHandle(INVALID_HANDLE_VALUE) 返回 TRUE (1)

验证：修改 emit_h00_code 只调用 CloseHandle(0xFFFFFFFFFFFFFFFF)，exit code = 1。

**结论：** 本系统上 CloseHandle 对无效句柄返回 TRUE，导致 exit code 始终为 1，**无法用 exit code 判断 API 是否成功**。

### 2. CreateFileA 硬编码路径正常工作

用 jmp-over-filename 技巧嵌入 "C:\SENTINEL.TXT"，调用 CreateFileA + CloseHandle：
- 文件被成功创建（0 字节）
- exit code = 1

**结论：** PE 结构、IAT、API 调用本身没有问题。

### 3. 增加 sentinel 代码后程序 AV 崩溃

在 H_00 起始处插入硬编码 CreateFileA 测试，然后继续原 argv 解析 + loadfile/writefile 流程：
- sentinel 文件被创建（CreateFileA 正常工作）
- 程序在后续流程中 AV 崩溃（exit code 0xC0000005）

这表明 sentinel 代码干扰了后续流程，可能是寄存器污染（RDI 被修改？）。

### 4. 栈对齐

原代码 `sub rsp, 0x1000` 导致栈在 API 调用时未对齐。已修复为 `sub rsp, 0x1008` + `lea r15, [rsp+0x808]`。但修复后行为不变。

### 5. WriteFile 的 lpNumberOfBytesWritten 参数

原代码使用 `lpNumberOfBytesWritten = NULL`。文档说某些 Windows 版本上 NULL 会导致不写入。已改为栈变量，但行为不变。

## 根因推测

exit code 1 的源头是 CloseHandle(INVALID_HANDLE_VALUE) 返回 TRUE。但 CreateFileA 为什么失败？

**最可能的根因：argv 解析器产生的路径有误。** 具体可能是：
1. cmdline 包含引号时，scan0 把引号当成 argv[0] 的一部分，跳过一个空格后 r12 指向正确位置——但如果有双空格，r12 指向空格字符（0x20）
2. 或 GetCommandLineA 返回的 cmdline 格式与预期不符

**但静态分析无法确定确切根因。** 所有指令在 hex dump 中都是正确的，寄存器使用和栈操作都平衡。需要运行时调试（WinDbg）来确认 argv 解析器产生的实际路径。

## 修复建议

1. **修复 argv 解析器**：在 null0/null1 之后添加跳过连续空格的循环
2. **修复 WriteFile 参数**：用栈变量替代 lpNumberOfBytesWritten=NULL
3. **修复栈对齐**：`sub rsp, 0x1000` → `sub rsp, 0x1008` + `lea r15, [rsp+0x808]`
4. **添加 `xor eax, eax`**：在 H_00 返回前清零 rax，确保 exit code 为 0