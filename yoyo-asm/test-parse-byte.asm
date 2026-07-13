; Standalone test for parse_byte
; Run with: nasm -f win64 test-parse-byte.asm && gcc test-parse-byte.obj -o test.exe
; Or: nasm -f win64 -o obj && link /SUBSYSTEM:CONSOLE obj kernel32.lib /ENTRY:start

default rel
section .text
global start
extern ExitProcess

start:
    ; Test 1: parse_byte("0E")
    lea rsi, [test1]
    xor ecx, ecx
    mov ecx, 2
    call parse_byte
    mov r12, rax       ; save result

    ; Test 2: parse_byte("73")
    lea rsi, [test2]
    xor ecx, ecx
    mov ecx, 2
    call parse_byte
    mov r13, rax       ; save result

    ; Print results via WriteConsole
    sub rsp, 0x28
    lea rcx, [stdout_handle]
    call [GetStdHandle]

    mov rcx, rax          ; hConsoleOutput
    lea rdx, [result_msg] ; lpBuffer
    mov r8d, 60           ; nNumberOfCharsToWrite
    lea r9, [written]     ; lpNumberOfCharsWritten
    mov qword [rsp+0x20], 0  ; lpReserved
    call [WriteConsoleA]

    add rsp, 0x28

    xor ecx, ecx
    call ExitProcess

; parse_byte(rsi=text, ecx=len) -> eax (byte value or -1)
parse_byte:
    xor eax, eax
    xor ecx, ecx
.l:
    cmp rsi, r10        ; r10 not set, treat as always-available
    jge .d
    movzx edx, byte [rsi]
    cmp dl, '0'
    jb .d
    cmp dl, '9'
    jbe .n
    cmp dl, 'A'
    jb .d
    cmp dl, 'F'
    jbe .h
    cmp dl, 'a'
    jb .d
    cmp dl, 'f'
    ja .d
    sub dl, 'a'-10
    jmp .a
.n:
    sub dl, '0'
    jmp .a
.h:
    sub dl, 'A'-10
.a:
    shl eax, 4
    or eax, edx
    inc ecx
    inc rsi
    cmp ecx, 2
    jb .l
.d:
    test ecx, ecx
    jnz .ok
    mov eax, -1
.ok:
    ret

section .data
test1: db '0', 'E', 0
test2: db '7', '3', 0
result_msg:
    db 'parse_byte("0E") = ', 0
    ; r12 value (parse_byte("0E"))
    ; We'll print as hex digit pairs

; Use Windows API
section .bss
stdout_handle: resq 1
written: resq 1
