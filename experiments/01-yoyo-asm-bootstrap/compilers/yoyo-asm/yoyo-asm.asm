default rel

section .text
global start
extern CreateFileA, ReadFile, WriteFile, CloseHandle, ExitProcess

; ── ENTRY ──────────────────────────────────────────────────────────
start:
    sub rsp, 0x28

    lea r15, [rel state_buf]
    xor eax, eax
    mov [r15+0x0E*8], rax    ; code_offset = 0
    mov [r15+0x10*8], rax    ; scanner_state = 0
    mov [r15+0x11*8], rax    ; acc = 0
    mov [r15+0x12*8], rax    ; digit_count = 0
    mov [r15+0x13*8], rax    ; current_opcode = 0
    mov [r15+0x14*8], rax    ; arg_index = 0
    mov [r15+0x15*8], rax    ; emit_state = 0
    mov [r15+0x16*8], rax    ; arg_count = 0
    mov [r15+0x17*8], rax    ; error_code = 0
    mov qword [r15+0x18*8], 1000

    call open_read
    cmp rax, -1
    je exit_fail

    lea rsi, [rel input_buf]
    mov ecx, [rel bytes_read]
    call parse

    call pass1
    call pass2
    call fixup

    call write_output

    xor ecx, ecx
    call ExitProcess

exit_fail:
    mov ecx, 1
    call ExitProcess

; ── FILE I/O ───────────────────────────────────────────────────────
open_read:
    sub rsp, 0x38
    lea rcx, [rel input_fn]
    mov edx, 0x80000000       ; GENERIC_READ
    mov r8d, 1                ; FILE_SHARE_READ
    xor r9d, r9d              ; lpSecurityAttributes = NULL
    mov dword [rsp+0x20], 3   ; OPEN_EXISTING
    mov qword [rsp+0x28], 0   ; dwFlagsAndAttributes
    mov qword [rsp+0x30], 0   ; hTemplateFile
    call CreateFileA
    cmp rax, -1
    je .fail
    mov r12, rax              ; save handle

    mov rcx, r12
    lea rdx, [rel input_buf]
    mov r8d, 16384
    lea r9, [rel bytes_read]
    mov qword [rsp+0x20], 0   ; lpOverlapped = NULL
    call ReadFile
    test eax, eax
    jz .fail

    mov rcx, r12
    call CloseHandle
    xor eax, eax
    add rsp, 0x38
    ret
.fail:
    mov rax, -1
    add rsp, 0x38
    ret

open_write:
    sub rsp, 0x38
    lea rcx, [rel output_fn]
    mov edx, 0x40000000       ; GENERIC_WRITE
    xor r8d, r8d              ; no share
    xor r9d, r9d              ; NULL
    mov dword [rsp+0x20], 2   ; CREATE_ALWAYS
    mov qword [rsp+0x28], 0   ; dwFlagsAndAttributes
    mov qword [rsp+0x30], 0   ; hTemplateFile
    call CreateFileA
    add rsp, 0x38
    ret



; ── PARSER ─────────────────────────────────────────────────────────
; Parse: each non-comment, non-empty line has "XX YY [ZZ ...args]"
; Comments start with ';' or '#'. Lines separated by \n.
; Stores into inst_buf at [count*26] = first 3 bytes (XX, YY, ZZ), rest 0.

parse:
    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rbx, [rel inst_buf]
    xor r14d, r14d

    ; rsi = start of input, ecx = bytes_read (set by caller)
    lea r10, [rsi+rcx]

.next_line:
    cmp rsi, r10
    jae .done

    ; Skip whitespace
.skip_ws:
    cmp rsi, r10
    jae .done
    movzx eax, byte [rsi]
    cmp al, ' '
    je .skip1
    cmp al, 9
    je .skip1
    cmp al, 10
    je .skip1
    cmp al, 13
    je .skip1
    jmp .not_ws
.skip1:
    inc rsi
    jmp .skip_ws
.not_ws:

    cmp rsi, r10
    jae .done

    ; Comment check
    movzx eax, byte [rsi]
    cmp al, ';'
    je .skip_line
    cmp al, '#'
    je .skip_line

    ; Read 3 hex bytes inline (handles 0-9, a-f, A-F)
; Use R12B for accumulating first nibble, R13B for combined value
    xor r12d, r12d
    movzx eax, byte [rsi]
    call .hex_to_nibble
    mov r12b, al
    shl r12b, 4
    inc rsi
    movzx eax, byte [rsi]
    call .hex_to_nibble
    or r12b, al
    inc rsi
    cmp byte [rsi], ' '
    jne .skip_line
    inc rsi

    xor r13d, r13d
    movzx eax, byte [rsi]
    call .hex_to_nibble
    mov r13b, al
    shl r13b, 4
    inc rsi
    movzx eax, byte [rsi]
    call .hex_to_nibble
    or r13b, al
    inc rsi
    cmp byte [rsi], ' '
    jne .skip_line
    inc rsi

    xor r12d, r12d
    movzx eax, byte [rsi]
    call .hex_to_nibble
    mov r12b, al
    shl r12b, 4
    inc rsi
    movzx eax, byte [rsi]
    call .hex_to_nibble
    or r12b, al
    inc rsi
    ; R12B = opcode

    ; Store (only opcode at [0])
    push rcx
    imul ecx, r14d, 26
    mov byte [rbx+rcx], r12b
    mov qword [rbx+rcx+1], 0
    mov qword [rbx+rcx+9], 0
    mov qword [rbx+rcx+17], 0
    pop rcx
    inc r14d

    cmp r14d, 255
    jae .done

.skip_line:
    cmp rsi, r10
    jae .done
    movzx eax, byte [rsi]
    cmp al, 10
    je .nl
    inc rsi
    jmp .skip_line
.nl:
    inc rsi
    jmp .next_line

.done:
    mov [rel inst_count], r14d
    mov [rel parse_debug], r14
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.hex_to_nibble:
    ; AL = ASCII char. Returns value 0-15 in AL.
    cmp al, '9'
    jbe .digit
    cmp al, 'A'
    jb .bad_hex
    cmp al, 'F'
    jbe .uc
    cmp al, 'a'
    jb .bad_hex
    cmp al, 'f'
    ja .bad_hex
    sub al, 'a'-10
    ret
.digit:
    sub al, '0'
    ret
.uc:
    sub al, 'A'-10
    ret
.bad_hex:
    mov al, 0
    ret

skip_to_content:
    cmp rsi, r10
    jge .ret
.l:
    movzx eax, byte [rsi]
    cmp al, ' '
    je .n
    cmp al, 9
    je .n
    cmp al, 10
    je .n
    cmp al, 13
    je .n
    ret
.n:
    inc rsi
    cmp rsi, r10
    jl .l
.ret:
    ret

skip_spc:
    cmp rsi, r10
    jge .ret
.l:
    movzx eax, byte [rsi]
    cmp al, ' '
    jne .ret
    inc rsi
    cmp rsi, r10
    jl .l
.ret:
    ret

skip_to_eol:
    cmp rsi, r10
    jge .ret
.l:
    movzx eax, byte [rsi]
    cmp al, 10
    je .ret
    inc rsi
    cmp rsi, r10
    jl .l
.ret:
    ret

parse_byte:
    xor eax, eax
    xor ecx, ecx
.l:
    cmp rsi, r10
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

parse_u64:
    xor rdx, rdx
    xor ecx, ecx
.l:
    cmp rsi, r10
    jge .d
    movzx r11d, byte [rsi]
    cmp r11b, '0'
    jb .d
    cmp r11b, '9'
    jbe .n
    cmp r11b, 'A'
    jb .d
    cmp r11b, 'F'
    jbe .h
    cmp r11b, 'a'
    jb .d
    cmp r11b, 'f'
    ja .d
    sub r11b, 'a'-10
    jmp .a
.n:
    sub r11b, '0'
    jmp .a
.h:
    sub r11b, 'A'-10
.a:
    shl rdx, 4
    or rdx, r11
    inc ecx
    inc rsi
    cmp ecx, 16
    jb .l
.d:
    test ecx, ecx
    setnz al
    ret

; ── PASS 1 ─────────────────────────────────────────────────────────
pass1:
    push r12
    push r13
    push r14
    xor r12d, r12d
    xor r13d, r13d
    mov r14d, [rel inst_count]
    lea rdi, [rel handler_off]
    xor eax, eax
    mov ecx, 256
    rep stosd
    mov dword [rel fixup_cnt], 0

.loop:
    cmp r13d, r14d
    jge .done
    lea rbx, [rel inst_buf]
    imul eax, r13d, 26
    add rbx, rax
    movzx ecx, byte [rbx]
    mov r8, [rbx+1]
    mov r9, [rbx+9]
    mov r11, [rbx+17]
    cmp cl, 0x40
    je .hdlr
    call calc_size
    mov byte [rbx+25], al
    add r12d, eax
    cmp cl, 0x41
    je .fix5
    cmp cl, 0x70
    je .fix5
    cmp cl, 0x71
    je .fix6
    cmp cl, 0x72
    je .fix6
    cmp cl, 0x73
    je .fix6
    cmp cl, 0x74
    je .fix6
    cmp cl, 0x75
    je .fix6
    cmp cl, 0x76
    je .fix6
    cmp cl, 0x77
    je .fix6
    cmp cl, 0x78
    je .fix6
    cmp cl, 0x79
    je .fix6
    cmp cl, 0x7A
    je .fix6
    jmp .next

.hdlr:
    lea rdi, [rel handler_off]
    mov [rdi+r8*4], r12d
    jmp .next

.fix5:
    mov edi, [rel fixup_cnt]
    cmp edi, 63
    jg .next
    lea r10, [rel fixup_buf]
    imul edi, 3
    mov [r10+rdi], r13b
    mov [r10+rdi+1], r8b
    mov byte [r10+rdi+2], 0
    inc dword [rel fixup_cnt]
    jmp .next

.fix6:
    mov edi, [rel fixup_cnt]
    cmp edi, 63
    jg .next
    lea r10, [rel fixup_buf]
    imul edi, 3
    mov [r10+rdi], r13b
    mov [r10+rdi+1], r8b
    mov byte [r10+rdi+2], 1
    inc dword [rel fixup_cnt]

.next:
    inc r13d
    jmp .loop

.done:
    mov [rel emitted_size], r12d
    pop r14
    pop r13
    pop r12
    ret

calc_size:
    cmp cl, 0x30
    je .s_set
    cmp cl, 0x60
    je .s_get
    cmp cl, 0x61
    je .s_addsub
    cmp cl, 0x62
    je .s_addsub
    cmp cl, 0x65
    je .s_cmp
    cmp cl, 0x66
    je .s_incdec
    cmp cl, 0x67
    je .s_incdec
    cmp cl, 0x68
    je .s_arith3
    cmp cl, 0x69
    je .s_arith3
    cmp cl, 0x63
    je .s_arith3
    cmp cl, 0x80
    je .s_ldb
    cmp cl, 0xA0
    je .s_1
    cmp cl, 0xFF
    je .s_1
    cmp cl, 0x41
    je .s_5
    cmp cl, 0x70
    je .s_5
    cmp cl, 0x71
    je .s_6
    cmp cl, 0x72
    je .s_6
    cmp cl, 0x73
    je .s_6
    cmp cl, 0x74
    je .s_6
    cmp cl, 0x75
    je .s_6
    cmp cl, 0x76
    je .s_6
    cmp cl, 0x77
    je .s_6
    cmp cl, 0x78
    je .s_6
    cmp cl, 0x79
    je .s_6
    cmp cl, 0x7A
    je .s_6
    xor eax, eax
    ret

.s_set:
    mov eax, r8d
    shl eax, 3
    cmp eax, 127
    ja .ss32
    mov eax, 14
    ret
.ss32:
    mov eax, 17
    ret

.s_get:
    mov eax, r8d
    shl eax, 3
    mov ecx, r9d
    shl ecx, 3
    xor edx, edx
    cmp eax, 127
    ja .g1b
    add edx, 4
    jmp .g2
.g1b:
    add edx, 7
.g2:
    cmp ecx, 127
    ja .g2b
    add edx, 4
    jmp .g_ret
.g2b:
    add edx, 7
.g_ret:
    mov eax, edx
    ret

.s_cmp:
    mov eax, r8d
    shl eax, 3
    mov ecx, r9d
    shl ecx, 3
    xor edx, edx
    cmp eax, 127
    ja .c1b
    add edx, 4
    jmp .c2
.c1b:
    add edx, 7
.c2:
    cmp ecx, 127
    ja .c2b
    add edx, 4
    jmp .c3
.c2b:
    add edx, 7
.c3:
    add edx, 3
    mov eax, edx
    ret

.s_incdec:
    mov eax, r8d
    shl eax, 3
    cmp eax, 127
    ja .idb
    mov eax, 12
    ret
.idb:
    mov eax, 18
    ret

.s_addsub:
    mov eax, r8d
    shl eax, 3
    xor edx, edx
    cmp eax, 127
    ja .asl
    add edx, 4
    jmp .asm
.asl:
    add edx, 7
.asm:
    mov eax, r9d
    cmp eax, -128
    jl .as32
    cmp eax, 127
    jg .as32
    add edx, 4
    jmp .asst
.as32:
    add edx, 7
.asst:
    mov eax, r8d
    shl eax, 3
    cmp eax, 127
    ja .astb
    add edx, 4
    jmp .as_ret
.astb:
    add edx, 7
.as_ret:
    mov eax, edx
    ret

.s_arith3:
    mov eax, r8d
    shl eax, 3
    mov ecx, r9d
    shl ecx, 3
    xor edx, edx
    cmp eax, 127
    ja .a1b
    add edx, 4
    jmp .a2
.a1b:
    add edx, 7
.a2:
    cmp ecx, 127
    ja .a2b
    add edx, 4
    jmp .a3
.a2b:
    add edx, 7
.a3:
    add edx, 3
    mov eax, r8d
    shl eax, 3
    cmp eax, 127
    ja .a3b
    add edx, 4
    jmp .a_ret
.a3b:
    add edx, 7
.a_ret:
    mov eax, edx
    ret

.s_ldb:
    mov eax, r9d
    shl eax, 3
    xor edx, edx
    cmp eax, 127
    ja .lb1
    add edx, 4
    jmp .lb2
.lb1:
    add edx, 7
.lb2:
    add edx, 4
    mov eax, r8d
    shl eax, 3
    cmp eax, 127
    ja .lb2b
    add edx, 4
    jmp .lb_ret
.lb2b:
    add edx, 7
.lb_ret:
    mov eax, edx
    ret

.s_1:
    mov eax, 1
    ret
.s_5:
    mov eax, 5
    ret
.s_6:
    mov eax, 6
    ret

; ── X64 EMITTERS ───────────────────────────────────────────────────
emit_movabs_rax:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0xB8
    mov [rdi+2], rdx
    add rdi, 10
    ret

emit_store_state:
    shl eax, 3
    mov byte [rdi], 0x49
    mov byte [rdi+1], 0x89
    cmp eax, 127
    ja .es32
    mov byte [rdi+2], 0x47
    mov byte [rdi+3], al
    add rdi, 4
    ret
.es32:
    mov byte [rdi+2], 0x87
    mov [rdi+3], eax
    add rdi, 7
    ret

emit_load_rax:
    shl eax, 3
    mov byte [rdi], 0x49
    mov byte [rdi+1], 0x8B
    cmp eax, 127
    ja .el32
    mov byte [rdi+2], 0x47
    mov byte [rdi+3], al
    add rdi, 4
    ret
.el32:
    mov byte [rdi+2], 0x87
    mov [rdi+3], eax
    add rdi, 7
    ret

emit_load_rdx:
    shl eax, 3
    mov byte [rdi], 0x49
    mov byte [rdi+1], 0x8B
    cmp eax, 127
    ja .elr32
    mov byte [rdi+2], 0x57
    mov byte [rdi+3], al
    add rdi, 4
    ret
.elr32:
    mov byte [rdi+2], 0x97
    mov [rdi+3], eax
    add rdi, 7
    ret

emit_add_imm:
    cmp edx, -128
    jl .eai32
    cmp edx, 127
    jg .eai32
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x83
    mov byte [rdi+2], 0xC0
    mov byte [rdi+3], dl
    add rdi, 4
    ret
.eai32:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x81
    mov byte [rdi+2], 0xC0
    mov [rdi+3], edx
    add rdi, 7
    ret

emit_sub_imm:
    cmp edx, -128
    jl .esi32
    cmp edx, 127
    jg .esi32
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x83
    mov byte [rdi+2], 0xE8
    mov byte [rdi+3], dl
    add rdi, 4
    ret
.esi32:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x81
    mov byte [rdi+2], 0xE8
    mov [rdi+3], edx
    add rdi, 7
    ret

emit_cmp_reg:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x39
    mov byte [rdi+2], 0xD0
    add rdi, 3
    ret

emit_add_reg:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x01
    mov byte [rdi+2], 0xD0
    add rdi, 3
    ret

emit_sub_reg:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x29
    mov byte [rdi+2], 0xD0
    add rdi, 3
    ret

emit_mul_reg:
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x0F
    mov byte [rdi+2], 0xAF
    mov byte [rdi+3], 0xC2
    add rdi, 4
    ret

emit_call_placeholder:
    mov byte [rdi], 0xE8
    mov dword [rdi+1], 0
    add rdi, 5
    ret

emit_jmp_placeholder:
    mov byte [rdi], 0xE9
    mov dword [rdi+1], 0
    add rdi, 5
    ret

emit_jcc_placeholder:
    mov byte [rdi], 0x0F
    mov byte [rdi+1], al
    mov dword [rdi+2], 0
    add rdi, 6
    ret

emit_movzx_byte:
    mov byte [rdi], 0x0F
    mov byte [rdi+1], 0xB6
    mov byte [rdi+2], 0x42
    mov [rdi+3], r10b
    add rdi, 4
    ret

emit_ret_instr:
    mov byte [rdi], 0xC3
    add rdi, 1
    ret

; ── PASS 2 ─────────────────────────────────────────────────────────
pass2:
    push r12
    push r13
    push r14

    lea rdi, [rel output_buf]
    ; sub rsp, 0x200 (allocate 512B stack state buffer)
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x81
    mov byte [rdi+2], 0xEC
    mov dword [rdi+3], 0x00000200
    add rdi, 7
    ; mov r15, rsp (r15 = state buffer base)
    mov byte [rdi], 0x4C
    mov byte [rdi+1], 0x8B
    mov byte [rdi+2], 0xFC
    add rdi, 3
    ; call H_00 (displacement fixup patched later)
    mov byte [rdi], 0xE8
    mov dword [rdi+1], 0
    add rdi, 5
    ; add rsp, 0x200 (restore stack)
    mov byte [rdi], 0x48
    mov byte [rdi+1], 0x81
    mov byte [rdi+2], 0xC4
    mov dword [rdi+3], 0x00000200
    add rdi, 7
    ; ret
    mov byte [rdi], 0xC3
    add rdi, 1

    lea r10, [rel output_buf]
    sub rdi, r10
    mov [rel startup_end], edi
    add rdi, r10

    xor r13d, r13d
    mov r14d, [rel inst_count]

.loop:
    cmp r13d, r14d
    jge .end

    lea rbx, [rel inst_buf]
    imul eax, r13d, 26
    add rbx, rax
    movzx ecx, byte [rbx]
    mov r8, [rbx+1]
    mov r9, [rbx+9]
    mov r11, [rbx+17]

    cmp cl, 0x40
    je .next

    cmp cl, 0x30
    je .set
    cmp cl, 0x60
    je .get
    cmp cl, 0x61
    je .add
    cmp cl, 0x62
    je .sub
    cmp cl, 0x65
    je .cmp
    cmp cl, 0x66
    je .inc
    cmp cl, 0x67
    je .dec
    cmp cl, 0x68
    je .addv
    cmp cl, 0x69
    je .subv
    cmp cl, 0x63
    je .mul
    cmp cl, 0x41
    je .call
    cmp cl, 0x70
    je .jmp
    cmp cl, 0x71
    je .je
    cmp cl, 0x72
    je .jne
    cmp cl, 0x73
    je .jl
    cmp cl, 0x74
    je .jge
    cmp cl, 0x75
    je .jle
    cmp cl, 0x76
    je .jg
    cmp cl, 0x77
    je .jb
    cmp cl, 0x78
    je .jae
    cmp cl, 0x79
    je .jbe
    cmp cl, 0x7A
    je .ja
    cmp cl, 0x80
    je .ldb
    cmp cl, 0xA0
    je .raw
    cmp cl, 0xFF
    je .ret
    jmp .next

.set:
    mov rdx, r9
    call emit_movabs_rax
    mov eax, r8d
    call emit_store_state
    jmp .next
.get:
    mov eax, r9d
    call emit_load_rax
    mov eax, r8d
    call emit_store_state
    jmp .next
.add:
    mov eax, r8d
    call emit_load_rax
    mov edx, r9d
    call emit_add_imm
    mov eax, r8d
    call emit_store_state
    jmp .next
.sub:
    mov eax, r8d
    call emit_load_rax
    mov edx, r9d
    call emit_sub_imm
    mov eax, r8d
    call emit_store_state
    jmp .next
.cmp:
    mov eax, r8d
    call emit_load_rax
    mov eax, r9d
    call emit_load_rdx
    call emit_cmp_reg
    jmp .next
.inc:
    mov eax, r8d
    call emit_load_rax
    mov edx, 1
    call emit_add_imm
    mov eax, r8d
    call emit_store_state
    jmp .next
.dec:
    mov eax, r8d
    call emit_load_rax
    mov edx, 1
    call emit_sub_imm
    mov eax, r8d
    call emit_store_state
    jmp .next
.addv:
    mov eax, r8d
    call emit_load_rax
    mov eax, r9d
    call emit_load_rdx
    call emit_add_reg
    mov eax, r8d
    call emit_store_state
    jmp .next
.subv:
    mov eax, r8d
    call emit_load_rax
    mov eax, r9d
    call emit_load_rdx
    call emit_sub_reg
    mov eax, r8d
    call emit_store_state
    jmp .next
.mul:
    mov eax, r8d
    call emit_load_rax
    mov eax, r9d
    call emit_load_rdx
    call emit_mul_reg
    mov eax, r8d
    call emit_store_state
    jmp .next
.call:
    call emit_call_placeholder
    jmp .next
.jmp:
    call emit_jmp_placeholder
    jmp .next
.je:
    mov al, 0x84
    jmp .jcc
.jne:
    mov al, 0x85
    jmp .jcc
.jl:
    mov al, 0x8C
    jmp .jcc
.jge:
    mov al, 0x8D
    jmp .jcc
.jle:
    mov al, 0x8E
    jmp .jcc
.jg:
    mov al, 0x8F
    jmp .jcc
.jb:
    mov al, 0x82
    jmp .jcc
.jae:
    mov al, 0x83
    jmp .jcc
.jbe:
    mov al, 0x86
    jmp .jcc
.ja:
    mov al, 0x87
.jcc:
    call emit_jcc_placeholder
    jmp .next
.ldb:
    mov eax, r9d
    call emit_load_rdx
    mov r10b, r11b
    call emit_movzx_byte
    mov eax, r8d
    call emit_store_state
    jmp .next
.raw:
    mov byte [rdi], r8b
    add rdi, 1
    jmp .next
.ret:
    call emit_ret_instr

.next:
    inc r13d
    jmp .loop

.end:
    lea r10, [rel output_buf]
    sub rdi, r10
    mov [rel emitted_total], edi
    pop r14
    pop r13
    pop r12
    ret

; ── FIXUP ──────────────────────────────────────────────────────────
fixup:
    push r12
    push r13

    lea r15, [rel output_buf]
    mov r12d, [rel startup_end]
    xor r13d, r13d
    xor r14d, r14d

.loop:
    cmp r14d, [rel inst_count]
    jge .done

    lea rbx, [rel inst_buf]
    imul eax, r14d, 26
    add rbx, rax
    movzx ecx, byte [rbx]
    movzx eax, byte [rbx+25]
    mov r11d, eax

    cmp cl, 0x40
    je .next

    cmp cl, 0x41
    je .do5
    cmp cl, 0x70
    je .do5
    cmp cl, 0x71
    je .do6
    cmp cl, 0x72
    je .do6
    cmp cl, 0x73
    je .do6
    cmp cl, 0x74
    je .do6
    cmp cl, 0x75
    je .do6
    cmp cl, 0x76
    je .do6
    cmp cl, 0x77
    je .do6
    cmp cl, 0x78
    je .do6
    cmp cl, 0x79
    je .do6
    cmp cl, 0x7A
    je .do6
    jmp .next

.do5:
    mov edx, [rbx+1]
    lea rax, [rel handler_off]
    mov edx, [rax+rdx*4]
    add edx, r12d
    lea eax, [r12+r13]
    sub edx, eax
    sub edx, 5
    lea rax, [r15+r12]
    add rax, r13
    mov [rax+1], edx
    mov eax, r11d
    jmp .next

.do6:
    mov edx, [rbx+1]
    lea rax, [rel handler_off]
    mov edx, [rax+rdx*4]
    add edx, r12d
    lea eax, [r12+r13]
    sub edx, eax
    sub edx, 6
    lea rax, [r15+r12]
    add rax, r13
    mov [rax+2], edx
    mov eax, r11d

.next:
    add r13d, eax
    inc r14d
    jmp .loop

.done:
    ; Fixup startup blob's call to H_00 (call at offset 10)
    mov eax, [rel startup_end]
    sub eax, 15          ; startup_end - (call_offset + 5)
    mov [r15+11], eax    ; displacement field at call_offset + 1
    pop r13
    pop r12
    ret

; ── WRITE OUTPUT PE ────────────────────────────────────────────────
write_output:
    push r12
    push r13
    push r14

    lea r12, [rel pe_work_buf]

    mov word [r12], 'MZ'
    ; DEBUG
    mov ecx, [rel inst_count]
    mov [r12+4], ecx
    mov ecx, [rel emitted_total]
    mov [r12+8], ecx
    mov ecx, [rel startup_end]
    mov [r12+12], ecx
    ; DEBUG parse_debug (r14d at end of parse)
    mov eax, [rel parse_debug]
    mov [r12+0x1C], eax
    mov ecx, [rel emitted_total]
    mov [r12+8], ecx
    mov ecx, [rel startup_end]
    mov [r12+12], ecx
    mov ecx, [rel bytes_read]
    mov [r12+16], ecx
    mov ecx, [rel fixup_cnt]
    mov [r12+20], ecx
    mov ecx, [rel emitted_size]
    mov [r12+24], ecx
    ; Dump first 24 opcodes + 24 full slot0-2 bytes
    lea rsi, [rel inst_buf]
    lea rdi, [r12+0x28]
    mov ecx, 24
.dump_opcodes:
    movzx eax, byte [rsi]
    mov [rdi], al
    inc rdi
    add rsi, 26
    dec ecx
    jnz .dump_opcodes
    ; Dump raw inst_buf bytes 0-47 (first ~3 slots full)
    lea rsi, [rel inst_buf]
    lea rdi, [r12+0x40]
    mov ecx, 48
    rep movsb
    ; Dump first 16 bytes of input_buf
    lea rsi, [rel input_buf]
    lea rdi, [r12+0x70]
    mov ecx, 16
    rep movsb
    mov dword [r12+0x3C], 0x80
    mov dword [r12+0x80], 0x00004550
    mov word [r12+0x84], 0x8664
    mov word [r12+0x86], 1
    mov dword [r12+0x88], 0
    mov dword [r12+0x8C], 0
    mov dword [r12+0x90], 0
    mov word [r12+0x94], 0x80
    mov word [r12+0x96], 0x002F
    mov word [r12+0x98], 0x020B
    mov word [r12+0x9A], 0

    mov eax, [rel emitted_total]
    add eax, 0x1FF
    and eax, 0xFFFFFE00
    mov dword [r12+0x9C], eax
    mov dword [r12+0xA0], 0
    mov dword [r12+0xA4], 0
    mov dword [r12+0xA8], 0x1000
    mov dword [r12+0xAC], 0x1000
    mov dword [r12+0xB0], 0x40000000
    mov dword [r12+0xB4], 0x00000001
    mov dword [r12+0xB8], 0x1000
    mov dword [r12+0xBC], 0x200
    mov word [r12+0xC0], 6
    mov word [r12+0xC2], 0
    mov word [r12+0xC4], 0
    mov word [r12+0xC6], 0
    mov word [r12+0xC8], 6
    mov word [r12+0xCA], 0
    mov dword [r12+0xCC], 0
    mov eax, [rel emitted_total]
    add eax, 0xFFF
    and eax, 0xFFFFF000
    add eax, 0x1000
    mov dword [r12+0xD0], eax

    mov dword [r12+0xD4], 0x200
    mov dword [r12+0xD8], 0
    mov word [r12+0xDC], 3
    mov word [r12+0xDE], 0
    mov qword [r12+0xE0], 0x100000
    mov qword [r12+0xE8], 0x1000
    mov qword [r12+0xF0], 0x100000
    mov qword [r12+0xF8], 0x1000
    mov dword [r12+0x100], 0
    mov dword [r12+0x104], 0
    mov qword [r12+0x108], 0
    mov qword [r12+0x110], 0

    mov dword [r12+0x118], 0x7865742E
    mov dword [r12+0x11C], 0x00000074
    mov eax, [rel emitted_total]
    add eax, 0xFFF
    and eax, 0xFFFFF000
    mov dword [r12+0x120], eax
    mov dword [r12+0x124], 0x1000
    mov eax, [rel emitted_total]
    add eax, 0x1FF
    and eax, 0xFFFFFE00
    mov dword [r12+0x128], eax
    mov dword [r12+0x12C], 0x200
    mov dword [r12+0x130], 0
    mov dword [r12+0x134], 0
    mov word [r12+0x138], 0
    mov word [r12+0x13A], 0
    mov dword [r12+0x13C], 0x60000020

    mov ecx, [rel startup_end]
    add ecx, [rel emitted_total]
    lea rsi, [rel output_buf]
    lea rdi, [r12+0x200]
    rep movsb

    mov eax, [rel startup_end]
    add eax, [rel emitted_total]
    add eax, 0x1FF
    and eax, 0xFFFFFE00
    add eax, 0x200
    mov r14d, eax
    call open_write
    cmp rax, -1
    je .fail
    mov r13, rax

    mov rcx, r13
    lea rdx, [rel pe_work_buf]
    mov r8d, r14d
    lea r9, [rel bytes_written_pe]
    sub rsp, 0x30
    mov qword [rsp+0x20], 0   ; lpOverlapped = NULL
    call WriteFile
    add rsp, 0x30

    mov rcx, r13
    sub rsp, 0x20
    call CloseHandle
    add rsp, 0x20

    pop r14
    pop r13
    pop r12
    ret

.fail:
    mov ecx, 2
    call ExitProcess

section .bss
state_buf:     resb 2048
inst_buf:      resb 256*26
handler_off:   resd 256
fixup_buf:     resb 64*3
output_buf:    resb 65536
pe_work_buf:   resb 131072
parse_debug:   resq 1

section .data
fixup_cnt:     dd 0
inst_count:    dd 0
emitted_size:  dd 0
emitted_total: dd 0
startup_end:   dd 0
bytes_read:    dd 0
input_buf:     times 16384 db 0
input_fn:      db 'input.ky', 0
output_fn:     db 'output.exe', 0
bytes_written_pe: dd 0
