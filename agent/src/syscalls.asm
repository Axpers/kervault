; Indirect syscall stubs for x64 Windows (MASM syntax for ml64.exe)
;
; Call stack spoofing: sub rsp,8 places a ntdll ret gadget at [rsp].
; After syscall;ret, the first ret returns into the gadget (another ret
; in ntdll), which pops the real return address — making the captured
; stack trace show a return through ntdll instead of our code.

EXTERN g_ret_gadget:QWORD

.code

; -- 0 shifts (<=4 NT args) --
indirect_syscall PROC
    sub rsp, 8
    mov rax, qword ptr [g_ret_gadget]
    mov [rsp], rax
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 30h]
    mov r9, [rsp + 38h]
    mov r10, rcx
    jmp r11
indirect_syscall ENDP

; -- 2 shifts (5-6 NT args) --
indirect_syscall_s2 PROC
    sub rsp, 8
    mov rax, qword ptr [g_ret_gadget]
    mov [rsp], rax
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 30h]
    mov r9, [rsp + 38h]
    mov r10, [rsp + 40h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 48h]
    mov [rsp + 30h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s2 ENDP

; -- 7 shifts (9-11 NT args) --
indirect_syscall_s7 PROC
    sub rsp, 8
    mov rax, qword ptr [g_ret_gadget]
    mov [rsp], rax
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 30h]
    mov r9, [rsp + 38h]
    mov r10, [rsp + 40h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 48h]
    mov [rsp + 30h], r10
    mov r10, [rsp + 50h]
    mov [rsp + 38h], r10
    mov r10, [rsp + 58h]
    mov [rsp + 40h], r10
    mov r10, [rsp + 60h]
    mov [rsp + 48h], r10
    mov r10, [rsp + 68h]
    mov [rsp + 50h], r10
    mov r10, [rsp + 70h]
    mov [rsp + 58h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s7 ENDP

; -- 10 shifts (14 NT args) --
indirect_syscall_s10 PROC
    sub rsp, 8
    mov rax, qword ptr [g_ret_gadget]
    mov [rsp], rax
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 30h]
    mov r9, [rsp + 38h]
    mov r10, [rsp + 40h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 48h]
    mov [rsp + 30h], r10
    mov r10, [rsp + 50h]
    mov [rsp + 38h], r10
    mov r10, [rsp + 58h]
    mov [rsp + 40h], r10
    mov r10, [rsp + 60h]
    mov [rsp + 48h], r10
    mov r10, [rsp + 68h]
    mov [rsp + 50h], r10
    mov r10, [rsp + 70h]
    mov [rsp + 58h], r10
    mov r10, [rsp + 78h]
    mov [rsp + 60h], r10
    mov r10, [rsp + 80h]
    mov [rsp + 68h], r10
    mov r10, [rsp + 88h]
    mov [rsp + 70h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s10 ENDP

end
