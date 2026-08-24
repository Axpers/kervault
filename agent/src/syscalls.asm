; Indirect syscall stubs for x64 Windows (MASM syntax for ml64.exe)
;
; Each variant shifts exactly N stack slots to compensate for the
; +0x10 offset from the 2 extra C params (SSN, addr).

.code

; ── 0 shifts (≤4 NT args) ────────────────────────────────────
indirect_syscall PROC
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]
    mov r10, rcx
    jmp r11
indirect_syscall ENDP

; ── 2 shifts (5-6 NT args) ───────────────────────────────────
indirect_syscall_s2 PROC
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]
    mov r10, [rsp + 38h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 40h]
    mov [rsp + 30h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s2 ENDP

; ── 7 shifts (9-11 NT args) ──────────────────────────────────
indirect_syscall_s7 PROC
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]
    mov r10, [rsp + 38h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 40h]
    mov [rsp + 30h], r10
    mov r10, [rsp + 48h]
    mov [rsp + 38h], r10
    mov r10, [rsp + 50h]
    mov [rsp + 40h], r10
    mov r10, [rsp + 58h]
    mov [rsp + 48h], r10
    mov r10, [rsp + 60h]
    mov [rsp + 50h], r10
    mov r10, [rsp + 68h]
    mov [rsp + 58h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s7 ENDP

; ── 10 shifts (14 NT args) ───────────────────────────────────
indirect_syscall_s10 PROC
    mov r11, rdx
    mov eax, ecx
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]
    mov r10, [rsp + 38h]
    mov [rsp + 28h], r10
    mov r10, [rsp + 40h]
    mov [rsp + 30h], r10
    mov r10, [rsp + 48h]
    mov [rsp + 38h], r10
    mov r10, [rsp + 50h]
    mov [rsp + 40h], r10
    mov r10, [rsp + 58h]
    mov [rsp + 48h], r10
    mov r10, [rsp + 60h]
    mov [rsp + 50h], r10
    mov r10, [rsp + 68h]
    mov [rsp + 58h], r10
    mov r10, [rsp + 70h]
    mov [rsp + 60h], r10
    mov r10, [rsp + 78h]
    mov [rsp + 68h], r10
    mov r10, [rsp + 80h]
    mov [rsp + 70h], r10
    mov r10, rcx
    jmp r11
indirect_syscall_s10 ENDP

end
