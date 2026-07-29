; Indirect syscall stub for x64 Windows
; Executes the syscall instruction from within ntdll's own code section,
; so the call stack shows a legitimate return address in ntdll.
;
; Calling convention:
;   indirect_syscall(DWORD ssn, PVOID syscall_addr, ...)
;   rcx = SSN
;   rdx = address of `syscall` instruction in ntdll
;   r8, r9, [rsp+...] = actual Nt* function arguments

.code

indirect_syscall PROC
    ; Save the syscall address (rdx) for the final jmp
    mov r10, rdx

    ; Move SSN into eax (this is what the kernel reads)
    mov eax, ecx

    ; Shift all arguments: the real Nt* args start at r8
    ; arg1 (originally r8)  -> rcx (where Nt* expects it)
    ; arg2 (originally r9)  -> rdx
    ; arg3 (originally [rsp+0x28]) -> r8
    ; arg4 (originally [rsp+0x30]) -> r9
    ; arg5+ stay on stack but shifted
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]

    ; For stack args (5th param onward), we need to adjust
    ; The caller already set up the shadow space + args on stack
    ; We just need to make sure the stack args are in the right place
    ; Since we consumed 2 extra params (ssn, addr), stack args are offset by +16

    ; Jump to the `syscall` instruction in ntdll
    ; This makes the return address point into ntdll (legitimate call stack)
    jmp r10

indirect_syscall ENDP

end
