/* Indirect syscall stub for x64 Windows (GAS syntax for MinGW) */

.global indirect_syscall
.text

indirect_syscall:
    /* rcx = SSN, rdx = syscall_addr, r8/r9/stack = real args */
    mov %rdx, %r10       /* save syscall addr */
    mov %ecx, %eax       /* SSN into eax */

    /* Shift args: real params start at r8 */
    mov %r8, %rcx        /* arg1 */
    mov %r9, %rdx        /* arg2 */
    mov 0x28(%rsp), %r8  /* arg3 */
    mov 0x30(%rsp), %r9  /* arg4 */

    /* Jump to syscall instruction in ntdll */
    jmp *%r10
