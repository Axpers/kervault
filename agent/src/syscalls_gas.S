/* Indirect syscall stub for x64 Windows (GAS syntax for MinGW)
 *
 * Windows syscall convention: kernel reads first param from r10 (not rcx,
 * because the syscall instruction destroys rcx with the return address).
 */

.global indirect_syscall
.text

indirect_syscall:
    /* rcx = SSN, rdx = syscall_addr, r8/r9/stack = real Nt* args */
    mov %rdx, %r11       /* save syscall addr in r11 (r10 is needed for arg1) */
    mov %ecx, %eax       /* SSN into eax */

    /* Shift real args into position */
    mov %r8, %rcx        /* arg1 -> rcx */
    mov %r9, %rdx        /* arg2 -> rdx */
    mov 0x28(%rsp), %r8  /* arg3 */
    mov 0x30(%rsp), %r9  /* arg4 */

    /* Kernel reads first param from r10 (syscall clobbers rcx) */
    mov %rcx, %r10

    /* Jump to syscall instruction in ntdll */
    jmp *%r11
