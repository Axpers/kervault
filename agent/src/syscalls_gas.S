/* Indirect syscall stub for x64 Windows (GAS syntax for MinGW)
 *
 * Calling: indirect_syscall(SSN, syscall_addr, arg1, arg2, arg3, arg4, [arg5, arg6])
 * Transforms to kernel: r10=arg1, rdx=arg2, r8=arg3, r9=arg4, [rsp+0x28]=arg5, [rsp+0x30]=arg6
 *
 * No push/pop — no callee-saved register clobbering.
 */

.global indirect_syscall
.text

indirect_syscall:
    mov %rdx, %r11       /* save syscall jump target in r11 */
    mov %ecx, %eax       /* SSN into eax */

    /* Load register args from their current positions */
    mov %r8, %rcx        /* arg1 (was in r8) -> rcx */
    mov %r9, %rdx        /* arg2 (was in r9) -> rdx */
    mov 0x28(%rsp), %r8  /* arg3 (5th C param) -> r8 */
    mov 0x30(%rsp), %r9  /* arg4 (6th C param) -> r9 */

    /* Copy stack args 5,6 into kernel-expected positions.
     * arg5 is at rsp+0x38, kernel expects it at rsp+0x28.
     * arg6 is at rsp+0x40, kernel expects it at rsp+0x30.
     * We can now safely overwrite rsp+0x28/0x30 (already loaded into r8/r9). */
    mov 0x38(%rsp), %r10
    mov %r10, 0x28(%rsp)
    mov 0x40(%rsp), %r10
    mov %r10, 0x30(%rsp)

    /* r10 = first arg for kernel (syscall clobbers rcx) */
    mov %rcx, %r10

    /* Jump to syscall;ret in ntdll */
    jmp *%r11
