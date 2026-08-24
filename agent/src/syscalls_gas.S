/* Indirect syscall stubs for x64 Windows (GAS syntax for MinGW)
 *
 * Calling: indirect_syscall_sN(SSN, syscall_addr, arg1, arg2, ..., argM)
 *   rcx = SSN, rdx = syscall_addr
 *   r8 = arg1, r9 = arg2, [rsp+0x28..] = arg3..argM
 *
 * The 2 extra C params (SSN, addr) shift all stack args by +0x10.
 * Each stub variant copies exactly N stack slots to fix the offset,
 * matching the number of NT args that live on the stack (NT_args - 4).
 *
 * Using the wrong stub for a function will corrupt the caller's stack.
 */

.macro SYSCALL_STUB name, shifts
.global \name
\name:
    mov %rdx, %r11
    mov %ecx, %eax
    mov %r8, %rcx
    mov %r9, %rdx
    mov 0x28(%rsp), %r8
    mov 0x30(%rsp), %r9
    .set _off, 0
    .rept \shifts
    mov (0x38 + _off)(%rsp), %r10
    mov %r10, (0x28 + _off)(%rsp)
    .set _off, _off + 8
    .endr
    mov %rcx, %r10
    jmp *%r11
.endm

.text

SYSCALL_STUB indirect_syscall,     0
SYSCALL_STUB indirect_syscall_s2,  2
SYSCALL_STUB indirect_syscall_s7,  7
SYSCALL_STUB indirect_syscall_s10, 10
