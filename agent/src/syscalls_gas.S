/* Indirect syscall stubs for x64 Windows (GAS syntax for MinGW)
 *
 * Call stack spoofing: sub rsp,8 places a ntdll ret gadget at [rsp].
 * After syscall;ret in ntdll, the first ret jumps to the gadget (also
 * a ret), which pops the real return address. The top of the captured
 * call stack therefore shows a return through ntdll, not our code.
 *
 * The sub shifts all stack-relative reads by +8; write destinations
 * stay at the offsets the kernel expects (0x28+).
 */

.macro SYSCALL_STUB name, shifts
.global \name
\name:
    sub $8, %rsp
    movq g_ret_gadget(%rip), %rax
    mov %rax, (%rsp)
    mov %rdx, %r11
    mov %ecx, %eax
    mov %r8, %rcx
    mov %r9, %rdx
    mov 0x30(%rsp), %r8
    mov 0x38(%rsp), %r9
    .set _off, 0
    .rept \shifts
    mov (0x40 + _off)(%rsp), %r10
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
