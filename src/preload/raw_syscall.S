#if defined(__i386__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:     /* syscallno = 4(%esp) */
        .cfi_startproc
        pushl %ebx        /* syscallno = 8(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %esi        /* syscallno = 12(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edi        /* syscallno = 16(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %ebp        /* syscallno = 20(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0

        movl 20(%esp), %eax /* %eax = syscallno */
        movl 24(%esp), %ebx /* %ebx = a0 */
        movl 28(%esp), %ecx /* %ecx = a1 */
        movl 32(%esp), %edx /* %edx = a2 */
        movl 36(%esp), %esi /* %esi = a3 */
        movl 40(%esp), %edi /* %edi = a4 */
        movl 44(%esp), %ebp /* %ebp = a5 */

        pushl 56(%esp)
        .cfi_adjust_cfa_offset 4
        pushl 56(%esp)
        .cfi_adjust_cfa_offset 4

        call *56(%esp)

        addl $8,%esp
        .cfi_adjust_cfa_offset -8
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        ret
        .cfi_endproc
        .size _raw_syscall, . - _raw_syscall

#elif defined(__x86_64__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:
        .cfi_startproc
        /* Incoming args are in %rdi, %rsi, %rdx, %rcx, %r8, %r9, and 8(%rsp).
	       Syscall arguments are %rdi, %rsi, %rdx, %r10, %r8, %r9. */
        movq %rdi, %rax         /* syscall number */
        movq %rsi, %rdi         /* first syscall arg */
        movq %rdx, %rsi         /* second syscall arg */
        movq %rcx, %rdx         /* third syscall arg */
        movq %r8, %r10          /* fourth syscall arg */
        movq %r9, %r8           /* fifth syscall arg */
        movq 8(%rsp), %r9       /* sixth syscall arg */

        pushq 32(%rsp)
        .cfi_adjust_cfa_offset 8
        pushq 32(%rsp)
        .cfi_adjust_cfa_offset 8

        /* During a system call the kernel makes some user-space-visible
           register changes:
           a) on entry, %r11 is set to %rflags
           b) %rcx is sometimes set to -1 (perhaps because of something rr does)
           c) on entry or exit, some flags are sometimes changed
           Also, during replay we may perform single-stepping which can set
           TF (trace flag). We need to hide this.

           fixup_syscall_registers is responsible for fixing up registers
           to hide these effects when we get a ptrace trap from system calls
           in the kernel: it clears TF from %r11, forces %rcx to -1, and sets
           flags to fixed values (ZF+PF+IF+reserved, same as for "xor reg,reg").
           Task::canonicalize_and_set_regs is responsible for fixing up registers
           when we emulate a system call that was traced during recording (by
           running to a breakpoint at that system call). It does the above
           effects after setting %r11 to %rflags.

           For untraced system calls there is no trap to rr during recording or
           replay, so we must handle these issues here. We do not need
           untraced system calls to behave exactly the same as traced
           system calls, since whether a given system call was traced or not is
           the same whether recording or replaying, but it's a good idea to
           make them as similar as possible. We do need register values
           to be perfectly consistent at every instruction in every replay
           whether or not singlestepping is used (because a ReplayTimeline::mark
           might be created at any point). During replay, untraced syscall
           instructions are replaced with "xor %eax,%eax".

           The following code is harmless for traced syscalls (and needs to be,
           because traced syscalls go through here too).
         */

        /* Set %r11 and %rcx to the values we expect them to have after the
           system call.
           Set flags to ZF+PF+IF+reserved (0x246) first. This simplifies
           everything.
           This all has to be independent of TF being set at any point during
           replay! But the way we're doing it here, it's trivial.
         */
        xor %ecx,%ecx
        /* At this point, flags are 0x246 + possibly TF. */
        movq $0x246,%r11
        movq $-1,%rcx

        callq *32(%rsp)

        /* At this point, during recording we don't trust the kernel to have
           restored flags correctly. It probably doesn't matter, but fix it
           anyway. */
        xor %ecx,%ecx
        /* At this point, the high 32 bits of %rcx are unknown. Fix that by
           setting to -1 to match traced syscalls. */
        movq $-1,%rcx
        /* At this point, %r11 is always 0x246 during replay and during
           recording (because TF is never set during recording). Nothing to
           fix in %r11. */

        addq $16,%rsp
        .cfi_adjust_cfa_offset -16
        ret
        .cfi_endproc
        .size _raw_syscall, . - _raw_syscall

#elif defined(__aarch64__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:
        .cfi_startproc
        // The two stack arguments needs to be at sp + 8 and sp + 16
        // but they are currently at sp and sp + 8.
        // Since sp needs to be 16 bytes aligned we need to load and push them again.
        str x30, [sp, -32]!
        .cfi_def_cfa_offset 32
        .cfi_offset x30, -32
        ldp x8, x30, [sp, 32]
        stp x8, x30, [sp, 8]
        mov x8,x0
        mov x0,x1
        mov x1,x2
        mov x2,x3
        mov x3,x4
        mov x4,x5
        mov x5,x6
        blr x7
        ldr x30, [sp], 32
        .cfi_def_cfa_offset 0
        .cfi_restore x30
        ret
        .cfi_endproc
        .size _raw_syscall, . - _raw_syscall
#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */

/* The syscallbuf code calls these functions to check that it can access
 * tracee memory (see can_write() etc in syscallbuf.c). Each one touches every
 * page of its range (or the bytes of a string up to its NUL) and returns 1.
 * When one of their accesses faults, rr sets the ip to _memory_check_failed,
 * which returns 0. They must not use the stack, so that its `ret` returns to
 * the caller, and rr must not see a fault anywhere else in
 * [_memory_checks_start, _memory_checks_end). But when replay wouldn't fault
 * (a SIGBUS, or a protection key fault), rr skips the access instead, or
 * aborts if it's in _memory_check_readable_str. So the instructions after an
 * access must not depend on its effects. (rr recognizes the access and the
 * instruction after it by their bytes; see
 * skippable_memory_check_access_length.)
 *
 * long _memory_check_writable(void* addr, size_t len): with an atomic RMW
 *   that doesn't change the memory
 * long _memory_check_readable(const void* addr, size_t len)
 * long _memory_check_readable_str(const char* str)
 */
        .text
        .global _memory_check_failed
        .hidden _memory_check_failed
        .global _memory_checks_start
        .hidden _memory_checks_start
        .global _memory_check_writable
        .hidden _memory_check_writable
        .global _memory_check_readable
        .hidden _memory_check_readable
        .global _memory_check_readable_str
        .hidden _memory_check_readable_str
        .global _memory_checks_end
        .hidden _memory_checks_end
#if defined(__x86_64__)
_memory_check_failed:
        .cfi_startproc
        xor %eax, %eax
        ret
        .cfi_endproc
_memory_checks_start:
_memory_check_writable:
        .cfi_startproc
        mov $1, %eax
        test %rsi, %rsi
        jz 2f
        add %rdi, %rsi
        jc 3f
1:      lock orb $0, (%rdi)
        and $-4096, %rdi
        add $4096, %rdi
        cmp %rsi, %rdi
        jb 1b
2:      ret
3:      xor %eax, %eax
        ret
        .cfi_endproc
_memory_check_readable:
        .cfi_startproc
        mov $1, %eax
        test %rsi, %rsi
        jz 2f
        add %rdi, %rsi
        jc 3f
1:      cmpb $0, (%rdi)
        and $-4096, %rdi
        add $4096, %rdi
        cmp %rsi, %rdi
        jb 1b
2:      ret
3:      xor %eax, %eax
        ret
        .cfi_endproc
_memory_check_readable_str:
        .cfi_startproc
        mov $1, %eax
1:      cmpb $0, (%rdi)
        je 2f
        add $1, %rdi
        jmp 1b
2:      ret
        .cfi_endproc
_memory_checks_end:
#elif defined(__i386__)
_memory_check_failed:
        .cfi_startproc
        xor %eax, %eax
        ret
        .cfi_endproc
_memory_checks_start:
_memory_check_writable:
        .cfi_startproc
        mov 4(%esp), %ecx
        mov 8(%esp), %edx
        mov $1, %eax
        test %edx, %edx
        jz 2f
        add %ecx, %edx
        jc 3f
1:      lock orb $0, (%ecx)
        and $-4096, %ecx
        add $4096, %ecx
        cmp %edx, %ecx
        jb 1b
2:      ret
3:      xor %eax, %eax
        ret
        .cfi_endproc
_memory_check_readable:
        .cfi_startproc
        mov 4(%esp), %ecx
        mov 8(%esp), %edx
        mov $1, %eax
        test %edx, %edx
        jz 2f
        add %ecx, %edx
        jc 3f
1:      cmpb $0, (%ecx)
        and $-4096, %ecx
        add $4096, %ecx
        cmp %edx, %ecx
        jb 1b
2:      ret
3:      xor %eax, %eax
        ret
        .cfi_endproc
_memory_check_readable_str:
        .cfi_startproc
        mov 4(%esp), %ecx
        mov $1, %eax
1:      cmpb $0, (%ecx)
        je 2f
        add $1, %ecx
        jmp 1b
2:      ret
        .cfi_endproc
_memory_checks_end:
#elif defined(__aarch64__)
        /* rr requires LSE atomics on aarch64 */
        .arch_extension lse
_memory_check_failed:
        .cfi_startproc
        mov x0, #0
        ret
        .cfi_endproc
_memory_checks_start:
_memory_check_writable:
        .cfi_startproc
        cbz x1, 2f
        adds x1, x0, x1
        b.cs 3f
1:      stclrb wzr, [x0]
        and x0, x0, #~4095
        add x0, x0, #4096
        cmp x0, x1
        b.lo 1b
2:      mov x0, #1
        ret
3:      mov x0, #0
        ret
        .cfi_endproc
_memory_check_readable:
        .cfi_startproc
        cbz x1, 2f
        adds x1, x0, x1
        b.cs 3f
1:      ldrb wzr, [x0]
        and x0, x0, #~4095
        add x0, x0, #4096
        cmp x0, x1
        b.lo 1b
2:      mov x0, #1
        ret
3:      mov x0, #0
        ret
        .cfi_endproc
_memory_check_readable_str:
        .cfi_startproc
1:      ldrb w2, [x0], #1
        cbnz w2, 1b
        mov x0, #1
        ret
        .cfi_endproc
_memory_checks_end:
#endif

        .global _syscallbuf_code_end
        .hidden _syscallbuf_code_end
_syscallbuf_code_end:

        .section .note.GNU-stack,"",@progbits
        .previous
