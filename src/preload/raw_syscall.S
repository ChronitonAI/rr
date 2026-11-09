/* When a software-ticks compiler pass builds the preload library (the pass
   predefines __RR_SOFTTICKS__ as the tracee ABI version it implements, for
   assembler sources too), the library's compiled code ticks and the library
   carries the note that promises include/rr/softticks.h's guarantee: no
   instrumented instruction executes twice at the same pc and stack pointer
   without a tick in between. The pass cannot place ticks here, and
   _raw_syscall is called several times from one frame with no tick in
   between (e.g. start_commit_buffered_syscall's getpid, gettid and getuid
   calls), so it ticks at its entry, as compiled functions do. The sequences
   are the ABI's, byte for byte (RR_SOFTTICKS_*_TICK_ASM), so a trap in one is
   an ordinary tick trap. They clobber only the flags (x86) or x16 and x17
   (aarch64), which are dead at a function's entry; the flags are set again
   before the system call. Every call of _raw_syscall happens in replay as in
   recording (the instruction it calls differs, not the path to it), so the
   tick counts match. */
#include "rr/softticks.h"
#if defined(__RR_SOFTTICKS__) && __RR_SOFTTICKS__ != RR_SOFTTICKS_ABI_VERSION
#error "raw_syscall.S implements software ticks ABI version 1 only"
#endif

#if defined(__i386__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:     /* syscallno = 4(%esp) */
        .cfi_startproc
#if defined(__RR_SOFTTICKS__)
        testb $0x80, 0x70001807
        jnz 1f
        subl $1, 0x70001800
        jnz 1f
        subl $1, 0x70001804
        jae 1f
        int3
1:
#endif
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
#if defined(__RR_SOFTTICKS__)
        testb $0x80, 0x70001807
        jnz 1f
        decq 0x70001800
        jnz 1f
        int3
1:
#endif
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
#if defined(__RR_SOFTTICKS__)
        movz x16, #0x7001, lsl #16
        ldr x17, [x16, #0x800]
        tbnz x17, #63, 1f
        sub x17, x17, #1
        str x17, [x16, #0x800]
        cbnz x17, 1f
        brk #0x5354
1:
        mov x17, xzr
#endif
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
        .global _syscallbuf_code_end
        .hidden _syscallbuf_code_end
_syscallbuf_code_end:

        .section .note.GNU-stack,"",@progbits
        .previous
