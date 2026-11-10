/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "../ptrace_util.h"

/* A ptracer sets the flags (on x86-64 also rcx and r11) of its tracee at
   the syscall-entry stops of a getpid and an mmap. After each of these
   syscalls the tracee passes the values it has in those registers to a
   getppid as arguments, so rr compares them between recording and replay
   at the getppid's entry. */

#define STR2(x) #x
#define STR(x) STR2(x)

#ifdef SYS_mmap2
#define MMAP_SYSCALLNO SYS_mmap2
#else
#define MMAP_SYSCALLNO SYS_mmap
#endif

/* Makes syscall |no| with arguments |a1| to |a6|, then a getppid whose
   arguments are the flags (on x86-64 also rcx and r11) that syscall left.
   Returns the result of syscall |no|. */
long syscall_then_getppid(long no, long a1, long a2, long a3, long a4,
                          long a5, long a6);
extern char after_first_syscall;

#if defined(__x86_64__)
__asm__(".text\n"
        ".globl syscall_then_getppid\n"
        ".type syscall_then_getppid,@function\n"
        "syscall_then_getppid:\n\t"
        "mov %rdi,%rax\n\t"
        "mov %rsi,%rdi\n\t"
        "mov %rdx,%rsi\n\t"
        "mov %rcx,%rdx\n\t"
        "mov %r8,%r10\n\t"
        "mov %r9,%r8\n\t"
        "mov 8(%rsp),%r9\n\t"
        "syscall\n\t"
        ".globl after_first_syscall\n"
        "after_first_syscall:\n\t"
        "pushf\n\t"
        "pop %rdi\n\t"
        "mov %rcx,%rsi\n\t"
        "mov %r11,%rdx\n\t"
        "mov %rax,%r8\n\t"
        "mov $" STR(SYS_getppid) ",%eax\n\t"
        "syscall\n\t"
        "mov %r8,%rax\n\t"
        "ret\n\t"
        ".size syscall_then_getppid,.-syscall_then_getppid\n");
#elif defined(__i386__)
__asm__(".text\n"
        ".globl syscall_then_getppid\n"
        ".type syscall_then_getppid,@function\n"
        "syscall_then_getppid:\n\t"
        "push %ebp\n\t"
        "push %edi\n\t"
        "push %esi\n\t"
        "push %ebx\n\t"
        "mov 20(%esp),%eax\n\t"
        "mov 24(%esp),%ebx\n\t"
        "mov 28(%esp),%ecx\n\t"
        "mov 32(%esp),%edx\n\t"
        "mov 36(%esp),%esi\n\t"
        "mov 40(%esp),%edi\n\t"
        "mov 44(%esp),%ebp\n\t"
        "int $0x80\n\t"
        ".globl after_first_syscall\n"
        "after_first_syscall:\n\t"
        "pushf\n\t"
        "pop %ebx\n\t"
        "mov %eax,%esi\n\t"
        "mov $" STR(SYS_getppid) ",%eax\n\t"
        "int $0x80\n\t"
        "mov %esi,%eax\n\t"
        "pop %ebx\n\t"
        "pop %esi\n\t"
        "pop %edi\n\t"
        "pop %ebp\n\t"
        "ret\n\t"
        ".size syscall_then_getppid,.-syscall_then_getppid\n");
#endif

int main(void) {
  pid_t child;
  int status;
  int entry_stops = 0;
  long page_size = sysconf(_SC_PAGESIZE);

  child = fork();
  test_assert(child >= 0);
  if (0 == child) {
    long ret;
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, 0, 0));
    raise(SIGSTOP);
    ret = syscall_then_getppid(SYS_getpid, 0, 0, 0, 0, 0, 0);
    test_assert(ret == getpid());
    ret = syscall_then_getppid(MMAP_SYSCALLNO, 0, page_size,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert((unsigned long)ret < (unsigned long)-4095);
    return 0;
  }
  test_assert(child > 1);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 ==
              ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD));
  while (1) {
    struct user_regs_struct regs;
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    if (WIFEXITED(status)) {
      break;
    }
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));
    ptrace_getregs(child, &regs);
    if ((uintptr_t)regs.IP != (uintptr_t)&after_first_syscall ||
        (long)regs.SYSCALL_RESULT != -ENOSYS) {
      continue;
    }
    /* Syscall-entry stop: set CF, PF, AF, ZF, SF and OF */
    regs.eflags |= 0x8d5;
#ifdef __x86_64__
    regs.rcx = 0x1234;
    regs.r11 = 0x5678;
#endif
    ptrace_setregs(child, &regs);
    ++entry_stops;
  }
  test_assert(0 == WEXITSTATUS(status));
  test_assert(2 == entry_stops);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
