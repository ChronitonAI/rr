/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A tracer stops its tracee with a signal while the tracee is blocked in a
   read(), suppresses the signal and single-steps the tracee, which restarts
   the read(). The step must end after the read().
   On x86, the tracer then does the same with another read(), but cancels the
   restart by setting orig_ax to -1 and moves the ip, as gdb does when it
   writes the pc. Then the step must execute just one instruction.
   Last, on x86, the tracer resumes a tracee from such a stop with
   PTRACE_SYSEMU_SINGLESTEP. The step must end at the entry of the restarted
   read(), and the tracer emulates the read(). */

static int fds[2];

#if defined(__x86_64__) || defined(__i386__)
extern char step_target[];
extern char step_target_next[];

/* One instruction, then exit_group(77). */
__asm__(".text\n"
        "step_target:\n"
        "  nop\n"
        "step_target_next:\n"
#if defined(__x86_64__)
        "  mov $231, %eax\n"
        "  mov $77, %edi\n"
        "  syscall\n"
#else
        "  mov $252, %eax\n"
        "  mov $77, %ebx\n"
        "  int $0x80\n"
#endif
        "  hlt\n");

/* A read() that doesn't go through the syscall buffer: rr doesn't patch
   syscalls in a task that has a ptracer. */
static long raw_read(int fd, void* buf, size_t count) {
  long ret;
#if defined(__x86_64__)
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
                       : "rcx", "r11", "memory");
#else
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "a"((long)SYS_read), "b"(fd), "c"(buf), "d"(count)
                       : "memory");
#endif
  return ret;
}
#endif

/* Lets the tracee run from its first stop until it blocks in its read(),
   and stops it there with SIGUSR2. */
static void stop_in_read(pid_t pid) {
  int status;
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));

  wait_for_task_asleep_in_syscall(pid, SYS_read, fds[0]);
  test_assert(0 == kill(pid, SIGUSR2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR2);
}

int main(void) {
  pid_t pid;
  int status;
  char ch;

  test_assert(0 == pipe(fds));
  /* rr doesn't patch syscalls in a task that has a ptracer. Do a read() here,
     so that the child's read() can use the syscall buffer. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(1 == read(fds[0], &ch, 1));

  if (0 == (pid = fork())) {
    char buf[4];
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    test_assert(4 == read(fds[0], buf, 4));
    test_assert(0 == memcmp(buf, "abcd", 4));
    raise(SIGUSR1);
    return 77;
  }
  test_assert(pid > 0);
  stop_in_read(pid);

  /* Suppress SIGUSR2. The read() restarts and finds the data. */
  test_assert(4 == write(fds[1], "abcd", 4));
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

#if defined(__x86_64__) || defined(__i386__)
  if (0 == (pid = fork())) {
    char buf[4];
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    raw_read(fds[0], buf, 4);
    test_assert(0);
  }
  test_assert(pid > 0);
  stop_in_read(pid);

  {
    struct user_regs_struct regs;
    ptrace_getregs(pid, &regs);
    test_assert(regs.ORIG_SYSCALLNO == SYS_read);
    regs.ORIG_SYSCALLNO = -1;
    regs.IP = (uintptr_t)step_target;
    ptrace_setregs(pid, &regs);
    /* Suppress SIGUSR2. The read() doesn't restart. */
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptrace_getregs(pid, &regs);
    test_assert((uintptr_t)regs.IP == (uintptr_t)step_target_next);
  }

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  if (0 == (pid = fork())) {
    char buf[4];
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    test_assert(4 == raw_read(fds[0], buf, 4));
    return 77;
  }
  test_assert(pid > 0);
  stop_in_read(pid);

  {
    struct user_regs_struct regs;
    /* Suppress SIGUSR2. The read() restarts. */
    test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptrace_getregs(pid, &regs);
    test_assert(regs.ORIG_SYSCALLNO == SYS_read);
    /* Emulate the read(). */
    regs.SYSCALL_RESULT = 4;
    ptrace_setregs(pid, &regs);
  }

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
