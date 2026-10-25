/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A tracer skips a restarted syscall of its child, with PTRACE_SYSEMU or by
   setting the syscall number to -1 at its syscall-entry stop: it sends the
   child a signal while it's blocked in readv() and resumes it from the
   signal-delivery stop, suppressing the signal. The child then restarts the
   readv(). */

static int fds[2];

/* Wait for a syscall stop of readv() (or of a skipped syscall, for an exit),
   of kind |op| if the kernel can tell us. */
static void wait_for_readv_stop(pid_t child, int op) {
  struct rr_ptrace_syscall_info info;
  int status;
  long ret;

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, (void*)sizeof(info), &info);
  if (ret < 0) {
    /* PTRACE_GET_SYSCALL_INFO was added in Linux 5.3. */
    test_assert(errno == EIO);
    return;
  }
  test_assert(info.op == op);
  if (op == RR_PTRACE_SYSCALL_INFO_ENTRY) {
    test_assert(info.entry.nr == SYS_readv);
  }
}

/* Interrupt the child in readv() and resume it with PTRACE_SYSEMU, which
   gives the syscall-entry stop of the restarted readv(). */
static void skip_restarted_readv(pid_t child) {
  int status;

  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY);
}

int main(void) {
  struct user_regs_struct regs;
  struct iovec iov;
  pid_t child;
  int status;
  char ch;

  test_assert(0 == pipe(fds));

  if (0 == (child = fork())) {
    /* readv() fails when the tracer skips it. The syscall buffer doesn't
       handle readv(). */
    iov.iov_base = &ch;
    iov.iov_len = 1;
    do {
      ch = 0;
      readv(fds[0], &iov, 1);
    } while (ch != 'q');
    return 77;
  }
  test_assert(child > 0);

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));

  /* With PTRACE_SYSCALL from the syscall-entry stop, the skipped readv()
     gets a syscall-exit stop. The next stop is the syscall-entry stop of the
     child's next readv(). */
  skip_restarted_readv(child);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT);
  ptrace_getregs(child, &regs);
#if !defined(__aarch64__)
  test_assert((uintptr_t)regs.SYSCALL_RESULT == (uintptr_t)-ENOSYS);
#endif
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY);

  /* With PTRACE_CONT from the syscall-entry stop, the child goes on to block
     in its next readv(). */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  skip_restarted_readv(child);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);

  /* A tracer that uses PTRACE_SYSCALL can skip the restarted readv() too,
     by setting the syscall number to -1 at the syscall-entry stop. That
     gives a syscall-exit stop. */
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY);
  ptrace_getregs(child, &regs);
  ptrace_change_syscall(child, &regs, -1);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT);
#if !defined(__aarch64__)
  ptrace_getregs(child, &regs);
  test_assert((uintptr_t)regs.SYSCALL_RESULT == (uintptr_t)-ENOSYS);
#endif
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_readv_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);

  test_assert(1 == write(fds[1], "q", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
