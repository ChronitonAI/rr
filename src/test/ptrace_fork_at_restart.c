/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"
#include "ptrace_util.h"

/* A tracer interrupts its child's read() of a pipe with a signal. At the
   signal-delivery stop it suppresses the signal and changes the syscall
   number, so that the kernel restarts the read() as a fork().

   rr resumes the child with PTRACE_SYSCALL, since the interrupted read()
   may restart, so on kernels that report the syscall-entry stop before the
   PTRACE_EVENT_SECCOMP stop, the fork()'s syscall-entry stop comes first.
   rr must record the fork(). */

#define CHILD_STATUS 77
#define GRANDCHILD_STATUS 78

static int pipe_fds[2];

static int run_child(void) {
  char ch;
  intptr_t ret;
  int status;

  /* The syscall buffer doesn't handle this read(). */
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  if (ret == 0) {
    return GRANDCHILD_STATUS;
  }
  test_assert(ret > 0);
  test_assert(ret == waitpid(ret, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == GRANDCHILD_STATUS);
  return CHILD_STATUS;
}

int main(void) {
  struct user_regs_struct regs;
  pid_t child;
  int status;

  test_assert(0 == pipe(pipe_fds));
  if (0 == (child = fork())) {
    return run_child();
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, pipe_fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  ptrace_getregs(child, &regs);
#if defined(__aarch64__)
  regs.ORIG_SYSCALLNO = SYS_clone;
  regs.regs[0] = SIGCHLD;
  regs.regs[1] = 0;
  regs.regs[2] = 0;
  regs.regs[3] = 0;
  regs.regs[4] = 0;
#else
  regs.ORIG_SYSCALLNO = SYS_fork;
#endif
  ptrace_setregs(child, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));

  while (1) {
    test_assert(child == waitpid(child, &status, 0));
    if (!WIFSTOPPED(status)) {
      break;
    }
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL,
                            (void*)(uintptr_t)WSTOPSIG(status)));
  }
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == CHILD_STATUS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
