/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"
#include "ptrace_util.h"

/* A tracer interrupts its child's read() of an empty pipe with a signal,
   writes a byte to the pipe and resumes the child from the
   signal-delivery stop with PTRACE_SYSEMU, suppressing the signal. At the
   syscall-entry stop of the restarted read() it sets the result to
   EMULATED_RESULT. The read() must not run: the byte stays in the pipe.

   rr resumes the child with PTRACE_SYSCALL, since the interrupted read()
   may restart, so on kernels that report the syscall-entry stop before the
   PTRACE_EVENT_SECCOMP stop, the restarted read()'s syscall-entry stop
   comes first. rr must skip the read(). */

#define CHILD_STATUS 77
#define EMULATED_RESULT 42

static int pipe_fds[2];

static int run_child(void) {
  char ch = 0;
  intptr_t ret;

  /* The syscall buffer doesn't handle this read(). */
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  test_assert(ret == EMULATED_RESULT);
  test_assert(ch == 0);
  test_assert(1 == read(pipe_fds[0], &ch, 1));
  test_assert(ch == 'x');
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
  test_assert(child > 0);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)PTRACE_O_TRACESYSGOOD));
  wait_for_task_asleep_in_syscall(child, SYS_read, pipe_fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  ptrace_getregs(child, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
  regs.SYSCALL_RESULT = EMULATED_RESULT;
  ptrace_setregs(child, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == CHILD_STATUS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
