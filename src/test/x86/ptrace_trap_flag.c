/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

/* A tracer sets the trap flag (TF) in its tracee's EFLAGS to single-step it,
   and clears it again after three SIGTRAPs. */

#define TF 0x100

int main(void) {
  struct user_regs_struct regs;
  pid_t pid;
  int status;
  int traps = 0;

  if (0 == (pid = fork())) {
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    raise(SIGUSR1);
    return 77;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  ptrace_getregs(pid, &regs);
  regs.eflags |= TF;
  ptrace_setregs(pid, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  while (1) {
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status));
    if (WSTOPSIG(status) == SIGUSR1) {
      break;
    }
    test_assert(WSTOPSIG(status) == SIGTRAP);
    if (++traps == 3) {
      ptrace_getregs(pid, &regs);
      regs.eflags &= ~TF;
      ptrace_setregs(pid, &regs);
    }
    test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  }
  test_assert(traps == 3);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
