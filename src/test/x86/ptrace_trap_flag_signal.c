/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

/* A tracer sets the trap flag (TF) in its tracee's EFLAGS and resumes it with
   a signal that has a handler. The handler sees TF set in its context, and
   after it returns, the tracee traps after every instruction until the
   tracer clears TF again. */

#define TF 0x100

static volatile int handler_saw_tf;

static void handler(__attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si, void* context) {
  ucontext_t* uc = context;
  handler_saw_tf = !!(uc->uc_mcontext.gregs[REG_EFL] & TF);
}

int main(void) {
  struct user_regs_struct regs;
  pid_t pid;
  int status;
  int traps = 0;

  if (0 == (pid = fork())) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    /* Not raise(): glibc's raise() blocks all signals around the tgkill,
       which would delay SIGUSR1. */
    syscall(SYS_tgkill, getpid(), sys_gettid(), SIGSTOP);
    return handler_saw_tf ? 77 : 78;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  ptrace_getregs(pid, &regs);
  regs.eflags |= TF;
  ptrace_setregs(pid, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, (void*)SIGUSR1));
  while (1) {
    test_assert(pid == waitpid(pid, &status, 0));
    if (WIFEXITED(status)) {
      break;
    }
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    if (++traps == 3) {
      ptrace_getregs(pid, &regs);
      regs.eflags &= ~TF;
      ptrace_setregs(pid, &regs);
    }
    test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  }
  test_assert(WEXITSTATUS(status) == 77);
  test_assert(traps == 3);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
