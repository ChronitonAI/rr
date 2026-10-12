/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A tracer delivers a signal to its tracee with PTRACE_SINGLESTEP. The step
   must end at the first instruction of the signal handler, with the signal
   frame set up. */

static volatile int handled;

static void handler(__attribute__((unused)) int sig) { handled = 1; }

/* The handler's first argument, as the tracer sees it at the handler's first
   instruction. */
static long handler_arg(pid_t pid, struct user_regs_struct* regs) {
#if defined(__i386__)
  long v;
  errno = 0;
  /* The return address is at the top of the stack, the argument above. */
  v = ptrace(PTRACE_PEEKDATA, pid, (void*)(regs->esp + 4), NULL);
  test_assert(errno == 0);
  return v;
#else
  (void)pid;
  return regs->SYSCALL_ARG1;
#endif
}

int main(void) {
  struct user_regs_struct regs;
  siginfo_t si;
  pid_t pid;
  int status;

  if (0 == (pid = fork())) {
    test_assert(SIG_ERR != signal(SIGUSR2, handler));
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGUSR2);
    test_assert(handled);
    return 77;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR2);

  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, (void*)SIGUSR2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, pid, NULL, &si));
  test_assert(si.si_code == SIGTRAP);
  /* The kernel reports the tracee as the sender. */
  test_assert(si.si_pid == pid);
  ptrace_getregs(pid, &regs);
  test_assert((uintptr_t)regs.IP == (uintptr_t)handler);
  test_assert(handler_arg(pid, &regs) == SIGUSR2);

  /* The next step executes the handler's first instruction. */
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  ptrace_getregs(pid, &regs);
  test_assert((uintptr_t)regs.IP != (uintptr_t)handler);

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
