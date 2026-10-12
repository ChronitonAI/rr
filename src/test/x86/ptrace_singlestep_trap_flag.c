/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

/* A tracer single-steps its tracee until a popf sets the trap flag (TF) in
   EFLAGS. Then it lets the tracee run, and the tracee traps after every
   instruction until it clears TF again. */

#define TF 0x100

int main(void) {
  struct user_regs_struct regs;
  pid_t pid;
  int status;
  int steps = 0;
  int traps = 0;

  if (0 == (pid = fork())) {
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
#ifdef __x86_64__
    __asm__ __volatile__("pushfq\n\t"
                         "orq $0x100,(%%rsp)\n\t"
                         "popfq\n\t"
                         "nop\n\t"
                         "nop\n\t"
                         "nop\n\t"
                         "pushfq\n\t"
                         "andq $~0x100,(%%rsp)\n\t"
                         "popfq\n\t" ::
                             : "memory", "cc");
#else
    __asm__ __volatile__("pushfl\n\t"
                         "orl $0x100,(%%esp)\n\t"
                         "popfl\n\t"
                         "nop\n\t"
                         "nop\n\t"
                         "nop\n\t"
                         "pushfl\n\t"
                         "andl $~0x100,(%%esp)\n\t"
                         "popfl\n\t" ::
                             : "memory", "cc");
#endif
    return 77;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  do {
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptrace_getregs(pid, &regs);
    test_assert(++steps < 100000);
  } while (!(regs.eflags & TF));
  while (1) {
    test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    if (WIFEXITED(status)) {
      break;
    }
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ++traps;
  }
  atomic_printf("steps: %d, traps: %d\n", steps, traps);
  test_assert(WEXITSTATUS(status) == 77);
  test_assert(traps >= 3);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
