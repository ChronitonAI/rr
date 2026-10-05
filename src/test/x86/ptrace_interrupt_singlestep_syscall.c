/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_ERESTARTSYS 512

/* A tracer single-steps its child into a readv() that blocks, and interrupts
   it with PTRACE_INTERRUPT. Linux reports the PTRACE_EVENT_STOP after the
   readv() exits, and then the single-step's SIGTRAP. The syscall buffer
   doesn't handle readv(). Under rr, the race it tests (how far rr has got
   with the child's stop at the readv()'s exit when the tracer reads the
   child's registers and resumes it) only happens in some recordings, nearly
   all of them in chaos mode, which the .run file uses. */

static int fds[2];
static int go_fds[2];

static void wait_for_stop(pid_t child, int expected_status) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == expected_status);
}

/* The child is at the exit of the interrupted readv(). */
static void check_regs(pid_t child) {
  struct user_regs_struct regs;
  ptrace_getregs(child, &regs);
  test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
  test_assert((long)regs.SYSCALL_RESULT == -RR_ERESTARTSYS);
}

static void child_readv(void) {
  struct iovec iov;
  long ret;
  char ch;

  /* Wait until the tracer has seized us. */
  test_assert(1 == read(go_fds[0], &ch, 1));
  iov.iov_base = &ch;
  iov.iov_len = 1;
  /* The tracer single-steps from the int3 into the syscall. */
#if defined(__x86_64__)
  __asm__ __volatile__("int3\n\t"
                       "syscall\n\t"
                       : "=a"(ret)
                       : "a"(SYS_readv), "D"(fds[0]), "S"(&iov), "d"(1)
                       : "rcx", "r11", "memory");
#else
  __asm__ __volatile__("int3\n\t"
                       "int $0x80\n\t"
                       : "=a"(ret)
                       : "a"(SYS_readv), "b"(fds[0]), "c"(&iov), "d"(1)
                       : "memory");
#endif
  test_assert(ret == 1);
  test_assert(ch == 'x');
}

int main(void) {
  pid_t child;
  int status;

  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(go_fds));

  if (0 == (child = fork())) {
    child_readv();
    return 77;
  }
  test_assert(child > 0);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(go_fds[1], "g", 1));
  wait_for_stop(child, (SIGTRAP << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_stop(child, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);
  check_regs(child);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_stop(child, (SIGTRAP << 8) | 0x7f);
  check_regs(child);

  /* The readv() restarts. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
