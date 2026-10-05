/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* The child sleeps in clock_nanosleep(). Each PTRACE_INTERRUPT interrupts the
   sleep, and when the child resumes, the kernel restarts it with
   restart_syscall(). We interrupt the child again and again, often while it
   is only just restarting the sleep. Each time, the next stop must be a
   PTRACE_EVENT_STOP. The race it tests only happens in some recordings. */

#define ITERATIONS 200

int main(void) {
  pid_t child;
  int status;
  int i;

  if (0 == (child = fork())) {
    sleep(10000);
    return 77;
  }
  test_assert(child > 0);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));

  for (i = 0; i < ITERATIONS; ++i) {
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
    /* Under rr, this usually makes rr resume the child before we interrupt
       it. */
    sched_yield();
    test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  }

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
