/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Over and over, a new ptracer seizes the child, which is blocked in read(),
   interrupts it with PTRACE_INTERRUPT, waits for the stop and exits. The
   child must then finish its read() normally. */

#define NUM_ITERATIONS 200

int main(void) {
  int fds[2];
  int ready_fds[2];
  pid_t child;
  pid_t ptracer;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(ready_fds));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_fds[1], "r", 1));
    test_assert(1 == read(fds[0], &ch, 1));
    test_assert(ch == 'x');
    return 77;
  }

  test_assert(1 == read(ready_fds[0], &ch, 1));
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    if (0 == (ptracer = fork())) {
      test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
      test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
      test_assert(child == waitpid(child, &status, 0));
      /* Linux reports a PTRACE_EVENT_STOP with SIGTRAP here, but rr doesn't
         always emulate that exactly. */
      test_assert(WIFSTOPPED(status));
      return 44;
    }
    test_assert(ptracer == waitpid(ptracer, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  }

  test_assert(1 == write(fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
