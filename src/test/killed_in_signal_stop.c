/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Recorded by killed_in_signal_stop.run, rr SIGKILLs the child in its
   signal-stop for SIGUSR1, and lets it reach its PTRACE_EVENT_EXIT stop,
   before rr reads the siginfo of the signal-stop. */

int main(void) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    raise(SIGUSR1);
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status));
  if (WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    test_assert(WTERMSIG(status) == SIGUSR1);
    atomic_puts("child got SIGUSR1");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
