/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Child B stops its sibling A and exits, while their parent waits for any
   child with WUNTRACED. The parent's waits must report both A's stop and B's
   exit, in either order. The race it tests (A's stop and B's exit during
   the same wait) only happens in some recordings, so we try this a number
   of times. */

static void run(void) {
  pid_t a;
  pid_t b;
  pid_t pid;
  int status;
  int saw_a_stop = 0;
  int saw_a_death = 0;
  int saw_b_exit = 0;

  if (0 == (a = fork())) {
    for (;;) {
      pause();
    }
  }
  test_assert(a > 0);
  if (0 == (b = fork())) {
    test_assert(a > 1);
    test_assert(0 == kill(a, SIGSTOP));
    _exit(0);
  }
  test_assert(b > 0);

  for (;;) {
    pid = waitpid(-1, &status, WUNTRACED);
    if (pid < 0) {
      test_assert(errno == ECHILD);
      break;
    }
    if (pid == a && WIFSTOPPED(status)) {
      test_assert(!saw_a_stop && WSTOPSIG(status) == SIGSTOP);
      saw_a_stop = 1;
      test_assert(0 == kill(a, SIGKILL));
    } else if (pid == a) {
      test_assert(saw_a_stop && WIFSIGNALED(status) &&
                  WTERMSIG(status) == SIGKILL);
      saw_a_death = 1;
    } else {
      test_assert(pid == b);
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      saw_b_exit = 1;
    }
  }
  test_assert(saw_a_death);
  test_assert(saw_b_exit);
}

int main(void) {
  int i;
  for (i = 0; i < 30; ++i) {
    run();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
