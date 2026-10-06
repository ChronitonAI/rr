/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Recorded by fork_child_of_killed_parent.run, rr SIGKILLs our child when it
   stops for PTRACE_EVENT_FORK (or VFORK), before rr learns the new pid. The
   grandchild survives and has to run. */

static int fds[2];

static void child(int use_vfork) {
  pid_t grandchild = use_vfork ? vfork() : fork();
  if (!grandchild) {
    char ch = 'g';
    test_assert(write(fds[1], &ch, 1) == 1);
    _exit(0);
  }
  test_assert(grandchild > 0);
  test_assert(grandchild == waitpid(grandchild, NULL, 0));
  _exit(0);
}

static int run(int use_vfork) {
  int status;
  pid_t pid = fork();
  if (!pid) {
    child(use_vfork);
  }
  test_assert(pid == waitpid(pid, &status, 0));
  int killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
  if (!killed) {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  /* Whether or not our child was killed, the grandchild must run. */
  struct pollfd pfd = { fds[0], POLLIN, 0 };
  test_assert(1 == poll(&pfd, 1, 10000));
  char ch;
  test_assert(read(fds[0], &ch, 1) == 1 && ch == 'g');
  return killed;
}

int main(void) {
  test_assert(0 == pipe(fds));
  if (run(0)) {
    atomic_puts("fork parent was killed");
  }
  if (run(1)) {
    atomic_puts("vfork parent was killed");
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
