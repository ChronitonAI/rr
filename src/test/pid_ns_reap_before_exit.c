/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

/* A pid namespace init that exits while it still has a child can't finish
   exiting (zap_pid_ns_processes) until its child has been killed and reaped.
   Check that rr doesn't consider such a task reaped before it has actually
   become a zombie: if it did, rr would forget it while the kernel zombie
   remains, and then wait forever for the exit of the init of the enclosing
   pid namespace, which in turn waits for that zombie to be reaped.

   Priorities steer rr's scheduler so that it considers the exiting inner
   init first, then lets the outer init exit, and only then handles the
   inner init's child. */

static int inner_init_exiting_pipe[2];
static int child_ready_pipe[2];

static int do_outer_init(void) {
  pid_t inner_init;
  char ch;

  setpriority(PRIO_PROCESS, 0, 10);
  test_assert(0 == unshare(CLONE_NEWPID));
  inner_init = fork();
  test_assert(inner_init >= 0);
  if (!inner_init) {
    pid_t child = fork();
    test_assert(child >= 0);
    if (!child) {
      setpriority(PRIO_PROCESS, 0, 19);
      test_assert(1 == write(child_ready_pipe[1], "x", 1));
      pause();
      return 0;
    }
    setpriority(PRIO_PROCESS, 0, 0);
    test_assert(1 == read(child_ready_pipe[0], &ch, 1));
    test_assert(1 == write(inner_init_exiting_pipe[1], "y", 1));
    /* Exit while our child is still alive */
    return 0;
  }
  test_assert(1 == read(inner_init_exiting_pipe[0], &ch, 1));
  /* Exit while the inner init is still exiting */
  return 77;
}

int main(void) {
  pid_t pid;
  int status;

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == pipe(inner_init_exiting_pipe));
  test_assert(0 == pipe(child_ready_pipe));

  /* This is the first child, therefore PID 1 in its PID namespace */
  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    return do_outer_init();
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
