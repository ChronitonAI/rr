/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* For each kind of task that clone(), fork() and vfork() create, we have rr
   SIGKILL a child at the entry of the syscall that would create the task,
   while rr prepares that syscall (see RRCALL_KILL_IN_CLONE_PREPARATION). */

enum { NEW_THREAD, NEW_FORK_CHILD, NEW_VFORK_CHILD, NUM_CASES };

static void* thread_fn(__attribute__((unused)) void* p) { return NULL; }

static void create_task(int which) {
  pthread_t thread;
  pid_t child;
  int status;

  switch (which) {
    case NEW_THREAD:
      test_assert(0 == pthread_create(&thread, NULL, thread_fn, NULL));
      test_assert(0 == pthread_join(thread, NULL));
      return;
    case NEW_FORK_CHILD:
      child = fork();
      break;
    case NEW_VFORK_CHILD:
      child = vfork();
      break;
    default:
      test_assert(0);
      return;
  }
  if (!child) {
    _exit(0);
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
  /* This arms nothing; it tells us whether we're running under rr. */
  int under_rr = rr_arm_kill(RRCALL_KILL_NONE, 0, 0);
  int which;

  for (which = 0; which < NUM_CASES; ++which) {
    int status;
    pid_t child = fork();
    if (!child) {
      /* Arm the kill after the fork(), so that the fork() doesn't trigger
         it. */
      rr_arm_kill(RRCALL_KILL_IN_CLONE_PREPARATION, 0, 0);
      create_task(which);
      _exit(0);
    }
    test_assert(child > 0);
    test_assert(child == waitpid(child, &status, 0));
    if (under_rr) {
      test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    } else {
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
