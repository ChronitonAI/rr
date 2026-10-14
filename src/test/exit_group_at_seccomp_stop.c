/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child arms RRCALL_KILL_EXIT_GROUP_FROM_SECCOMP_STOP and calls
   exit_group(). rr lets the exit_group() go ahead from the syscall's
   PTRACE_EVENT_SECCOMP stop, waits until the child has reached its
   PTRACE_EVENT_EXIT stop, and only then handles the seccomp stop. */

int main(void) {
  pid_t child;
  int status;

  child = fork();
  if (!child) {
    rr_arm_kill(RRCALL_KILL_EXIT_GROUP_FROM_SECCOMP_STOP, 0, 0);
    syscall(SYS_exit_group, 77);
    test_assert(0 && "Still alive");
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
