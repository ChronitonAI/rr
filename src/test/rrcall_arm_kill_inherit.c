/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* We arm RRCALL_KILL_AFTER_EXEC_STOP with RRCALL_ARM_KILL_INHERIT, so that
   the children we create share it, and then run two children, one after the
   other, that exec. rr kills the first one once it has handled its
   PTRACE_EVENT_EXEC stop. The kill happens only once, so the second child,
   and we ourselves, run normally. */

static pid_t exec_child(char* exe) {
  pid_t child = fork();
  if (!child) {
    char* argv[] = { exe, "exec'd", NULL };
    execve(exe, argv, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child > 0);
  return child;
}

int main(int argc, char** argv) {
  int armed;
  int status;
  pid_t child;

  if (argc > 1) {
    return 0;
  }

  armed = rr_arm_kill(RRCALL_KILL_AFTER_EXEC_STOP, 0, RRCALL_ARM_KILL_INHERIT);

  child = exec_child(argv[0]);
  test_assert(child == waitpid(child, &status, 0));
  if (armed) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    atomic_puts("first child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  child = exec_child(argv[0]);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
