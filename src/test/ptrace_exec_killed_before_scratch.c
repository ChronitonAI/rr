/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Like exec_killed_before_scratch, but the parent ptraces the child with
   PTRACE_O_TRACEEXEC, so rr records the exec at the child's exec stop. */

int main(int argc, char** argv) {
  pid_t child;
  int status;
  sigset_t set;
  int go_fds[2];
  char ch;

  if (argc > 1) {
    return 0;
  }

  /* See exec_killed_before_scratch. */
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
  test_assert(0 == pipe(go_fds));

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "child", NULL };
    test_assert(1 == read(go_fds[0], &ch, 1));
    rr_arm_kill(RRCALL_KILL_BEFORE_EXEC_SCRATCH, 0, 0);
    execve(argv[0], args, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)PTRACE_O_TRACEEXEC));
  test_assert(1 == write(go_fds[1], "g", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status)) {
    test_assert(WTERMSIG(status) == SIGKILL);
    atomic_puts("child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    atomic_puts("child exited");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
