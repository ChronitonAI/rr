/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* rr SIGKILLs the child when its execve of argv[1] has succeeded, just before
   rr sets up the new address space, and doesn't wait for it to reach its
   PTRACE_EVENT_EXIT stop. The child is SCHED_IDLE, so that the SIGKILL
   doesn't make it preempt rr (which runs on the same CPU, unless recording
   with -u) and get to that stop before rr reads its memory.
   exec_killed_before_post_exec.run passes a program for the other
   architecture: rr reads the new vdso only at the first exec of each
   architecture. */

int main(int argc, char** argv) {
  pid_t child;
  int status;
  int armed;

  test_assert(argc == 2);

  armed = rr_arm_kill(RRCALL_KILL_BEFORE_POST_EXEC, 0,
                      RRCALL_ARM_KILL_INHERIT);
  child = fork();
  if (!child) {
    char* args[] = { argv[1], NULL };
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    test_assert(0 == sched_setscheduler(0, SCHED_IDLE, &param));
    execve(argv[1], args, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child == waitpid(child, &status, 0));
  if (armed) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
