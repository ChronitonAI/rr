/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child is at its PTRACE_EVENT_EXEC stop, and the stop ends without the
   ptracer resuming it: the ptracer detaches, a ptracer that isn't the
   parent exits, or the ptracer SIGKILLs the child. In the first two cases,
   the execve returns and the new image runs. Finally, a ptracer that is
   the child's parent only looks at the stop (with WNOWAIT), SIGKILLs the
   child, waits until the child has exited, and exits. */

enum how { DETACH, TRACER_EXIT, KILL };

static void run_child(char* exe, enum how how) {
  int go_fds[2];
  int ready_fds[2];
  pid_t child;
  pid_t tracer;
  int status;
  char ch;

  test_assert(0 == pipe(go_fds));
  test_assert(0 == pipe(ready_fds));
  child = fork();
  if (!child) {
    char* argv[] = { exe, "exec'd", NULL };
    test_assert(0 == prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0));
    test_assert(1 == write(ready_fds[1], "r", 1));
    test_assert(1 == read(go_fds[0], &ch, 1));
    execve(exe, argv, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child > 0);
  test_assert(1 == read(ready_fds[0], &ch, 1));

  tracer = how == TRACER_EXIT ? fork() : getpid();
  test_assert(tracer >= 0);
  if (tracer == 0 || how != TRACER_EXIT) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                            (void*)PTRACE_O_TRACEEXEC));
    test_assert(1 == write(go_fds[1], "g", 1));
    test_assert(child == waitpid(child, &status, __WALL));
    test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
    switch (how) {
      case DETACH:
        test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
        break;
      case TRACER_EXIT:
        _exit(0);
      case KILL:
        test_assert(0 == kill(child, SIGKILL));
        test_assert(child == waitpid(child, &status, 0));
        test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        break;
    }
  }
  if (how == TRACER_EXIT) {
    test_assert(tracer == waitpid(tracer, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  if (how != KILL) {
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }
  close(go_fds[0]);
  close(go_fds[1]);
  close(ready_fds[0]);
  close(ready_fds[1]);
}

static void run_parent_tracer(char* exe) {
  int go_fds[2];
  int ready_fds[2];
  pid_t tracer;
  pid_t child;
  int status;
  siginfo_t si;
  char ch;
  int pidfd;
  struct pollfd pfd;

  tracer = fork();
  if (!tracer) {
    test_assert(0 == pipe(go_fds));
    test_assert(0 == pipe(ready_fds));
    child = fork();
    if (!child) {
      char* argv[] = { exe, "exec'd", NULL };
      test_assert(1 == write(ready_fds[1], "r", 1));
      test_assert(1 == read(go_fds[0], &ch, 1));
      execve(exe, argv, environ);
      test_assert(0 && "Failed exec!");
    }
    test_assert(child > 0);
    test_assert(1 == read(ready_fds[0], &ch, 1));
    pidfd = syscall(RR_pidfd_open, child, 0);
    if (pidfd < 0) {
      test_assert(errno == ENOSYS);
      atomic_puts("pidfd_open not supported, skipping the last case");
      test_assert(0 == kill(child, SIGKILL));
      _exit(0);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                            (void*)PTRACE_O_TRACEEXEC));
    test_assert(1 == write(go_fds[1], "g", 1));
    /* Leave the stop to be collected. */
    test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT | __WALL));
    test_assert(si.si_pid == child && si.si_code == CLD_TRAPPED);
    test_assert(0 == kill(child, SIGKILL));
    /* The pidfd becomes readable once the child has exited, which under rr
       is after rr has recorded its exit. */
    pfd.fd = pidfd;
    pfd.events = POLLIN;
    test_assert(1 == poll(&pfd, 1, -1));
    _exit(0);
  }
  test_assert(tracer > 0);
  test_assert(tracer == waitpid(tracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char** argv) {
  if (argc == 2) {
    /* The new image. */
    return 77;
  }
  run_child(argv[0], DETACH);
  run_child(argv[0], TRACER_EXIT);
  run_child(argv[0], KILL);
  run_parent_tracer(argv[0]);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
