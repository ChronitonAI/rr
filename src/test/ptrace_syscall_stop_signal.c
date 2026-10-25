/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer resumes its tracee from a syscall-entry-stop or a
   syscall-exit-stop with a signal, using PTRACE_CONT, PTRACE_SYSCALL or
   PTRACE_DETACH. The kernel sends the signal, and the tracee takes it once
   the syscall is done: if it's still traced, that's a signal-delivery-stop
   after the syscall's exit (and after the syscall-exit-stop, for
   PTRACE_SYSCALL at the syscall-entry-stop). */

static volatile int sigusr1_count;

static void handle_sigusr1(__attribute__((unused)) int sig) {
  ++sigusr1_count;
}

static void wait_for_stop(pid_t child, int sig) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == sig);
}

static void run_round(int at_exit, int request) {
  int status;
  pid_t child = fork();
  if (!child) {
    signal(SIGUSR1, handle_sigusr1);
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    kill(getpid(), SIGSTOP);
    syscall(SYS_getppid);
    exit(sigusr1_count);
  }

  wait_for_stop(child, SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  /* The syscall-entry-stop for getppid. */
  wait_for_stop(child, SIGTRAP);
  if (at_exit) {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
    /* The syscall-exit-stop for getppid. */
    wait_for_stop(child, SIGTRAP);
  }
  test_assert(0 == ptrace(request, child, NULL, (void*)SIGUSR1));
  if (request == PTRACE_SYSCALL && !at_exit) {
    wait_for_stop(child, SIGTRAP);
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  }
  if (request != PTRACE_DETACH) {
    wait_for_stop(child, SIGUSR1);
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGUSR1));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
}

int main(void) {
  int at_exit;
  for (at_exit = 0; at_exit < 2; ++at_exit) {
    run_round(at_exit, PTRACE_CONT);
    run_round(at_exit, PTRACE_SYSCALL);
    run_round(at_exit, PTRACE_DETACH);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
