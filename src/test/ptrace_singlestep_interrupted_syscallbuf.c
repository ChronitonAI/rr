/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer stops its tracee with a signal while the tracee is blocked in a
   read(), suppresses the signal, resumes the tracee to the entry of the
   restarted read() with PTRACE_SYSCALL, and then single-steps it until it
   raises SIGUSR1. When the read() goes through rr's syscall buffer, the
   tracer single-steps the syscall buffer's code after the read(). */

static int fds[2];

int main(void) {
  pid_t pid;
  int status;
  int steps = 0;
  char ch;

  test_assert(0 == pipe(fds));
  /* rr doesn't patch syscalls in a task that has a ptracer. Do a read() here,
     so that the child's read() can use the syscall buffer. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(1 == read(fds[0], &ch, 1));

  if (0 == (pid = fork())) {
    char buf[4];
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    test_assert(4 == read(fds[0], buf, 4));
    test_assert(0 == memcmp(buf, "abcd", 4));
    raise(SIGUSR1);
    return 77;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));

  wait_for_task_asleep_in_syscall(pid, SYS_read, fds[0]);
  test_assert(0 == kill(pid, SIGUSR2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR2);

  /* Suppress SIGUSR2. The read() restarts and finds the data. */
  test_assert(4 == write(fds[1], "abcd", 4));
  test_assert(0 == ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  while (1) {
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status));
    if (WSTOPSIG(status) == SIGUSR1) {
      break;
    }
    test_assert(WSTOPSIG(status) == SIGTRAP);
    test_assert(++steps < 100000);
  }
  atomic_printf("%d steps\n", steps);

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
