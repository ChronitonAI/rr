/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Fork through syscall(). Once earlier calls have let rr patch it, the
   fork happens at the syscall instruction of its extended jump patch, after
   rr's syscall hook has returned. */

static long do_fork(void) {
#ifdef SYS_fork
  return syscall(SYS_fork);
#else
  return syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

int main(void) {
  pid_t pid = getpid();
  long child;
  int status;
  int i;

  for (i = 0; i < 10; ++i) {
    test_assert(pid == syscall(SYS_getpid));
  }

  child = do_fork();
  test_assert(child >= 0);
  if (!child) {
    pid = getpid();
    for (i = 0; i < 10; ++i) {
      test_assert(pid == syscall(SYS_getpid));
    }
    _exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
