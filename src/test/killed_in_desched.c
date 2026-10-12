/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Recorded by killed_in_desched.run, rr SIGKILLs the child while it handles
   the desched signal of the child's read(), which blocks in the syscall
   buffer: right after the child reports a stop there, before rr looks at
   the stop. */

int main(void) {
  int fds[2];
  pid_t child;
  int status;
  char ch;

  test_assert(0 == pipe(fds));
  /* rr patches syscalls in a task on their first use, so do a read() here,
     to make the child's read() go through the syscall buffer. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(1 == read(fds[0], &ch, 1));

  if (0 == (child = fork())) {
    /* Nobody writes to the pipe, so this blocks. */
    read(fds[0], &ch, 1);
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  atomic_puts("child was killed");

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
