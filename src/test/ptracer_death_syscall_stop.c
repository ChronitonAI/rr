/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* A SIGSTOP stops the tracee's process, and the ptracer resumes the tracee
   with PTRACE_SYSCALL. At the tracee's next syscall-entry stop, for a
   write(), the ptracer exits, or detaches. Linux runs the syscall and then
   stops the tracee until a SIGCONT. The ptracer is not the tracee's
   parent. */

enum { EXIT, DETACH, NUM_MODES };

static void run(int mode) {
  pid_t child;
  pid_t ptracer;
  int status;
  int ready_pipe[2];
  int go_pipe[2];
  int ran_pipe[2];
  int cont_pipe[2];
  char ch = 'x';

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(ran_pipe));
  test_assert(0 == pipe(cont_pipe));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    /* Not raise(), which may make another syscall after the kill. */
    test_assert(0 == kill(getpid(), SIGSTOP));
    /* The ptracer leaves us at the entry of this write(). */
    test_assert(1 == write(ran_pipe[1], &ch, 1));
    test_assert(1 == read(cont_pipe[0], &ch, 1));
    exit(77);
  }

  /* Make sure the prctl has happened before the ptracer attaches. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  if (0 == (ptracer = fork())) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    /* Let the SIGSTOP put the child into a group-stop. */
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
    /* Its process stays stopped. */
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGTRAP << 8) | 0x7f));
    if (mode == DETACH) {
      test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
    }
    exit(44);
  }

  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  /* The write runs, and then the child stops until this SIGCONT (or the
     SIGCONT comes first). */
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == read(ran_pipe[0], &ch, 1));
  test_assert(1 == write(cont_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  int mode;
  for (mode = 0; mode < NUM_MODES; ++mode) {
    run(mode);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
