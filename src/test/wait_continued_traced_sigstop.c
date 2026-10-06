/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Our child C is in a group-stop for its ptracer T, our other child. We
   send C a SIGCONT and right away a SIGSTOP. The SIGCONT ends the stop of
   C's process when it is generated, although C stays in its ptrace stop, so
   our WCONTINUED wait must report the continue, even though the SIGSTOP
   discards the pending SIGCONT. */

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

int main(void) {
  int ready_pipe[2];
  int go_pipe[2];
  int to_ptracer[2];
  int from_ptracer[2];
  char ch = 'x';
  int status;
  siginfo_t si;
  pid_t child;
  pid_t ptracer;

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(to_ptracer));
  test_assert(0 == pipe(from_ptracer));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(1 == read(go_pipe[0], &ch, 1));
    exit(77);
  }
  test_assert(child > 0);

  /* C has done its prctl. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));

  if (0 == (ptracer = fork())) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status ==
                ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
    test_assert(1 == write(from_ptracer[1], &ch, 1));
    /* Wait until our parent has waited for C's continue. Then exit, which
       detaches C. */
    test_assert(1 == read(to_ptracer[0], &ch, 1));
    exit(44);
  }
  test_assert(ptracer > 0);

  /* C is in a group-stop for T now. */
  test_assert(1 == read(from_ptracer[0], &ch, 1));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == kill(child, SIGSTOP));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED));
  test_assert(si.si_signo == SIGCHLD && si.si_code == CLD_CONTINUED);
  test_assert(si.si_status == SIGCONT && si.si_pid == child);

  test_assert(1 == write(to_ptracer[1], &ch, 1));
  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  /* Whatever the SIGSTOP did to C, a SIGCONT continues it. */
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(go_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
