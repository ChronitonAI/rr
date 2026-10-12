/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Our child C is in a group-stop for its ptracer T, our other child. A
   SIGCONT from outside the recording ends the stop of C's process, although
   C stays in its ptrace stop, so our WCONTINUED wait must report that C was
   continued. (Under rr, the SIGCONT doesn't come from a recorded process,
   so rr only notices it when it finds it pending.)
   We write C's pid followed by a newline to the FIFO argv[1], and read a
   byte from the FIFO argv[2] once the test script has sent the SIGCONT. */

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

int main(int argc, char** argv) {
  int request_fd;
  int ack_fd;
  int ready_pipe[2];
  int go_pipe[2];
  int to_ptracer[2];
  int from_ptracer[2];
  char line[32];
  char ch = 'x';
  int status;
  siginfo_t si;
  pid_t child;
  pid_t ptracer;

  test_assert(argc == 3);
  request_fd = open(argv[1], O_WRONLY);
  test_assert(request_fd >= 0);
  ack_fd = open(argv[2], O_RDONLY);
  test_assert(ack_fd >= 0);
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

  /* C is in a group-stop for T now. Have the SIGCONT sent. */
  test_assert(1 == read(from_ptracer[0], &ch, 1));
  sprintf(line, "%d\n", child);
  test_assert((ssize_t)strlen(line) == write(request_fd, line, strlen(line)));
  test_assert(1 == read(ack_fd, &ch, 1));

  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED));
  test_assert(si.si_signo == SIGCHLD && si.si_code == CLD_CONTINUED);
  test_assert(si.si_status == SIGCONT && si.si_pid == child);

  test_assert(1 == write(to_ptracer[1], &ch, 1));
  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  test_assert(1 == write(go_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(0 == close(request_fd));
  test_assert(0 == close(ack_fd));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
