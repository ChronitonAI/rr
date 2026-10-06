/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Our child C is continued, and another process T traces it. Our
   WCONTINUED waits must still report that C was continued, with the right
   siginfo. */

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

enum {
  /* C is stopped and continued. Then T seizes it, stops it with
     PTRACE_INTERRUPT and detaches, before we wait for the continue. */
  INTERRUPTED,
  /* T has seized C, so C's stop is a ptrace stop, and we continue C while
     T keeps it there. */
  TRACED_STOP,
  NUM_MODES
};

static void run(int mode) {
  pid_t child;
  pid_t ptracer;
  int status;
  siginfo_t si;
  int ready_pipe[2];
  int go_pipe[2];
  int to_ptracer[2];
  int from_ptracer[2];
  char ch = 'x';
  /* In INTERRUPTED mode, C sets shared[0] when it spins, and stops spinning
     when we set shared[1]. */
  volatile int* shared =
      (volatile int*)mmap(NULL, 2 * sizeof(int), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  test_assert(shared != MAP_FAILED);
  shared[0] = shared[1] = 0;
  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(to_ptracer));
  test_assert(0 == pipe(from_ptracer));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    if (mode == INTERRUPTED) {
      raise(SIGSTOP);
      /* Spin rather than block in a syscall: rr may report the
         PTRACE_INTERRUPT of a task at a syscall boundary as a syscall
         stop. */
      shared[0] = 1;
      while (!shared[1]) {
      }
    } else {
      test_assert(1 == write(ready_pipe[1], &ch, 1));
      test_assert(1 == read(go_pipe[0], &ch, 1));
      raise(SIGSTOP);
      test_assert(1 == read(go_pipe[0], &ch, 1));
    }
    exit(77);
  }

  if (mode == INTERRUPTED) {
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    test_assert(0 == kill(child, SIGCONT));
    /* Wait until C has resumed. */
    while (!shared[0]) {
    }
  } else {
    /* C has done its prctl. */
    test_assert(1 == read(ready_pipe[0], &ch, 1));
  }

  if (0 == (ptracer = fork())) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    if (mode == INTERRUPTED) {
      test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
    } else {
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
    test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
    exit(44);
  }

  if (mode == TRACED_STOP) {
    /* C is in a group-stop for T now. */
    test_assert(1 == read(from_ptracer[0], &ch, 1));
    test_assert(0 == kill(child, SIGCONT));
  } else {
    test_assert(ptracer == waitpid(ptracer, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  }
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED));
  test_assert(si.si_signo == SIGCHLD && si.si_code == CLD_CONTINUED);
  test_assert(si.si_status == SIGCONT && si.si_pid == child);
  if (mode == TRACED_STOP) {
    test_assert(1 == write(to_ptracer[1], &ch, 1));
    test_assert(ptracer == waitpid(ptracer, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  }

  if (mode == INTERRUPTED) {
    shared[1] = 1;
  } else {
    test_assert(1 == write(go_pipe[1], &ch, 1));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  close(ready_pipe[0]);
  close(ready_pipe[1]);
  close(go_pipe[0]);
  close(go_pipe[1]);
  close(to_ptracer[0]);
  close(to_ptracer[1]);
  close(from_ptracer[0]);
  close(from_ptracer[1]);
  munmap((void*)shared, 2 * sizeof(int));
}

int main(void) {
  int mode;
  for (mode = 0; mode < NUM_MODES; ++mode) {
    run(mode);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
