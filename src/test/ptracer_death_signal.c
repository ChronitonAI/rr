/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A ptracer exits while its tracee is in a signal-delivery-stop. If the
   ptracer hasn't waited for the stop, the tracee gets the signal; if it has,
   the signal is gone. The ptracer is not the tracee's parent. */

#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif

enum {
  /* The ptracer sees the SIGUSR1 stop with WNOWAIT only. */
  NOT_WAITED,
  /* The ptracer waits for the SIGUSR1 stop. */
  WAITED,
  /* The ptracer attaches with PTRACE_ATTACH and exits right away. The
     attach's SIGSTOP stops the tracee. */
  ATTACH_SIGSTOP,
  /* The ptracer attaches with PTRACE_ATTACH and PTRACE_O_TRACECLONE, and
     exits at the tracee's PTRACE_EVENT_CLONE, without waiting for the new
     thread. The new thread starts with a SIGSTOP (not a SIGTRAP), which
     stops the process. */
  CLONE_SIGSTOP,
  NUM_MODES
};

static volatile int got_sigusr1;

static void handler(__attribute__((unused)) int sig) { got_sigusr1 = 1; }

static void* thread_func(__attribute__((unused)) void* p) { return NULL; }

static void run(int mode) {
  pid_t child;
  pid_t ptracer;
  int status;
  int ready_pipe[2];
  int go_pipe[2];
  int result_pipe[2];
  char ch = 'x';

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(result_pipe));

  if (0 == (child = fork())) {
    signal(SIGUSR1, handler);
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    if (mode == CLONE_SIGSTOP) {
      pthread_t thread;
      test_assert(0 == pthread_create(&thread, NULL, thread_func, NULL));
      test_assert(0 == pthread_join(thread, NULL));
    } else if (mode != ATTACH_SIGSTOP) {
      raise(SIGUSR1);
    }
    ch = got_sigusr1 ? 'Y' : 'N';
    test_assert(1 == write(result_pipe[1], &ch, 1));
    exit(77);
  }

  /* Make sure the prctl has happened before the ptracer attaches. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  if (0 == (ptracer = fork())) {
    siginfo_t si;
    if (mode == ATTACH_SIGSTOP) {
      test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
      exit(44);
    }
    if (mode == CLONE_SIGSTOP) {
      test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGSTOP << 8) | 0x7f));
      test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, NULL,
                              (void*)PTRACE_O_TRACECLONE));
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
      test_assert(1 == write(go_pipe[1], &ch, 1));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status ==
                  ((((PTRACE_EVENT_CLONE << 8) | SIGTRAP) << 8) | 0x7f));
      exit(44);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    if (mode == NOT_WAITED) {
      memset(&si, 0, sizeof(si));
      test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT));
      test_assert(si.si_code == CLD_TRAPPED && si.si_status == SIGUSR1);
    } else {
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    }
    /* Now just exit. */
    exit(44);
  }

  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  if (mode == ATTACH_SIGSTOP || mode == CLONE_SIGSTOP) {
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    test_assert(0 == kill(child, SIGCONT));
  }
  if (mode == ATTACH_SIGSTOP) {
    test_assert(1 == write(go_pipe[1], &ch, 1));
  }
  test_assert(1 == read(result_pipe[0], &ch, 1));
  test_assert(ch == (mode == NOT_WAITED ? 'Y' : 'N'));
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
