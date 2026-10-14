/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "../ptrace_util.h"

/* A ptracer resumes its tracee and exits. Linux turns off syscall tracing
   and, since 5.3, syscall emulation for the tracee (older kernels left
   PTRACE_SYSEMU in effect; rr follows current kernels), but leaves
   single-stepping on, so after a PTRACE_SINGLESTEP the tracee gets a SIGTRAP
   after its next instruction. On x86, entering a signal handler turns
   single-stepping off, so a single-step that delivers a signal to a handler
   ends there. The ptracer is not the tracee's parent. */

enum {
  /* The ptracer resumes the tracee with PTRACE_SINGLESTEP and SIGUSR1,
     which has a handler, and exits. */
  STEP_SIGNAL,
  /* As STEP_SIGNAL, but the ptracer waits for the stop that ends the step
     before it exits. */
  STEP_SIGNAL_WAITED,
  /* The ptracer resumes the tracee with PTRACE_SINGLESTEP and exits. The
     tracee's SIGTRAP handler runs once. */
  STEP,
  /* As STEP, but the ptracer waits for the stop that ends the step before
     it exits. */
  STEP_WAITED,
  /* The ptracer resumes the tracee with PTRACE_SYSEMU and exits. The
     tracee's next syscall runs. */
  SYSEMU,
  NUM_MODES
};

static volatile int sigusr1_count;
static volatile int sigtrap_count;

static void handle_sigusr1(__attribute__((unused)) int sig) {
  ++sigusr1_count;
}

static void handle_sigtrap(__attribute__((unused)) int sig) {
  ++sigtrap_count;
}

static void run(int mode, volatile int* ptracer_gone) {
  pid_t child;
  pid_t ptracer;
  int status;
  int ready_pipe[2];
  int go_pipe[2];
  int result_pipe[2];
  char ch = 'x';
  char result[3];

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(result_pipe));
  *ptracer_gone = 0;

  if (0 == (child = fork())) {
    pid_t pid = getpid();
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGTRAP, handle_sigtrap);
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    test_assert(0 == kill(pid, SIGUSR1));
    /* Make no syscalls until the ptracer has exited. */
    while (!*ptracer_gone) {
    }
    result[0] = syscall(SYS_getpid) == pid ? 'P' : 'N';
    result[1] = '0' + sigusr1_count;
    result[2] = '0' + sigtrap_count;
    test_assert(3 == write(result_pipe[1], result, 3));
    exit(77);
  }

  /* Make sure the prctl has happened before the ptracer attaches. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  if (0 == (ptracer = fork())) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    switch (mode) {
      case STEP_SIGNAL:
      case STEP_SIGNAL_WAITED:
        test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL,
                                (void*)SIGUSR1));
        break;
      case STEP:
      case STEP_WAITED:
        test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, NULL));
        break;
      case SYSEMU:
        test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
        break;
    }
    if (mode == STEP_SIGNAL_WAITED || mode == STEP_WAITED) {
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGTRAP << 8) | 0x7f));
    }
    /* Now just exit. */
    exit(44);
  }

  test_assert(ptracer == waitpid(ptracer, &status, 0));
  *ptracer_gone = 1;
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  test_assert(child == waitpid(child, &status, 0));
  atomic_printf("mode %d: tracee status %#x\n", mode, status);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  test_assert(3 == read(result_pipe[0], result, 3));
  /* The syscall ran, and each handler ran as often as expected. */
  test_assert(result[0] == 'P');
  test_assert(result[1] ==
              (mode == STEP_SIGNAL || mode == STEP_SIGNAL_WAITED ? '1' : '0'));
  test_assert(result[2] == (mode == STEP || mode == STEP_WAITED ? '1' : '0'));

  test_assert(0 == close(ready_pipe[0]));
  test_assert(0 == close(ready_pipe[1]));
  test_assert(0 == close(go_pipe[0]));
  test_assert(0 == close(go_pipe[1]));
  test_assert(0 == close(result_pipe[0]));
  test_assert(0 == close(result_pipe[1]));
}

int main(void) {
  int mode;
  volatile int* ptracer_gone = (volatile int*)mmap(
      NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(ptracer_gone != MAP_FAILED);
  for (mode = 0; mode < NUM_MODES; ++mode) {
    run(mode, ptracer_gone);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
