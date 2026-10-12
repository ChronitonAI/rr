/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

/* A pid namespace's init traces its child, which stops for a signal, and
   exits without resuming it. The init can't finish exiting until the child
   has been killed and reaped, but Linux detaches the child before that, so
   the child doesn't stay stopped for its dead tracer. Meanwhile another
   process spins, without making syscalls, until we have waited for the
   init. Under rr, that process always being runnable must not keep the
   child from being killed, which the init's exit waits for. */

/* Set when the spinner can stop. */
static volatile int* done;

static int spin(void) {
  while (!*done) {
  }
  return 0;
}

static int do_init(void) {
  pid_t child;
  int status;

  child = fork();
  test_assert(child >= 0);
  if (!child) {
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    /* Once our tracer has exited, we get here, until the SIGKILL that the
       pid namespace's teardown sends us. (Exiting here could race with that
       SIGKILL.) */
    while (1) {
      pause();
    }
  }
  /* Don't wait for |child| by pid: rr doesn't translate the pid of an
     emulated ptracee in a pid namespace. */
  test_assert(0 < waitpid(-1, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  /* Exit while our child is stopped for us. */
  return 77;
}

int main(void) {
  pid_t spinner;
  pid_t init;
  int status;

  done = (volatile int*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(done != MAP_FAILED);
  spinner = fork();
  test_assert(spinner >= 0);
  if (!spinner) {
    return spin();
  }

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    atomic_puts("Insufficient permissions, skipping test");
  } else {
    /* This is the first child, therefore PID 1 in its PID namespace */
    init = fork();
    test_assert(init >= 0);
    if (!init) {
      return do_init();
    }
    test_assert(init == waitpid(init, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  *done = 1;
  test_assert(spinner == waitpid(spinner, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
