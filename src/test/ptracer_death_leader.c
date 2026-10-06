/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The ptracer is a thread-group leader. It exits while its tracee is in a
   PTRACE_EVENT_CLONE stop, but another thread of its process keeps
   running. The tracee should resume when the ptracer exits. */

static int status_pipe[2];

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

static void* wait_for_tracee(__attribute__((unused)) void* p) {
  char ch = 0;
  test_assert(1 == read(status_pipe[0], &ch, 1));
  test_assert(ch == 'K');
  atomic_puts("EXIT-SUCCESS");
  exit(0);
  return NULL;
}

int main(void) {
  pid_t child;
  int status;
  int ready_pipe[2];
  char ready = 'R';
  pthread_t thread;

  test_assert(0 == pipe(status_pipe));
  test_assert(0 == pipe(ready_pipe));

  if (0 == (child = fork())) {
    char ch = 0;
    char ok = 'K';

    test_assert(1 == read(ready_pipe[0], &ch, 1));
    test_assert(ch == 'R');
    test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
    test_assert(0 == pthread_join(thread, NULL));
    test_assert(1 == write(status_pipe[1], &ok, 1));
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACECLONE));
  test_assert(1 == write(ready_pipe[1], &ready, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_CLONE << 16) | (SIGTRAP << 8) | 0x7f));

  test_assert(0 == pthread_create(&thread, NULL, wait_for_tracee, NULL));
  /* Exit this thread only. The child should resume. */
  syscall(SYS_exit, 0);
  test_assert(0);
  return 0;
}
