/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* We trace the main thread of a child with two threads and stop the child.
   Linux reports only the main thread's ptrace stops to us, so a WUNTRACED
   wait doesn't report the child's job-control stop. */

static int ready_fds[2];

static void* child_thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(ready_fds[1], &tid, sizeof(tid)));
  for (;;) {
    pause();
  }
  return NULL;
}

int main(void) {
  pthread_t thread;
  pid_t child;
  pid_t tid;
  int status;
  char state;

  test_assert(0 == pipe(ready_fds));
  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, child_thread_main, NULL));
    for (;;) {
      pause();
    }
  }
  test_assert(sizeof(tid) == read(ready_fds[0], &tid, sizeof(tid)));

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  /* Wait until the other thread has stopped too. */
  do {
    sched_yield();
    state = get_task_state(tid);
  } while (state != 'T' && state != 't');

  test_assert(0 == waitpid(child, &status, WUNTRACED | WNOHANG));

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
