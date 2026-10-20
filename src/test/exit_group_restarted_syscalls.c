/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A process's threads are blocked in syscalls when they get a signal that
   they ignore. Under rr, which sees the signal, it interrupts the syscalls,
   which are then restarted. One thread's syscall returns, and it exits the
   process. The other thread may then be at a PTRACE_EVENT_SECCOMP stop of
   its restarted syscall that rr has collected but not processed yet when
   the exit_group kills it, and rr must then handle its exit instead. That
   race only happens in some recordings; exit_group_pending_seccomp_stop
   sets it up every time. */

#define ROUNDS 30

static int fds[2];
static int tid_fds[2];

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(tid_fds[1], &tid, sizeof(tid)));
  test_assert(1 == read(fds[0], &ch, 1));
  exit(77);
  return NULL;
}

int main(void) {
  pthread_t thread;
  pid_t child;
  pid_t tid;
  int status;
  int i;

  for (i = 0; i < ROUNDS; ++i) {
    test_assert(0 == pipe(fds));
    test_assert(0 == pipe(tid_fds));
    if (0 == (child = fork())) {
      test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
      pthread_join(thread, NULL);
      test_assert(0);
    }
    test_assert(sizeof(tid) == read(tid_fds[0], &tid, sizeof(tid)));
    wait_for_task_asleep_in_syscall(tid, SYS_read, fds[0]);
    /* The main thread is in pthread_join(), whose futex syscall depends on
       the libc. */
    while (get_task_state(child) != 'S') {
      sched_yield();
    }
    /* SIGURG is ignored by default. */
    test_assert(0 == syscall(SYS_tgkill, child, child, SIGURG));
    test_assert(0 == syscall(SYS_tgkill, child, tid, SIGURG));
    test_assert(1 == write(fds[1], "x", 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == close(fds[0]));
    test_assert(0 == close(fds[1]));
    test_assert(0 == close(tid_fds[0]));
    test_assert(0 == close(tid_fds[1]));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
