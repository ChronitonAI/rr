/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child's second thread blocks in pselect6(), which the syscall buffer
   doesn't handle, and arms RRCALL_KILL_BY_EXIT_GROUP_AT_SECCOMP_STOP. Its
   main thread then calls exit_group(). Before rr lets the main thread run
   exit_group(), it interrupts the second thread's pselect6() and collects
   the PTRACE_EVENT_SECCOMP stop of the restarted pselect6() without
   handling it. exit_group() kills the second thread at that stop, and rr
   handles the stop after that. */

static volatile pid_t thread_tid;

static void* thread_main(__attribute__((unused)) void* p) {
  rr_arm_kill(RRCALL_KILL_BY_EXIT_GROUP_AT_SECCOMP_STOP, 0, 0);
  thread_tid = sys_gettid();
  syscall(SYS_pselect6, 0, NULL, NULL, NULL, NULL, NULL);
  test_assert(0 && "pselect6() returned");
  return NULL;
}

int main(void) {
  pthread_t thread;
  pid_t child;
  int status;

  child = fork();
  if (!child) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    while (!thread_tid) {
      sched_yield();
    }
    wait_for_task_asleep_in_syscall(thread_tid, SYS_pselect6, 0);
    syscall(SYS_exit_group, 77);
    test_assert(0 && "Still alive");
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
