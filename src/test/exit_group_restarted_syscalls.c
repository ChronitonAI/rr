/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A process's threads are blocked in syscalls when they get a signal that
   they ignore. Under rr, which sees the signal, it interrupts the syscalls,
   which are then restarted. One thread's syscall returns, and it exits the
   process. Another thread may then be at a PTRACE_EVENT_SECCOMP stop of
   its restarted syscall that rr has collected but not processed yet when
   the exit_group kills it, and rr must then handle its exit instead. The
   race it tests only happens in some recordings.

   The threads that don't exit the process block in read()s that the
   syscall buffer doesn't handle, since a restarted syscall that the
   syscall buffer handles doesn't stop at PTRACE_EVENT_SECCOMP. We wake the
   exiting thread before we signal them, so that the PTRACE_EVENT_SECCOMP
   stops of their restarted syscalls tend to come while it exits the
   process. */

#define ROUNDS 20
/* Threads that block besides the main thread. Each one makes the race more
   likely. */
#define BLOCKED_THREADS 2

static int block_fds[2];
static int wake_fds[2];
static int tid_fds[2];
static int exit_tid_fds[2];

static void block(void) {
  char ch;
  unbufferable_syscall(SYS_read, block_fds[0], (uintptr_t)&ch, 1);
  test_assert(0 && "read() returned");
}

static void* blocked_thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(tid_fds[1], &tid, sizeof(tid)));
  block();
  return NULL;
}

static void interrupt_blocked_thread(pid_t child, pid_t tid) {
  /* The process may have exited already. */
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGURG) || errno == ESRCH);
}

static void* exit_thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(exit_tid_fds[1], &tid, sizeof(tid)));
  test_assert(1 == read(wake_fds[0], &ch, 1));
  exit(77);
  return NULL;
}

int main(void) {
  pthread_t thread;
  pid_t child;
  pid_t tids[BLOCKED_THREADS];
  pid_t exit_tid;
  int status;
  int i;
  int j;

  for (i = 0; i < ROUNDS; ++i) {
    test_assert(0 == pipe(block_fds));
    test_assert(0 == pipe(wake_fds));
    test_assert(0 == pipe(tid_fds));
    test_assert(0 == pipe(exit_tid_fds));
    if (0 == (child = fork())) {
      for (j = 0; j < BLOCKED_THREADS; ++j) {
        test_assert(0 == pthread_create(&thread, NULL, blocked_thread_main,
                                        NULL));
      }
      test_assert(0 == pthread_create(&thread, NULL, exit_thread_main, NULL));
      block();
    }
    test_assert(child > 0);
    for (j = 0; j < BLOCKED_THREADS; ++j) {
      test_assert(sizeof(tids[j]) ==
                  read(tid_fds[0], &tids[j], sizeof(tids[j])));
      test_assert(tids[j] > 1);
    }
    test_assert(sizeof(exit_tid) ==
                read(exit_tid_fds[0], &exit_tid, sizeof(exit_tid)));
    test_assert(exit_tid > 1);
    wait_for_task_asleep_in_syscall(child, SYS_read, block_fds[0]);
    for (j = 0; j < BLOCKED_THREADS; ++j) {
      wait_for_task_asleep_in_syscall(tids[j], SYS_read, block_fds[0]);
    }
    wait_for_task_asleep_in_syscall(exit_tid, SYS_read, wake_fds[0]);
    /* SIGURG is ignored by default. */
    test_assert(0 == syscall(SYS_tgkill, child, exit_tid, SIGURG));
    test_assert(1 == write(wake_fds[1], "x", 1));
    interrupt_blocked_thread(child, child);
    for (j = 0; j < BLOCKED_THREADS; ++j) {
      interrupt_blocked_thread(child, tids[j]);
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == close(block_fds[0]));
    test_assert(0 == close(block_fds[1]));
    test_assert(0 == close(wake_fds[0]));
    test_assert(0 == close(wake_fds[1]));
    test_assert(0 == close(tid_fds[0]));
    test_assert(0 == close(tid_fds[1]));
    test_assert(0 == close(exit_tid_fds[0]));
    test_assert(0 == close(exit_tid_fds[1]));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
