/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* A wait consumes only the stop it reports:
   - We trace both threads of a child and give both a signal-delivery stop.
     When another thread of ours waits for the second thread's stop, that
     stop is gone and the main thread's is still there.
   - We trace the second thread of a child whose main thread has exited and
     stop the child. When we wait for the child's job-control stop, the
     traced thread's group stop is still there. */

static int ready_fds[2];
static pid_t child;
static pid_t tid;

static void* child_thread_main(__attribute__((unused)) void* p) {
  pid_t my_tid = sys_gettid();
  test_assert(sizeof(my_tid) == write(ready_fds[1], &my_tid, sizeof(my_tid)));
  for (;;) {
    pause();
  }
  return NULL;
}

static void fork_child(int main_thread_exits) {
  pthread_t thread;
  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, child_thread_main, NULL));
    if (main_thread_exits) {
      pthread_exit(NULL);
    }
    for (;;) {
      pause();
    }
  }
  test_assert(sizeof(tid) == read(ready_fds[0], &tid, sizeof(tid)));
}

static void kill_and_reap_child(void) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void* wait_for_tid_main(__attribute__((unused)) void* p) {
  int status;
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  return NULL;
}

static void other_thread_waits(void) {
  pthread_t thread;
  siginfo_t si;
  int status;

  fork_child(0);
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGUSR1));
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGUSR1));
  test_assert(0 == waitid(P_PID, tid, &si, WSTOPPED | WNOWAIT | __WALL));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT | __WALL));

  test_assert(0 == pthread_create(&thread, NULL, wait_for_tid_main, NULL));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(0 == waitpid(tid, &status, __WALL | WNOHANG));
  test_assert(child == waitpid(child, &status, __WALL | WNOHANG));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  kill_and_reap_child();
}

static void job_control_wait(void) {
  siginfo_t si;
  int status;

  fork_child(1);
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  while (get_task_state(child) != 'Z') {
    sched_yield();
  }
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, (void*)SIGSTOP));
  test_assert(0 == waitid(P_PID, tid, &si, WSTOPPED | WNOWAIT | __WALL));

  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED));
  test_assert(si.si_pid == child && si.si_code == CLD_STOPPED &&
              si.si_status == SIGSTOP);
  test_assert(tid == waitpid(tid, &status, __WALL | WNOHANG));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  kill_and_reap_child();
}

int main(void) {
  test_assert(0 == pipe(ready_fds));
  other_thread_waits();
  job_control_wait();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
