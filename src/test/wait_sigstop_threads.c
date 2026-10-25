/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* waitpid(), wait4() and waitid() report the stop of a child process with
   several threads, or whose main thread has exited, with the child's pid. */

#define ROUNDS 6
#define THREADS 4

static int ready_fds[2];

static void* thread_main(__attribute__((unused)) void* p) {
  test_assert(1 == write(ready_fds[1], "r", 1));
  for (;;) {
    pause();
  }
  return NULL;
}

static pid_t fork_child(int threads, int main_thread_exits) {
  pthread_t thread;
  pid_t child;
  int i;
  char ch;

  if (0 == (child = fork())) {
    for (i = 0; i < threads; ++i) {
      test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    }
    if (main_thread_exits) {
      pthread_exit(NULL);
    }
    for (;;) {
      pause();
    }
  }
  for (i = 0; i < threads; ++i) {
    test_assert(1 == read(ready_fds[0], &ch, 1));
  }
  if (main_thread_exits) {
    while (get_task_state(child) != 'Z') {
      sched_yield();
    }
  }
  return child;
}

/* Polls with WNOHANG until the child's stop is there. */
static void wait_for_stop(int how, pid_t child) {
  siginfo_t* si;
  int status;
  pid_t ret;

  switch (how) {
    case 0:
      while (0 == (ret = waitpid(child, &status, WUNTRACED | WNOHANG))) {
        sched_yield();
      }
      test_assert(child == ret);
      test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
      break;
    case 1:
      while (0 == (ret = wait4(-1, &status, WUNTRACED | WNOHANG, NULL))) {
        sched_yield();
      }
      test_assert(child == ret);
      test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
      break;
    case 2:
      ALLOCATE_GUARD(si, 'a');
      do {
        sched_yield();
        si->si_pid = 0;
        test_assert(0 == waitid(P_PID, child, si, WSTOPPED | WNOHANG));
      } while (!si->si_pid);
      test_assert(si->si_pid == child && si->si_code == CLD_STOPPED &&
                  si->si_status == SIGSTOP);
      VERIFY_GUARD(si);
      break;
  }
}

int main(void) {
  pid_t child;
  int status;
  int how;
  int i;

  test_assert(0 == pipe(ready_fds));
  for (how = 0; how < 3; ++how) {
    for (i = 0; i < ROUNDS; ++i) {
      child = fork_child(THREADS, i % 2);
      test_assert(0 == kill(child, SIGSTOP));
      wait_for_stop(how, child);
      test_assert(0 == kill(child, SIGKILL));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    }
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
