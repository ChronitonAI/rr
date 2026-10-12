/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A process's threads are blocked in syscalls when a signal that they ignore
   interrupts them, which they then restart. One thread's syscall returns,
   and it exits the process. Under rr, the other thread may be at a
   PTRACE_EVENT_SECCOMP stop of its restarted syscall that rr has collected
   but not processed yet when the exit_group kills it. */

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

/* Returns true if the thread |tid| of |pid| is sleeping. */
static int thread_sleeping(pid_t pid, pid_t tid) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/task/%d/stat", pid, tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  return p[2] == 'S';
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
    while (!thread_sleeping(child, child) || !thread_sleeping(child, tid)) {
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
