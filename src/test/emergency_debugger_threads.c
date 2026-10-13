/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static int pipe_fds[2];
static volatile pid_t reader_tid;

static void* blocked_reader(__attribute__((unused)) void* p) {
  char ch;
  reader_tid = sys_gettid();
  test_assert(1 == read(pipe_fds[0], &ch, 1));
  return NULL;
}

/* Returns the state letter of thread `tid` of process `pid`. */
static char thread_state(pid_t pid, pid_t tid) {
  char path[PATH_MAX];
  char buf[1024];
  sprintf(path, "/proc/%d/task/%d/stat", pid, tid);
  int fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  ssize_t len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  close(fd);
  /* The state comes after the command name, which is in parentheses. */
  char* end_of_comm = strrchr(buf, ')');
  test_assert(end_of_comm && end_of_comm[1] == ' ');
  return end_of_comm[2];
}

static void __attribute__((noinline)) fail_here(void) { rr_fail_assertion(); }

int main(void) {
  test_assert(0 == pipe(pipe_fds));
  pid_t parent = getpid();
  pid_t child = fork();
  if (!child) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, blocked_reader, NULL));
    while (!reader_tid) {
      sched_yield();
    }
    /* Wait until our parent is blocked in waitpid() and our other thread in
       read(), so that rr has resumed them into those syscalls and they
       aren't stopped when rr fails. */
    while (thread_state(parent, parent) != 'S' ||
           thread_state(getpid(), reader_tid) != 'S') {
      sched_yield();
    }
    /* While rr records us, this doesn't return. */
    fail_here();
    return 77;
  }
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
