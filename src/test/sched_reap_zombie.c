/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread-group leader that exits before the group's other threads can't be
 * reaped until they are gone too, so rr keeps it to reap later, when the
 * scheduler picks it. If the scheduler picks it when another task's timeslice
 * expires, rr must still record that task's SCHED event: the tasks that run
 * next may run before that task continues, and replay must not run them
 * before the part of the task's execution that preceded the expiry.
 *
 * The main thread spins until the waiter thread sets `done`, which the waiter
 * does once waitpid() reports the child's exit, i.e. after rr has reaped the
 * child's leader. We arrange for rr to reap the leader when the main thread's
 * timeslice expires, and to run the waiter next:
 * - The child thread waits until the main thread is blocked, then blocks
 *   itself, so rr last ran the main thread before it.
 * - The child's leader wakes both and exits. rr runs the main thread first.
 * - The main thread calls sched_yield(), so rr runs the child thread, which
 *   exits (now the leader can be reaped), then the main thread again.
 * - The main thread spins until its timeslice expires. Then rr picks the
 *   leader (exiting tasks have the highest priority) and reaps it, which lets
 *   the waiter's waitpid() return, and runs the waiter, which sets `done`.
 * Without the main thread's SCHED, replay runs the waiter's store to `done`
 * before the main thread's spin and diverges (and a DEBUG build of rr already
 * fails when it resumes the waiter). That depends on rr's scheduling going as
 * described, which it doesn't always do, so we try a few times. */

#define ROUNDS 4

struct waiting {
  /* Set to wake the task. */
  int go;
  /* Set by the task just before it waits for `go`. */
  pid_t tid;
};

struct shared {
  struct waiting thread;
  struct waiting main;
};

static struct shared* shared;
static volatile int done;
static pid_t parent;
static pid_t child;

static void wait_for_go(struct waiting* w) {
  __atomic_store_n(&w->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  while (!__atomic_load_n(&w->go, __ATOMIC_SEQ_CST)) {
    syscall(SYS_futex, &w->go, FUTEX_WAIT, 0, NULL, NULL, 0);
  }
}

static void go(struct waiting* w) {
  __atomic_store_n(&w->go, 1, __ATOMIC_SEQ_CST);
  test_assert(syscall(SYS_futex, &w->go, FUTEX_WAKE, 1, NULL, NULL, 0) >= 0);
}

/* The state letter of task `tid` of process `pid`, from its stat file. */
static char task_state(pid_t pid, pid_t tid) {
  char path[64];
  char buf[512];
  char* p;
  ssize_t len;
  int fd;
  sprintf(path, "/proc/%d/task/%d/stat", pid, tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p && p[1] == ' ');
  return p[2];
}

/* Wait until the task of process `pid` that waits with `w` is blocked in
 * its futex wait. We observe that while we run, so rr last ran it before
 * us. */
static void wait_until_waiting(pid_t pid, struct waiting* w) {
  struct timespec ts = { 0, 1000000 };
  pid_t tid;
  while (!(tid = __atomic_load_n(&w->tid, __ATOMIC_SEQ_CST)) ||
         task_state(pid, tid) != 'S') {
    nanosleep(&ts, NULL);
  }
}

static void* waiter(__attribute__((unused)) void* p) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  done = 1;
  return NULL;
}

static void* child_thread(__attribute__((unused)) void* p) {
  wait_until_waiting(parent, &shared->main);
  wait_for_go(&shared->thread);
  /* The child's last thread: the child exits with status 0. */
  syscall(SYS_exit, 0);
  return NULL;
}

static void do_round(void) {
  pthread_t thread;
  uint64_t iterations = 0;

  memset(shared, 0, sizeof(*shared));
  done = 0;
  child = fork();
  if (!child) {
    pthread_t t;
    test_assert(0 == pthread_create(&t, NULL, child_thread, NULL));
    wait_until_waiting(getpid(), &shared->thread);
    go(&shared->thread);
    go(&shared->main);
    /* The thread-group leader exits first. */
    syscall(SYS_exit, 0);
    exit(1);
  }

  test_assert(0 == pthread_create(&thread, NULL, waiter, NULL));
  wait_for_go(&shared->main);
  sched_yield();
  while (!done) {
    ++iterations;
  }
  test_assert(0 == pthread_join(thread, NULL));
  atomic_printf("spun %s\n", iterations > 0 ? "a while" : "not at all");
}

int main(void) {
  int i;

  parent = getpid();
  shared = (struct shared*)mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(shared != MAP_FAILED);
  for (i = 0; i < ROUNDS; ++i) {
    do_round();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
