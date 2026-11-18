/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

/* A thread of a pid namespace's init exits holding a robust mutex while the
   init's main thread is blocked in pthread_mutex_lock() on it. The kernel
   marks the mutex FUTEX_OWNER_DIED and wakes the main thread, whose lock
   returns EOWNERDEAD. */

static pthread_mutex_t mutex;
static int thread_locked;

/* Our pid in the pid namespace of /proc, the parent namespace */
static pid_t proc_pid(void) {
  char buf[32];
  ssize_t len = readlink("/proc/self", buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  return atoi(buf);
}

static void* run_thread(void* p) {
  pid_t main_tid = (pid_t)(uintptr_t)p;

  test_assert(main_tid > 1);
  test_assert(0 == pthread_mutex_lock(&mutex));
  __atomic_store_n(&thread_locked, 1, __ATOMIC_SEQ_CST);
  /* The main thread sleeps only in its pthread_mutex_lock(). */
  while (get_task_state(main_tid) != 'S') {
    sched_yield();
  }
  return NULL;
}

static void run_init(void) {
  pthread_mutexattr_t attr;
  pthread_t thread;
  pid_t main_tid;

  test_assert(getpid() == 1);
  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(&mutex, &attr));

  main_tid = proc_pid();
  test_assert(0 == pthread_create(&thread, NULL, run_thread,
                                  (void*)(uintptr_t)main_tid));

  while (!__atomic_load_n(&thread_locked, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(&mutex));
  test_assert(0 == pthread_mutex_consistent(&mutex));
  test_assert(0 == pthread_mutex_unlock(&mutex));
  test_assert(0 == pthread_join(thread, NULL));
}

int main(void) {
  pid_t child;
  int status;

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* The first child is the init of the new pid namespace. */
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    run_init();
    return 0;
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
