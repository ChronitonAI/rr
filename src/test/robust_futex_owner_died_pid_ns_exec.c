/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

/* A thread of a pid namespace's init execs, which kills the init's main
   thread while it holds a process-shared robust mutex and the init's parent,
   outside the namespace, is blocked in pthread_mutex_lock() on it. The
   kernel marks the mutex FUTEX_OWNER_DIED and wakes the parent, whose lock
   returns EOWNERDEAD. The thread that execs takes over the main thread's
   tid. SIGCHLD is blocked so that the init's exit doesn't interrupt the
   parent's lock. */

struct shared {
  pthread_mutex_t mutex;
  int init_locked;
};

static void* run_thread(void* p) {
  pid_t parent = (pid_t)(uintptr_t)p;
  char* argv[] = { "/proc/self/exe", "dummy", NULL };

  test_assert(parent > 1);
  /* The parent sleeps only in its pthread_mutex_lock(). */
  while (get_task_state(parent) != 'S') {
    sched_yield();
  }
  execve("/proc/self/exe", argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

static void run_init(struct shared* s, pid_t parent) {
  pthread_t thread;

  test_assert(getpid() == 1);
  test_assert(0 == pthread_mutex_lock(&s->mutex));
  __atomic_store_n(&s->init_locked, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, run_thread,
                                  (void*)(uintptr_t)parent));
  /* The exec kills this thread. */
  while (1) {
    pause();
  }
}

int main(int argc, __attribute__((unused)) char** argv) {
  pthread_mutexattr_t attr;
  struct shared* s;
  sigset_t sigchld;
  pid_t parent;
  pid_t child;
  int status;

  if (argc > 1) {
    /* The init after the exec */
    test_assert(getpid() == 1);
    return 0;
  }

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  s = (struct shared*)mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(s != MAP_FAILED);
  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(&s->mutex, &attr));

  sigemptyset(&sigchld);
  sigaddset(&sigchld, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigchld, NULL));

  parent = getpid();
  test_assert(parent > 1);
  /* The first child is the init of the new pid namespace. */
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    run_init(s, parent);
  }

  while (!__atomic_load_n(&s->init_locked, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(&s->mutex));
  test_assert(0 == pthread_mutex_consistent(&s->mutex));
  test_assert(0 == pthread_mutex_unlock(&s->mutex));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
