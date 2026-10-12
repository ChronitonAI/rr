/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

/* A pid namespace init that exits while it still has a child can't finish
   exiting until that child has been killed and reaped, so rr reaps it only
   later, when the scheduler finds that it has become a zombie. Meanwhile
   two threads of another process take turns: each reads a shared value,
   branches on it and changes it, without making syscalls, so rr switches
   between them when their time slices end and records a SCHED event for
   each switch. When rr reaps the init at one of these switches, it must
   still record the SCHED event of the thread it just stopped. If it didn't,
   the other thread's next events would end up in the trace before code
   that the stopped thread ran before them, and replay would diverge: the
   other thread would see the shared value before the stopped thread's last
   changes to it. */

#define NUM_SPINNERS 2

/* shared[0] is the value the spinners change, shared[1] tells them to
   stop. */
static volatile uint32_t* shared;

static void* spin(__attribute__((unused)) void* arg) {
  uint32_t sum = 0;
  while (!shared[1]) {
    uint32_t v = shared[0];
    if (v & 1) {
      sum += v;
    } else {
      sum ^= v >> 1;
    }
    shared[0] = v * 3 + 1;
  }
  return (void*)(uintptr_t)sum;
}

static int run_spinners(void) {
  pthread_t threads[NUM_SPINNERS];
  int i;
  for (i = 0; i < NUM_SPINNERS; ++i) {
    test_assert(0 == pthread_create(&threads[i], NULL, spin, NULL));
  }
  for (i = 0; i < NUM_SPINNERS; ++i) {
    test_assert(0 == pthread_join(threads[i], NULL));
  }
  return 0;
}

static int do_init(void) {
  int ready_pipe[2];
  pid_t child;
  char ch;

  test_assert(0 == pipe(ready_pipe));
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    test_assert(1 == write(ready_pipe[1], "x", 1));
    pause();
    return 1;
  }
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  /* Exit while our child is still alive. The kernel kills it, and we can't
     finish exiting until it has been reaped. */
  return 77;
}

int main(void) {
  pid_t spinners;
  pid_t init;
  int status;

  shared = (volatile uint32_t*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(shared != MAP_FAILED);

  /* Fork the spinners first: a process with threads can't set up the
     namespaces. */
  spinners = fork();
  test_assert(spinners >= 0);
  if (!spinners) {
    return run_spinners();
  }

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    atomic_puts("Insufficient permissions, skipping test");
  } else {
    /* This is the first child, therefore PID 1 in its PID namespace */
    init = fork();
    test_assert(init >= 0);
    if (!init) {
      return do_init();
    }
    test_assert(init == waitpid(init, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  shared[1] = 1;
  test_assert(spinners == waitpid(spinners, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
