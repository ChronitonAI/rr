/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread unshares its fd table and exits while the main thread makes
   buffered syscalls. Afterwards all the remaining threads share one fd
   table again, which rr tells the preload library. That update must be
   recorded with the thread's exit, not in the main thread's next
   SYSCALLBUF_FLUSH event, where replay would take it for the buffer's
   contents. */

#define NUM_THREADS 30
#define NUM_ITERATIONS 2000

static int fds[2];

static void* unshare_and_exit(__attribute__((unused)) void* arg) {
  test_assert(0 == unshare(CLONE_FILES));
  return NULL;
}

int main(void) {
  int i, j;
  char ch = 'x';

  test_assert(0 == pipe(fds));
  for (i = 0; i < NUM_THREADS; ++i) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, unshare_and_exit, NULL));
    for (j = 0; j < NUM_ITERATIONS; ++j) {
      test_assert(1 == write(fds[1], &ch, 1));
      test_assert(1 == read(fds[0], &ch, 1));
    }
    test_assert(0 == pthread_join(thread, NULL));
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
