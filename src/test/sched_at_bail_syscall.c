/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* The main thread asks rr for a time-slice signal a different number of
   ticks ahead each time, then passes a counter that the other thread
   increments to getsid(), which the syscall buffer doesn't handle. For some
   iterations the signal arrives in the syscall buffer code, rr defers it, and
   the main thread runs on to the traced getsid() in the extended jump patch,
   where rr backs it out of the syscall to handle the signal first. With -s, rr
   switches to the other thread at the next opportunity. If it did that before
   recording the main thread's SCHED, replay would run the main thread's read
   of the counter after the other thread's increments, and the getsid()
   argument register at the SCHED would differ from the recording. */

#define NUM_ITERATIONS 256
/* rr can't program a time-slice period below 32 ticks on some CPUs, so spin
   for longer than that first. */
#define SPIN_TICKS 40

static volatile int done;
static volatile long counter;

static void* do_thread(__attribute__((unused)) void* p) {
  while (!done) {
    ++counter;
  }
  return NULL;
}

static void spin(int n) {
  volatile int i;
  for (i = 0; i < n; ++i) {
  }
}

int main(void) {
  pthread_t thread;
  int i;

  if (!running_under_rr()) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    test_assert(0 == syscall(SYS_rrcall_arm_time_slice, SPIN_TICKS + i, (long)0,
                             (long)0, (long)0, (long)0, (long)0));
    spin(SPIN_TICKS);
    syscall(SYS_getsid, 0, counter);
  }
  done = 1;
  test_assert(0 == pthread_join(thread, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
