/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* An interval timer sends SIGALRM, which this program ignores, every
   millisecond while the program blocks in read() on a timerfd and in
   clock_nanosleep() with TIMER_ABSTIME. A traced task still gets ignored
   signals, so each one interrupts the syscall, and the kernel restarts the
   syscall after the signal's stop. Sometimes another SIGALRM arrives after
   rr has looked at the pending signals at that stop, and the task stops for
   it before it's back in user space. rr must record that stop with the
   registers of the restarted syscall, as it did for the previous signal.
   The race it tests only happens in some recordings. */

#define TIMER_PERIOD_US 1000
#define WAIT_NS 20000000
#define ROUNDS 10

int main(void) {
  struct itimerval timer = { { 0, TIMER_PERIOD_US }, { 0, TIMER_PERIOD_US } };
  struct itimerval timer_off;
  struct itimerspec timerfd_value;
  struct timespec deadline;
  uint64_t expirations;
  int fd;
  int i;

  test_assert(SIG_ERR != signal(SIGALRM, SIG_IGN));
  fd = timerfd_create(CLOCK_MONOTONIC, 0);
  test_assert(fd >= 0);
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));

  for (i = 0; i < ROUNDS; ++i) {
    memset(&timerfd_value, 0, sizeof(timerfd_value));
    timerfd_value.it_value.tv_nsec = WAIT_NS;
    test_assert(0 == timerfd_settime(fd, 0, &timerfd_value, NULL));
    test_assert(sizeof(expirations) ==
                read(fd, &expirations, sizeof(expirations)));
    test_assert(expirations == 1);

    test_assert(0 == clock_gettime(CLOCK_MONOTONIC, &deadline));
    deadline.tv_nsec += WAIT_NS;
    if (deadline.tv_nsec >= 1000000000) {
      deadline.tv_nsec -= 1000000000;
      deadline.tv_sec++;
    }
    test_assert(0 == clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                                     &deadline, NULL));
  }

  memset(&timer_off, 0, sizeof(timer_off));
  test_assert(0 == setitimer(ITIMER_REAL, &timer_off, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
