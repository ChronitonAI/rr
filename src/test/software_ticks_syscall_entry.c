/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* Calls the syscall entry that the preload library publishes for code it can't
 * patch (RR_SOFTTICKS_SYSCALL_OFFSET in include/rr/softticks.h), while a timer
 * signal interrupts it, also inside the syscall buffer's code. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

#define TICK() RR_SOFTTICK()

typedef long (*syscall_entry)(long no, const long* args);

static volatile int sigs;

static void handler(__attribute__((unused)) int sig) {
  TICK();
  ++sigs;
}

static long call(syscall_entry entry, long no, long a0, long a1, long a2) {
  long args[6] = { a0, a1, a2, 0, 0, 0 };
  TICK();
  if (!entry) {
    long ret = syscall(no, a0, a1, a2);
    return ret < 0 ? -errno : ret;
  }
  return entry(no, args);
}

int main(void) {
  static const char msg[] = "via the entry\n";
  struct itimerval timer = { { 0, 1000 }, { 0, 1000 } };
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  struct timespec ts = { 0, 0 };
  syscall_entry entry;
  int fds[2];
  char c = 0;
  int i;

  TICK();
  entry = *(syscall_entry volatile*)RR_SOFTTICKS_SYSCALL_ADDR;
#if defined(__x86_64__) || defined(__i386__)
  /* Published when the syscall buffer is on. */
  test_assert((entry != NULL) == (getenv("RUNNING_UNDER_RR") != NULL &&
                                  getenv("_RR_USE_SYSCALLBUF") != NULL));
#else
  test_assert(entry == NULL);
#endif

  test_assert(call(entry, SYS_write, STDOUT_FILENO, (long)msg,
                   sizeof(msg) - 1) == (long)(sizeof(msg) - 1));
  test_assert(call(entry, SYS_getpid, 0, 0, 0) == getpid());
  test_assert(call(entry, SYS_close, -1, 0, 0) == -EBADF);
  test_assert(call(entry, SYS_clock_gettime, CLOCK_MONOTONIC, (long)&ts, 0) == 0);
  test_assert(ts.tv_sec != 0 || ts.tv_nsec != 0);
  test_assert(0 == pipe(fds));
  test_assert(call(entry, SYS_write, fds[1], (long)"x", 1) == 1);
  test_assert(call(entry, SYS_read, fds[0], (long)&c, 1) == 1);
  test_assert(c == 'x');

  signal(SIGALRM, handler);
  setitimer(ITIMER_REAL, &timer, NULL);
  /* Without the entry, every call is traced: fewer then. */
  for (i = 0; i < (entry ? 20000 : 1000); ++i) {
    TICK();
    test_assert(call(entry, SYS_getppid, 0, 0, 0) == getppid());
  }
  setitimer(ITIMER_REAL, &off, NULL);

  atomic_printf("signals: %d\n", sigs > 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
