/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Buffered read()s into a read-only buffer fail with EFAULT while a
   profiling timer keeps sending SIGPROF. rr stashes a SIGPROF that arrives
   in the syscall buffer code and blocks all signals until that code is done,
   so the SIGSEGV of the syscall buffer's check of the read()'s buffer can be
   blocked, and then the kernel resets SIGSEGV's disposition. rr must restore
   the tracee's SIGSEGV handler. The race it tests only happens in some
   recordings.
   ITIMER_PROF counts our CPU time, so the signals don't outpace a slow
   recording. */

#define READS 3000

static volatile int profs;

static void prof_handler(__attribute__((unused)) int sig) { ++profs; }

static void segv_handler(__attribute__((unused)) int sig) {
  atomic_puts("FAILED: SIGSEGV handler ran");
  _exit(1);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  struct itimerval timer;
  struct sigaction sa;
  char buf[16];
  char* ro_page;
  int zero_fd;
  int i;

  ro_page = (char*)mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
  test_assert(ro_page != MAP_FAILED);
  zero_fd = open("/dev/zero", O_RDONLY);
  test_assert(zero_fd >= 0);
  /* Read once with a good buffer first, so that rr patches read()'s call site
     to use the syscall buffer. */
  test_assert(16 == read(zero_fd, buf, sizeof(buf)));
  test_assert(16 == read(zero_fd, buf, sizeof(buf)));

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = segv_handler;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  sa.sa_handler = prof_handler;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGPROF, &sa, NULL));

  memset(&timer, 0, sizeof(timer));
  timer.it_interval.tv_usec = 300;
  timer.it_value.tv_usec = 300;
  test_assert(0 == setitimer(ITIMER_PROF, &timer, NULL));
  for (i = 0; i < READS; ++i) {
    test_assert(-1 == read(zero_fd, ro_page, 16));
    test_assert(errno == EFAULT);
  }
  memset(&timer, 0, sizeof(timer));
  test_assert(0 == setitimer(ITIMER_PROF, &timer, NULL));

  test_assert(0 == sigaction(SIGSEGV, NULL, &sa));
  test_assert(sa.sa_handler == segv_handler);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
