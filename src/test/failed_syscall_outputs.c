/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* These syscalls store an output and then fail. rr handles them without
   scratch, so the kernel stores the output in the tracee's memory, and
   replay must store it there too. */

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  /* The CPU clock of a process that doesn't exist (pid 0x0ffffff0 is above
     the kernel's PID_MAX_LIMIT), encoded as MAKE_PROCESS_CPUCLOCK does */
  clockid_t clock = (clockid_t)(~0x0ffffff0u << 3) | 2;
  int timer_id = -1;
  unsigned char vec[2] = { 0, 0 };
  char* p;

  /* timer_create() stores the timer id before the clock fails to create
     the timer. */
  test_assert(-1 == syscall(SYS_timer_create, clock, NULL, &timer_id));
  test_assert(errno == EINVAL);
  test_assert(timer_id >= 0);

  /* mincore() stores the state of the pages before an unmapped one, then
     fails with ENOMEM. */
  p = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  *p = 1;
  test_assert(-1 == mincore(p, 2 * page_size, vec));
  test_assert(errno == ENOMEM);
  test_assert(vec[0] & 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
