/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) maps over the
 * page of the countdown, then makes syscalls without ticking. rr must leave
 * that mapping alone instead of programming a countdown in it. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

#if defined(__RR_SOFTTICKS__) && __has_attribute(disable_sanitizer_instrumentation)
/* Built by a software-ticks compiler pass, which would tick in the loop below
   as well. */
__attribute__((disable_sanitizer_instrumentation))
#endif
int main(void) {
  int i;
  RR_SOFTTICK();
  atomic_puts("replacing the countdown's page");
  syscall(RR_mmap, RR_SOFTTICKS_COUNTDOWN_ADDR & ~4095L, 4096L, PROT_NONE,
          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1L, 0L);
  /* No ticks from here on: they would fault. A C library built for software
     ticks ticks in syscall() too, so make the system calls directly. */
  for (i = 0; i < 3; ++i) {
    unbufferable_syscall(RR_getpid, 0, 0, 0);
  }
  unbufferable_syscall(RR_write, STDOUT_FILENO, (uintptr_t)"EXIT-SUCCESS\n",
                       13);
  unbufferable_syscall(RR_exit_group, 0, 0, 0);
  return 1;
}
