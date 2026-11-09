/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) maps over the
 * page of the countdown, then makes syscalls without ticking. rr must leave
 * that mapping alone instead of programming a countdown in it. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

/* After the page is gone the program makes its system calls itself: libc's
   syscall() ticks at its entry when the C library is built for software ticks
   too. */
static inline __attribute__((always_inline)) long raw_syscall3(long no, long a,
                                                               long b, long c) {
#if defined(__x86_64__)
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(no), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
#elif defined(__i386__)
  long ret;
  __asm__ volatile("int $0x80"
                   : "=a"(ret)
                   : "a"(no), "b"(a), "c"(b), "d"(c)
                   : "memory");
  return ret;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = no;
  register long x0 __asm__("x0") = a;
  register long x1 __asm__("x1") = b;
  register long x2 __asm__("x2") = c;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
  return x0;
#else
#error unsupported architecture
#endif
}

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
  /* No ticks from here on: they would fault. */
  for (i = 0; i < 3; ++i) {
    raw_syscall3(RR_getpid, 0, 0, 0);
  }
  raw_syscall3(RR_write, STDOUT_FILENO, (long)"EXIT-SUCCESS\n", 13);
  raw_syscall3(RR_exit_group, 0, 0, 0);
  return 1;
}
