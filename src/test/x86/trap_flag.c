/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The tracee sets the trap flag (TF) in EFLAGS to single-step itself, and
   counts the SIGTRAPs. */

static volatile int traps;

static void handler(__attribute__((unused)) int sig) { ++traps; }

int main(void) {
  test_assert(SIG_ERR != signal(SIGTRAP, handler));
#ifdef __x86_64__
  __asm__ __volatile__("pushfq\n\t"
                       "orq $0x100,(%%rsp)\n\t"
                       "popfq\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "pushfq\n\t"
                       "andq $~0x100,(%%rsp)\n\t"
                       "popfq\n\t" ::
                           : "memory", "cc");
#else
  __asm__ __volatile__("pushfl\n\t"
                       "orl $0x100,(%%esp)\n\t"
                       "popfl\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "pushfl\n\t"
                       "andl $~0x100,(%%esp)\n\t"
                       "popfl\n\t" ::
                           : "memory", "cc");
#endif
  atomic_printf("traps: %d\n", traps);
  test_assert(traps >= 3);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
