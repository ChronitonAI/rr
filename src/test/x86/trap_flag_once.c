/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The tracee sets the trap flag (TF) in EFLAGS with popf and clears it again
   with the next popf. That popf still traps, once. */

static volatile int traps;

static void handler(__attribute__((unused)) int sig) { ++traps; }

int main(void) {
  test_assert(SIG_ERR != signal(SIGTRAP, handler));
#ifdef __x86_64__
  __asm__ __volatile__("pushfq\n\t"
                       "pushfq\n\t"
                       "orq $0x100,(%%rsp)\n\t"
                       "popfq\n\t"
                       "popfq\n\t" ::
                           : "memory", "cc");
#else
  __asm__ __volatile__("pushfl\n\t"
                       "pushfl\n\t"
                       "orl $0x100,(%%esp)\n\t"
                       "popfl\n\t"
                       "popfl\n\t" ::
                           : "memory", "cc");
#endif
  atomic_printf("traps: %d\n", traps);
  test_assert(traps == 1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
