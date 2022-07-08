/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* rr patches RDTSC instructions that are followed by certain instructions to
   use the syscallbuf. When the syscallbuf can't record an RDTSC (here,
   because the buffer is full), the extended jump patch executes the RDTSC
   and the instructions following it in the patched code itself. That must
   behave exactly like the original code: RDTSC only writes RAX and RDX, and
   the RIP-relative load must load from the original address.
   The two patch sites run in separate loops, separated by a sched_yield()
   that the .run script looks for, so the buffer fills up at each of them. */

#define NUM_ITERATIONS 100000

#ifdef __x86_64__
static uint64_t pc_rel_value __attribute__((used)) = 0x1122334455667788ULL;
#endif

int main(void) {
#ifdef __x86_64__
  int i;
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    uint64_t rcx = 0x1234567890abcdefULL + i;
    uint64_t r11 = 0xfedcba0987654321ULL - i;
    uint64_t rcx_out, r11_out;
    asm volatile("mov %[rcx], %%rcx\n\t"
                 "mov %[r11], %%r11\n\t"
                 "rdtsc\n\t"
                 "shl $32, %%rdx\n\t"
                 "mov %%rcx, %[rcx_out]\n\t"
                 "mov %%r11, %[r11_out]\n\t"
                 : [rcx_out] "=&r"(rcx_out), [r11_out] "=&r"(r11_out)
                 : [rcx] "r"(rcx), [r11] "r"(r11)
                 : "rax", "rcx", "rdx", "r11", "cc");
    test_assert(rcx_out == rcx);
    test_assert(r11_out == r11);
  }
  sched_yield();
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    uint64_t r9_out;
    asm volatile("rdtsc\n\t"
                 "mov pc_rel_value(%%rip), %%r9\n\t"
                 "mov %%r9, %[r9_out]\n\t"
                 : [r9_out] "=&r"(r9_out)
                 :
                 : "rax", "rdx", "r9", "cc");
    test_assert(r9_out == pc_rel_value);
  }
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
