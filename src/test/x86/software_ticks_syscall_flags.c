/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) makes system
 * calls through an assembled wrapper that ticks at its entry, like syscall()
 * in a C library built for software ticks: the system call follows the tick
 * with nothing in between that writes the flags. The syscall stub rr patches
 * in saves those flags in the preload thread-locals page; the checksums of
 * memory that recording and replay take at every event must agree. Each
 * traced system call (getsid) follows a buffered one (time) and 0 to 3 more
 * ticks; after the buffered one, replay stops at the syscall buffer's flush
 * breakpoint, where recording does not stop. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

long ticking_syscall(long no, long arg);
void tick(void);

__asm__(".text\n"
        ".globl tick\n"
        ".type tick, @function\n"
        "tick:\n\t" RR_SOFTTICKS_TICK_ASM "\n\t"
        "ret\n"
        ".size tick, .-tick\n");

/* The instruction after the system call is one rr patches with it. */
#if defined(__x86_64__)
__asm__(".text\n"
        ".globl ticking_syscall\n"
        ".type ticking_syscall, @function\n"
        "ticking_syscall:\n\t" RR_SOFTTICKS_TICK_ASM "\n\t"
        "movq %rdi, %rax\n\t"
        "movq %rsi, %rdi\n\t"
        "syscall\n\t"
        "cmpq $-4095, %rax\n\t"
        "ret\n"
        ".size ticking_syscall, .-ticking_syscall\n");
#elif defined(__i386__)
__asm__(".text\n"
        ".globl ticking_syscall\n"
        ".type ticking_syscall, @function\n"
        "ticking_syscall:\n\t" RR_SOFTTICKS_TICK_ASM "\n\t"
        "pushl %ebx\n\t"
        "movl 8(%esp), %eax\n\t"
        "movl 12(%esp), %ebx\n\t"
        "int $0x80\n\t"
        "cmpl $-4095, %eax\n\t"
        "popl %ebx\n\t"
        "ret\n"
        ".size ticking_syscall, .-ticking_syscall\n");
#endif

int main(void) {
  int i;
  int j;
  for (i = 0; i < 200; ++i) {
    test_assert(ticking_syscall(RR_time, 0) >= 0);
    for (j = 0; j < i % 4; ++j) {
      tick();
    }
    test_assert(ticking_syscall(RR_getsid, 0) >= 0);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
