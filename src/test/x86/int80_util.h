/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_INT80_UTIL_H_
#define RR_INT80_UTIL_H_

#include "util.h"

/* Helpers for tests of i386 syscalls that x86-64 processes make with
 * int $0x80. The kernel takes their arguments from ebx, ecx, edx, esi, edi and
 * ebp, ignores the upper halves of those registers and keeps all registers
 * but rax. Pointer arguments must be below 4GB. The syscall numbers and
 * int80_wait_for_blocked_syscall are for 32-bit builds too. */

#define I386_exit 1
#define I386_fork 2
#define I386_read 3
#define I386_write 4
#define I386_waitpid 7
#define I386_execve 11
#define I386_getpid 20
#define I386_pause 29
#define I386_ioctl 54
#define I386_old_mmap 90
#define I386_munmap 91
#define I386_socketcall 102
#define I386_clone 120
#define I386_mprotect 125
#define I386_getdents 141
#define I386_readv 145
#define I386_nanosleep 162
#define I386_mremap 163
#define I386_poll 168
#define I386_vfork 190
#define I386_mmap2 192
#define I386_getdents64 220
#define I386_gettid 224
#define I386_futex 240
#define I386_exit_group 252
#define I386_recvmsg 372

#if defined(__x86_64__)

struct int80_regs {
  uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9, r10, r11;
};

/* Loads rax to r11 from *in, executes int $0x80 and stores rax to r11
 * into *out. */
void int80_with_regs(const struct int80_regs* in, struct int80_regs* out);
__asm__(".text\n"
        ".globl int80_with_regs\n"
        ".type int80_with_regs, @function\n"
        "int80_with_regs:\n"
        "  push %rbx\n"
        "  push %rbp\n"
        "  push %rsi\n" /* out */
        "  push %rdi\n" /* in */
        "  mov 0(%rdi), %rax\n"
        "  mov 8(%rdi), %rbx\n"
        "  mov 16(%rdi), %rcx\n"
        "  mov 24(%rdi), %rdx\n"
        "  mov 32(%rdi), %rsi\n"
        "  mov 48(%rdi), %rbp\n"
        "  mov 56(%rdi), %r8\n"
        "  mov 64(%rdi), %r9\n"
        "  mov 72(%rdi), %r10\n"
        "  mov 80(%rdi), %r11\n"
        "  mov 40(%rdi), %rdi\n"
        "  int $0x80\n"
        "  xchg %rdi, 8(%rsp)\n" /* rdi = out, the stack slot = rdi */
        "  mov %rax, 0(%rdi)\n"
        "  mov %rbx, 8(%rdi)\n"
        "  mov %rcx, 16(%rdi)\n"
        "  mov %rdx, 24(%rdi)\n"
        "  mov %rsi, 32(%rdi)\n"
        "  mov %rbp, 48(%rdi)\n"
        "  mov %r8, 56(%rdi)\n"
        "  mov %r9, 64(%rdi)\n"
        "  mov %r10, 72(%rdi)\n"
        "  mov %r11, 80(%rdi)\n"
        "  mov 8(%rsp), %rax\n"
        "  mov %rax, 40(%rdi)\n"
        "  add $16, %rsp\n"
        "  pop %rbp\n"
        "  pop %rbx\n"
        "  ret\n"
        ".size int80_with_regs, .-int80_with_regs\n");

/* A page above 4GB that the x86-64 argument registers point to during
   int80() calls. Nothing may write to it. */
static unsigned char* int80_decoy;

inline static void int80_setup(void) {
  int80_decoy = (unsigned char*)mmap(
      (void*)0x7e0000000000ULL, 4096, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  test_assert(int80_decoy != MAP_FAILED);
  test_assert((uintptr_t)int80_decoy > UINT32_MAX);
  memset(int80_decoy, 0x5a, 4096);
}

inline static void int80_check_decoy(void) {
  int i;
  for (i = 0; i < 4096; ++i) {
    test_assert(int80_decoy[i] == 0x5a);
  }
}

/* Makes the i386 syscall nr with nargs arguments a1 to a6, with other values
 * in the x86-64 argument registers (rdi, rsi, rdx, r10, r8, r9): pointers to
 * the decoy page where they are not i386 arguments too, and garbage in the
 * upper halves of the i386 argument registers. Checks that rbx, rcx, rdx,
 * rsi, rdi and rbp are kept and that the decoy page is unchanged, and
 * returns the (32-bit) result. If regs_out isn't null, stores all registers
 * there. */
inline static long int80_full(int nargs, long nr, long a1, long a2, long a3,
                              long a4, long a5, long a6,
                              struct int80_regs* regs_out) {
  struct int80_regs in, out;
  uint64_t decoy = (uintptr_t)int80_decoy;
  in.rax = nr;
  in.rbx = (uint32_t)a1 | 0x1111111100000000ULL;
  in.rcx = (uint32_t)a2 | 0x2222222200000000ULL;
  in.rdx = (uint32_t)a3 | 0x3333333300000000ULL;
  in.rsi = nargs >= 4 ? ((uint32_t)a4 | 0x4444444400000000ULL) : decoy + 0x200;
  in.rdi = nargs >= 5 ? ((uint32_t)a5 | 0x5555555500000000ULL) : decoy + 0x100;
  in.rbp = (uint32_t)a6 | 0x6666666600000000ULL;
  in.r8 = decoy + 0x400;
  in.r9 = decoy + 0x500;
  in.r10 = decoy + 0x300;
  in.r11 = 0x1b1b1b1b1b1b1b1bULL;
  int80_with_regs(&in, &out);
  test_assert(out.rbx == in.rbx);
  test_assert(out.rcx == in.rcx);
  test_assert(out.rdx == in.rdx);
  test_assert(out.rsi == in.rsi);
  test_assert(out.rdi == in.rdi);
  test_assert(out.rbp == in.rbp);
  int80_check_decoy();
  if (regs_out) {
    *regs_out = out;
  }
  return (int32_t)out.rax;
}

#define int80_0(nr) int80_full(0, nr, 0, 0, 0, 0, 0, 0, NULL)
#define int80_1(nr, a) int80_full(1, nr, (long)(a), 0, 0, 0, 0, 0, NULL)
#define int80_2(nr, a, b)                                                      \
  int80_full(2, nr, (long)(a), (long)(b), 0, 0, 0, 0, NULL)
#define int80_3(nr, a, b, c)                                                   \
  int80_full(3, nr, (long)(a), (long)(b), (long)(c), 0, 0, 0, NULL)
#define int80_4(nr, a, b, c, d)                                                \
  int80_full(4, nr, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0, NULL)
#define int80_5(nr, a, b, c, d, e)                                             \
  int80_full(5, nr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0,  \
             NULL)
#define int80_6(nr, a, b, c, d, e, f)                                          \
  int80_full(6, nr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e),     \
             (long)(f), NULL)

/* Memory below 4GB */
inline static void* int80_low_alloc(size_t size) {
  void* p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  test_assert(p != MAP_FAILED);
  return p;
}

#define LOW(p) ((long)(uintptr_t)(p))

#endif /* __x86_64__ */

/* Waits until thread tid of this process sleeps in i386 syscall nr. */
inline static void int80_wait_for_blocked_syscall(pid_t tid, long nr) {
  char path[64];
  char buf[512];
  while (1) {
    int fd;
    ssize_t n;
    sprintf(path, "/proc/self/task/%d/syscall", tid);
    fd = open(path, O_RDONLY);
    test_assert(fd >= 0);
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0 && buf[0] != 'r') {
      buf[n] = 0;
      if (strtol(buf, NULL, 10) == nr) {
        char* p;
        sprintf(path, "/proc/self/task/%d/stat", tid);
        fd = open(path, O_RDONLY);
        test_assert(fd >= 0);
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        test_assert(n > 0);
        buf[n] = 0;
        p = strrchr(buf, ')');
        if (p && p[2] == 'S') {
          return;
        }
      }
    }
    sched_yield();
  }
}

#endif /* RR_INT80_UTIL_H_ */
