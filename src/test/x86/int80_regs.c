/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* An i386 syscall that an x86-64 process makes with int $0x80 keeps all
   registers but rax. Linux keeps r8-r11 too since 4.18 (commit
   22cd978e5986, which 4.14.y and 4.17.y have too). */

#if defined(__x86_64__)

static int kernel_keeps_r8_to_r11(void) {
  struct utsname u;
  int major, minor;
  test_assert(0 == uname(&u));
  test_assert(2 == sscanf(u.release, "%d.%d", &major, &minor));
  return major > 4 || (major == 4 && minor >= 18);
}

int main(void) {
  struct int80_regs in, out;
  int keeps_r8_to_r11 = kernel_keeps_r8_to_r11();
  int i;
  for (i = 0; i < 3; ++i) {
    in.rax = I386_getpid;
    in.rbx = 0x1111111111111111ULL + i;
    in.rcx = 0x2222222222222222ULL + i;
    in.rdx = 0x3333333333333333ULL + i;
    in.rsi = 0x4444444444444444ULL + i;
    in.rdi = 0x5555555555555555ULL + i;
    in.rbp = 0x6666666666666666ULL + i;
    in.r8 = 0x8888888888888888ULL + i;
    in.r9 = 0x9999999999999999ULL + i;
    in.r10 = 0xaaaaaaaaaaaaaaaaULL + i;
    in.r11 = 0xbbbbbbbbbbbbbbbbULL + i;
    int80_with_regs(&in, &out);
    test_assert((int32_t)out.rax == getpid());
    test_assert(out.rbx == in.rbx);
    test_assert(out.rcx == in.rcx);
    test_assert(out.rdx == in.rdx);
    test_assert(out.rsi == in.rsi);
    test_assert(out.rdi == in.rdi);
    test_assert(out.rbp == in.rbp);
    if (keeps_r8_to_r11) {
      test_assert(out.r8 == in.r8);
      test_assert(out.r9 == in.r9);
      test_assert(out.r10 == in.r10);
      test_assert(out.r11 == in.r11);
    }
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
