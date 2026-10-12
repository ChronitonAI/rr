/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* i386 rt_sigaction() and old sigaction() syscalls, made with int $0x80 (from
   an x86-64 process in the 64-bit build). Their structs are followed by bytes
   with all bits set, which the syscalls must leave alone, and the handlers are
   never called. */

#define I386_sigaction 67
#define I386_rt_sigaction 174
#define I386_SA_RESTORER 0x04000000

struct i386_sigaction {
  uint32_t handler;
  uint32_t flags;
  uint32_t restorer;
  uint32_t mask[2];
};

struct i386_old_sigaction {
  uint32_t handler;
  uint32_t mask;
  uint32_t flags;
  uint32_t restorer;
};

static long int80(long nr, long a1, long a2, long a3, long a4) {
  long ret;
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "0"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4)
                       : "memory");
  return ret;
}

#define PTR(p) ((long)(uintptr_t)(p))

static uint8_t* buf;

static void check_untouched(size_t from, size_t to) {
  size_t i;
  for (i = from; i < to; ++i) {
    test_assert(buf[i] == 0xff);
  }
}

int main(void) {
  struct i386_sigaction* act;
  struct i386_sigaction* oact;
  struct i386_old_sigaction* old_act;
  struct i386_old_sigaction* old_oact;

  buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
#if defined(__x86_64__)
             MAP_32BIT |
#endif
                 MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
  test_assert(buf != MAP_FAILED);
  act = (struct i386_sigaction*)buf;
  oact = (struct i386_sigaction*)(buf + 1024);
  old_act = (struct i386_old_sigaction*)(buf + 2048);
  old_oact = (struct i386_old_sigaction*)(buf + 3072);

  /* rt_sigaction() of a handler */
  memset(buf, 0xff, 4096);
  act->handler = 0x31337000;
  act->flags = SA_SIGINFO | SA_RESTART | I386_SA_RESTORER;
  act->restorer = 0x31337100;
  act->mask[0] = 1 << (SIGUSR2 - 1);
  act->mask[1] = 0;
  test_assert(0 == int80(I386_rt_sigaction, SIGURG, PTR(act), 0, 8));
  check_untouched(sizeof(*act), 1024);
  memset(oact, 0, sizeof(*oact));
  test_assert(0 == int80(I386_rt_sigaction, SIGURG, 0, PTR(oact), 8));
  check_untouched(1024 + sizeof(*oact), 2048);
  test_assert(oact->handler == 0x31337000);
  test_assert(oact->flags == (SA_SIGINFO | SA_RESTART | I386_SA_RESTORER));
  test_assert(oact->restorer == 0x31337100);
  test_assert(oact->mask[0] == 1 << (SIGUSR2 - 1));

  /* rt_sigaction() of SIG_IGN: SIGUSR2 is ignored */
  memset(act, 0, sizeof(*act));
  act->handler = (uint32_t)(uintptr_t)SIG_IGN;
  test_assert(0 == int80(I386_rt_sigaction, SIGUSR2, PTR(act), 0, 8));
  check_untouched(sizeof(*act), 1024);
  raise(SIGUSR2);

  /* old sigaction() of SIG_IGN, with a restorer with all bits set */
  memset(buf, 0xff, 4096);
  old_act->handler = (uint32_t)(uintptr_t)SIG_IGN;
  old_act->mask = 1 << (SIGUSR2 - 1);
  old_act->flags = SA_RESTART | I386_SA_RESTORER;
  old_act->restorer = 0xffffffff;
  test_assert(0 == int80(I386_sigaction, SIGUSR1, PTR(old_act), 0, 0));
  check_untouched(2048 + sizeof(*old_act), 3072);
  memset(oact, 0, sizeof(*oact));
  test_assert(0 == int80(I386_rt_sigaction, SIGUSR1, 0, PTR(oact), 8));
  test_assert(oact->handler == (uint32_t)(uintptr_t)SIG_IGN);
  test_assert(oact->flags == (SA_RESTART | I386_SA_RESTORER));
  test_assert(oact->restorer == 0xffffffff);
  test_assert(oact->mask[0] == 1 << (SIGUSR2 - 1));
  raise(SIGUSR1);

  /* old sigaction() of a handler, read back with old sigaction() */
  old_act->handler = 0x31337000;
  old_act->flags = SA_SIGINFO;
  old_act->mask = 0;
  test_assert(0 == int80(I386_sigaction, SIGURG, PTR(old_act), 0, 0));
  memset(old_oact, 0, sizeof(*old_oact));
  test_assert(0 == int80(I386_sigaction, SIGURG, 0, PTR(old_oact), 0));
  check_untouched(3072 + sizeof(*old_oact), 4096);
  test_assert(old_oact->handler == 0x31337000);
  test_assert(old_oact->flags == SA_SIGINFO);

  signal(SIGURG, SIG_DFL);
  signal(SIGUSR1, SIG_DFL);
  signal(SIGUSR2, SIG_DFL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
