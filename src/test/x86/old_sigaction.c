/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The old i386 sigaction() syscall takes a struct old_sigaction, which has
   only the first word of the signal mask, before sa_flags. The structs are
   followed by bytes with all bits set, which the syscalls must leave alone.
   rr must note the flags of the handler (SA_RESETHAND here). */

#if defined(__i386__)

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

static uint8_t* buf;

static volatile int handled;

static void handler(int sig) {
  test_assert(sig == SIGURG);
  ++handled;
}

static void check_untouched(size_t from, size_t to) {
  size_t i;
  for (i = from; i < to; ++i) {
    test_assert(buf[i] == 0xff);
  }
}

int main(void) {
  struct i386_old_sigaction* act;
  struct i386_old_sigaction* oact;
  struct i386_sigaction* rt_oact;

  buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
  test_assert(buf != MAP_FAILED);
  act = (struct i386_old_sigaction*)buf;
  oact = (struct i386_old_sigaction*)(buf + 1024);
  rt_oact = (struct i386_sigaction*)(buf + 2048);

  /* SIG_IGN, with SIGUSR2 in the mask and a restorer with all bits set, read
     back with rt_sigaction() */
  memset(buf, 0xff, 4096);
  act->handler = (uint32_t)(uintptr_t)SIG_IGN;
  act->mask = 1 << (SIGUSR2 - 1);
  act->flags = SA_RESTART | I386_SA_RESTORER;
  act->restorer = 0xffffffff;
  test_assert(0 == syscall(SYS_sigaction, SIGUSR1, act, NULL));
  check_untouched(sizeof(*act), 1024);
  test_assert(0 == syscall(SYS_rt_sigaction, SIGUSR1, NULL, rt_oact, 8));
  check_untouched(2048 + sizeof(*rt_oact), 4096);
  test_assert(rt_oact->handler == (uint32_t)(uintptr_t)SIG_IGN);
  test_assert(rt_oact->flags == (SA_RESTART | I386_SA_RESTORER));
  test_assert(rt_oact->restorer == 0xffffffff);
  test_assert(rt_oact->mask[0] == 1 << (SIGUSR2 - 1));
  raise(SIGUSR1);

  /* A handler with SA_RESETHAND, read back with sigaction() */
  memset(buf, 0xff, 4096);
  act->handler = (uint32_t)(uintptr_t)handler;
  act->mask = 0;
  act->flags = SA_RESETHAND;
  test_assert(0 == syscall(SYS_sigaction, SIGURG, act, NULL));
  test_assert(0 == syscall(SYS_sigaction, SIGURG, NULL, oact));
  check_untouched(1024 + sizeof(*oact), 2048);
  test_assert(oact->handler == (uint32_t)(uintptr_t)handler);
  test_assert(oact->mask == 0);
  test_assert(oact->flags == SA_RESETHAND);
  /* The first SIGURG runs the handler, and the second gets SIGURG's default
     action (ignore) */
  raise(SIGURG);
  test_assert(handled == 1);
  raise(SIGURG);
  test_assert(handled == 1);

  signal(SIGUSR1, SIG_DFL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
