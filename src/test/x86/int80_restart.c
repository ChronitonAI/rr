/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* Restarts of i386 syscalls that an x86-64 process makes with int $0x80,
   after signals interrupted them. */

#if defined(__x86_64__)

static pid_t main_tid;
static int* futex_word;
static int caught_signals;

static void handle_signal(__attribute__((unused)) int sig) { ++caught_signals; }

struct interruption {
  long syscallno;
  int sig;
  int wake;
};

static volatile int signalled;

static void* interrupter_thread(void* p) {
  struct interruption* in = p;
  int80_wait_for_blocked_syscall(main_tid, in->syscallno);
  syscall(SYS_tgkill, getpid(), main_tid, in->sig);
  signalled = 1;
  if (in->wake) {
    /* After the restart, if any, the syscall blocks again. */
    int80_wait_for_blocked_syscall(main_tid, in->syscallno);
    *futex_word = 1;
    syscall(SYS_futex, futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
  }
  return NULL;
}

static pthread_t interrupt(long syscallno, int sig, int wake) {
  static struct interruption in;
  pthread_t thread;
  in.syscallno = syscallno;
  in.sig = sig;
  in.wake = wake;
  signalled = 0;
  pthread_create(&thread, NULL, interrupter_thread, &in);
  return thread;
}

int main(void) {
  int32_t* ts = int80_low_alloc(4096);
  struct sigaction sa;
  pthread_t thread;
  long ret;

  int80_setup();
  main_tid = sys_gettid();
  futex_word = (int*)(ts + 16);

  /* A signal without a handler: SIGWINCH is ignored by default, so it only
     interrupts the syscall when a ptracer (rr) sees it. The kernel restarts
     a nanosleep with restart_syscall. Sleep until the signal was sent. */
  ts[0] = 0;
  ts[1] = 10000000;
  thread = interrupt(I386_nanosleep, SIGWINCH, 0);
  do {
    ret = int80_2(I386_nanosleep, LOW(ts), 0);
    test_assert(ret == 0);
  } while (!signalled);
  pthread_join(thread, NULL);

  /* A futex wait with a timeout is restarted with restart_syscall too. */
  ts[0] = 60;
  ts[1] = 0;
  *futex_word = 0;
  thread = interrupt(I386_futex, SIGWINCH, 1);
  while (!*futex_word) {
    ret = int80_4(I386_futex, LOW(futex_word), FUTEX_WAIT, 0, LOW(ts));
    test_assert(ret == 0 || ret == -EAGAIN);
  }
  pthread_join(thread, NULL);

  /* A futex wait without a timeout is restarted as it is, with its own
     syscall number. */
  *futex_word = 0;
  thread = interrupt(I386_futex, SIGWINCH, 1);
  while (!*futex_word) {
    ret = int80_4(I386_futex, LOW(futex_word), FUTEX_WAIT, 0, 0);
    test_assert(ret == 0 || ret == -EAGAIN);
  }
  pthread_join(thread, NULL);

  /* The same after a SA_RESTART handler ran. */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);
  *futex_word = 0;
  thread = interrupt(I386_futex, SIGUSR1, 1);
  while (!*futex_word) {
    ret = int80_4(I386_futex, LOW(futex_word), FUTEX_WAIT, 0, 0);
    test_assert(ret == 0 || ret == -EAGAIN);
  }
  pthread_join(thread, NULL);
  test_assert(caught_signals == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
