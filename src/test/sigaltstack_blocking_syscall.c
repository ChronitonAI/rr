/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal handler running on the alternate signal stack blocks in a
   (buffered) read(), and another SA_ONSTACK signal arrives meanwhile. The
   kernel must put the second signal's frame below the first handler's
   frames, since the thread is already on the alternate stack, and not at
   its top, over them. */

static int fds[2];
static pid_t main_tid;
static volatile int in_handler1;
static volatile int handler2_ran;

static void handler2(__attribute__((unused)) int sig) {
  volatile char scribble[256];
  memset((void*)scribble, 0xa5, sizeof(scribble));
  handler2_ran = 1;
}

static void handler1(__attribute__((unused)) int sig) {
  volatile char canary[256];
  char c;
  ssize_t ret;
  size_t i;

  memset((void*)canary, 0x5a, sizeof(canary));
  in_handler1 = 1;
  /* SIGUSR2 interrupts it. */
  while ((ret = read(fds[0], &c, 1)) < 0) {
    test_assert(errno == EINTR);
  }
  test_assert(ret == 1);
  test_assert(c == 'x');
  test_assert(handler2_ran);
  for (i = 0; i < sizeof(canary); ++i) {
    test_assert(canary[i] == 0x5a);
  }
}

static void* do_thread(__attribute__((unused)) void* p) {
  struct timespec ts = { 0, 10000000 };
  while (!in_handler1) {
    sched_yield();
  }
  /* Give the main thread time to block in read(). */
  nanosleep(&ts, NULL);
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR2));
  while (!handler2_ran) {
    sched_yield();
  }
  test_assert(1 == write(fds[1], "x", 1));
  return NULL;
}

int main(void) {
  static char altstack[64 * 1024];
  stack_t ss;
  struct sigaction sa;
  pthread_t thread;

  main_tid = sys_gettid();
  test_assert(0 == pipe(fds));

  ss.ss_sp = altstack;
  ss.ss_flags = 0;
  ss.ss_size = sizeof(altstack);
  test_assert(0 == sigaltstack(&ss, NULL));

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_ONSTACK;
  sa.sa_handler = handler1;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  sa.sa_handler = handler2;
  test_assert(0 == sigaction(SIGUSR2, &sa, NULL));

  test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
  raise(SIGUSR1);
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
