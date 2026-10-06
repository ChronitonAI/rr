/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread that blocks SIGCHLD waits for our child to stop. The SIGCHLDs for
   the child's stop and continue are for the process, so the main thread,
   which takes SIGCHLD in a handler, must get them. The main thread keeps
   SIGCHLD blocked except in sigsuspend(), so the test doesn't depend on
   timing. */

static volatile int sigchld_codes[8];
static volatile int num_sigchlds;

static pid_t child;
static int to_child[2];

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  if (num_sigchlds < 8) {
    sigchld_codes[num_sigchlds] = si->si_code;
  }
  ++num_sigchlds;
}

static void wait_for_sigchld(int code) {
  sigset_t unblocked;
  int n = num_sigchlds;
  sigemptyset(&unblocked);
  while (num_sigchlds == n) {
    sigsuspend(&unblocked);
  }
  test_assert(num_sigchlds == n + 1);
  test_assert(sigchld_codes[n] == code);
}

static void* waiter(__attribute__((unused)) void* p) {
  int status;
  char ch = 'x';
  /* SIGCHLD is blocked in this thread, as in the main thread. Let the child
     stop while we're waiting for it. */
  test_assert(1 == write(to_child[1], &ch, 1));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  return NULL;
}

int main(void) {
  struct sigaction sa;
  sigset_t mask;
  pthread_t thread;
  int status;
  char ch = 'x';

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(to_child));

  if (0 == (child = fork())) {
    test_assert(1 == read(to_child[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(1 == read(to_child[0], &ch, 1));
    return 77;
  }

  test_assert(0 == pthread_create(&thread, NULL, waiter, NULL));
  test_assert(0 == pthread_join(thread, NULL));
  wait_for_sigchld(CLD_STOPPED);
  test_assert(0 == kill(child, SIGCONT));
  wait_for_sigchld(CLD_CONTINUED);
  test_assert(1 == write(to_child[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  wait_for_sigchld(CLD_EXITED);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
