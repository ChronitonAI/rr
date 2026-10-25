/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We block SIGCHLD, stop a child, wait until the SIGCHLD for the stop is
   pending, wait for the stop, and kill and reap the child. When we unblock
   SIGCHLD, our handler gets the SIGCHLD for the stop, which the SIGCHLD for
   the exit merged into. The child may have a second thread, and we may send
   ourselves a SIGCHLD with raise() first, which is pending for our thread,
   so the handler gets it before the one for the stop. Or we take the
   SIGCHLD for the stop with sigwaitinfo() before we unblock SIGCHLD, and
   then the handler gets the SIGCHLD for the stop of the next child. */

static int ready_fds[2];
static volatile int handler_calls;
static siginfo_t handler_si[2];

static void handle_sigchld(__attribute__((unused)) int sig, siginfo_t* si,
                           __attribute__((unused)) void* context) {
  if (handler_calls < 2) {
    handler_si[handler_calls] = *si;
  }
  ++handler_calls;
}

static void set_sigchld_blocked(int how) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(0 == sigprocmask(how, &sigs, NULL));
}

static void wait_for_sigchld_pending(void) {
  sigset_t pending;
  do {
    sched_yield();
    test_assert(0 == sigpending(&pending));
  } while (!sigismember(&pending, SIGCHLD));
}

static void* child_thread_main(__attribute__((unused)) void* p) {
  test_assert(1 == write(ready_fds[1], "r", 1));
  for (;;) {
    pause();
  }
  return NULL;
}

static pid_t stop_and_reap_child(int with_thread) {
  pthread_t thread;
  pid_t child;
  int status;
  char ch;

  if (0 == (child = fork())) {
    if (with_thread) {
      test_assert(0 == pthread_create(&thread, NULL, child_thread_main, NULL));
    } else {
      test_assert(1 == write(ready_fds[1], "r", 1));
    }
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(1 == read(ready_fds[0], &ch, 1));

  test_assert(0 == kill(child, SIGSTOP));
  wait_for_sigchld_pending();
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  return child;
}

static void check_stop_siginfo(const siginfo_t* si, pid_t child) {
  test_assert(si->si_code == CLD_STOPPED);
  test_assert(si->si_pid == child);
  test_assert(si->si_status == SIGSTOP);
}

static void run_child(int with_thread, int raise_sigchld) {
  pid_t child;

  set_sigchld_blocked(SIG_BLOCK);
  child = stop_and_reap_child(with_thread);
  if (raise_sigchld) {
    test_assert(0 == raise(SIGCHLD));
  }

  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1 + raise_sigchld);
  if (raise_sigchld) {
    test_assert(handler_si[0].si_code == SI_TKILL);
    test_assert(handler_si[0].si_pid == getpid());
  }
  check_stop_siginfo(&handler_si[raise_sigchld], child);
}

static void take_sigchld_then_run_child(void) {
  sigset_t sigs;
  pid_t child;

  set_sigchld_blocked(SIG_BLOCK);
  stop_and_reap_child(0);
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo(&sigs, NULL));
  child = stop_and_reap_child(0);

  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  check_stop_siginfo(&handler_si[0], child);
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(ready_fds));

  run_child(0, 0);
  run_child(1, 0);
  run_child(0, 1);
  take_sigchld_then_run_child();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
