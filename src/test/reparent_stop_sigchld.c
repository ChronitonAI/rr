/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We are a subreaper and block SIGCHLD. Our child P stops its child A and
   exits once the SIGCHLD for A's stop is pending for P, so A becomes our
   child. We reap P, kill and reap A, and unblock SIGCHLD: our handler gets
   one SIGCHLD, for P's exit. */

static volatile int handler_calls;
static siginfo_t handler_si;

static void handle_sigchld(__attribute__((unused)) int sig, siginfo_t* si,
                           __attribute__((unused)) void* context) {
  handler_si = *si;
  ++handler_calls;
}

static void wait_for_sigchld_pending(void) {
  sigset_t pending;
  do {
    sched_yield();
    test_assert(0 == sigpending(&pending));
  } while (!sigismember(&pending, SIGCHLD));
}

int main(void) {
  struct sigaction sa;
  sigset_t sigs;
  pid_t child_p;
  pid_t child_a;
  int fds[2];
  int status;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigs, NULL));
  test_assert(0 == prctl(PR_SET_CHILD_SUBREAPER, 1));
  test_assert(0 == pipe(fds));

  if (0 == (child_p = fork())) {
    if (0 == (child_a = fork())) {
      for (;;) {
        pause();
      }
    }
    test_assert(child_a > 0);
    test_assert(0 == kill(child_a, SIGSTOP));
    wait_for_sigchld_pending();
    test_assert(sizeof(child_a) == write(fds[1], &child_a, sizeof(child_a)));
    return 77;
  }
  test_assert(child_p > 0);
  test_assert(sizeof(child_a) == read(fds[0], &child_a, sizeof(child_a)));
  test_assert(child_a > 1);
  test_assert(child_p == waitpid(child_p, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  test_assert(0 == kill(child_a, SIGKILL));
  test_assert(child_a == waitpid(child_a, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  test_assert(0 == sigprocmask(SIG_UNBLOCK, &sigs, NULL));
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_EXITED);
  test_assert(handler_si.si_pid == child_p);
  test_assert(handler_si.si_status == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
