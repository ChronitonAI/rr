/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We block SIGCHLD and:
   - Our child A exits. Once the SIGCHLD for A's exit is pending, we reap A.
     Then a child B stops, so the SIGCHLD for B's stop merges into the
     pending one. We wait for B's stop, kill and reap B, and unblock
     SIGCHLD: our handler gets one SIGCHLD, for A's exit. We block SIGCHLD
     again, and a child C stops. Once the SIGCHLD for the stop is pending,
     we may wait for C's stop, and we kill and reap C. When we unblock
     SIGCHLD, the handler gets one SIGCHLD, for C's stop.
   - A child C stops. Once the SIGCHLD for the stop is pending, we handle a
     SIGUSR1, wait for C's stop, and kill and reap C. When we unblock
     SIGCHLD, the handler gets one SIGCHLD, for C's stop. */

static volatile int handler_calls;
static siginfo_t handler_si;

static void handle_sigchld(__attribute__((unused)) int sig, siginfo_t* si,
                           __attribute__((unused)) void* context) {
  handler_si = *si;
  ++handler_calls;
}

static void handle_sigusr1(__attribute__((unused)) int sig) {}

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

static pid_t fork_child(void) {
  pid_t child = fork();
  if (0 == child) {
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  return child;
}

static void wait_for_stop(pid_t child) {
  int status;
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
}

static void kill_and_reap(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* Unblocks SIGCHLD and checks that the handler gets one SIGCHLD, for
   |child|'s stop. */
static void check_stop_sigchld(pid_t child) {
  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_STOPPED);
  test_assert(handler_si.si_pid == child);
  test_assert(handler_si.si_status == SIGSTOP);
}

static void merged_into_exit(int wait_for_c_stop) {
  pid_t child_a;
  pid_t child_b;
  pid_t child_c;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  if (0 == (child_a = fork())) {
    _exit(5);
  }
  test_assert(child_a > 0);
  wait_for_sigchld_pending();
  test_assert(child_a == waitpid(child_a, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 5);
  child_b = fork_child();
  test_assert(0 == kill(child_b, SIGSTOP));
  wait_for_stop(child_b);
  kill_and_reap(child_b);

  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_EXITED);
  test_assert(handler_si.si_pid == child_a);
  test_assert(handler_si.si_status == 5);

  set_sigchld_blocked(SIG_BLOCK);
  child_c = fork_child();
  test_assert(0 == kill(child_c, SIGSTOP));
  wait_for_sigchld_pending();
  if (wait_for_c_stop) {
    wait_for_stop(child_c);
  }
  kill_and_reap(child_c);
  check_stop_sigchld(child_c);
}

static void handle_other_signal(void) {
  pid_t child_c;

  set_sigchld_blocked(SIG_BLOCK);
  child_c = fork_child();
  test_assert(0 == kill(child_c, SIGSTOP));
  wait_for_sigchld_pending();
  test_assert(0 == raise(SIGUSR1));
  wait_for_stop(child_c);
  kill_and_reap(child_c);
  check_stop_sigchld(child_c);
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sigusr1;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));

  merged_into_exit(1);
  merged_into_exit(0);
  handle_other_signal();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
