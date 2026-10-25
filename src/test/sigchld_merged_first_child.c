/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We block SIGCHLD and stop a child A. Once the SIGCHLD for A's stop is
   pending, we may wait for A's stop, and then stop a child B and wait for
   B's stop. We kill and reap A, and B before it or not at all. When we
   unblock SIGCHLD, our handler gets one SIGCHLD, which the SIGCHLDs for B's
   stop and for the exits merged into: the one for A's stop.
   Then we do the same, except that after B's stop we continue A, stop it
   again and wait for that stop, and kill and reap A and B before or after
   unblocking SIGCHLD. The handler again gets one SIGCHLD, for A's first
   stop. */

static int cont_fds[2];
static volatile int handler_calls;
static siginfo_t handler_si;

static void handle_sigchld(__attribute__((unused)) int sig, siginfo_t* si,
                           __attribute__((unused)) void* context) {
  handler_si = *si;
  ++handler_calls;
}

static void handle_sigcont(__attribute__((unused)) int sig) {
  test_assert(1 == write(cont_fds[1], "c", 1));
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

/* Waits for |child|'s stop without consuming it. */
static void wait_for_stop_nowait(pid_t child) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT));
  test_assert(si.si_pid == child && si.si_code == CLD_STOPPED);
}

static void kill_and_reap(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void check_a_stop_sigchld(pid_t child_a) {
  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_STOPPED);
  test_assert(handler_si.si_pid == child_a);
  test_assert(handler_si.si_status == SIGSTOP);
}

static void run_two_children(int wait_for_a_stop, int kill_b_first) {
  pid_t child_a;
  pid_t child_b;

  set_sigchld_blocked(SIG_BLOCK);
  child_a = fork_child();
  child_b = fork_child();
  test_assert(0 == kill(child_a, SIGSTOP));
  wait_for_sigchld_pending();
  if (wait_for_a_stop) {
    wait_for_stop(child_a);
  }
  test_assert(0 == kill(child_b, SIGSTOP));
  wait_for_stop(child_b);
  if (kill_b_first) {
    kill_and_reap(child_b);
  }
  kill_and_reap(child_a);

  check_a_stop_sigchld(child_a);
  if (!kill_b_first) {
    kill_and_reap(child_b);
  }
}

static void run_stop_again(int reap_before_unblock) {
  pid_t child_a;
  pid_t child_b;
  char ch;

  set_sigchld_blocked(SIG_BLOCK);
  if (0 == (child_a = fork())) {
    signal(SIGCONT, handle_sigcont);
    test_assert(1 == write(cont_fds[1], "r", 1));
    for (;;) {
      pause();
    }
  }
  test_assert(child_a > 0);
  test_assert(1 == read(cont_fds[0], &ch, 1));
  child_b = fork_child();
  test_assert(0 == kill(child_a, SIGSTOP));
  wait_for_stop_nowait(child_a);
  wait_for_sigchld_pending();
  test_assert(0 == kill(child_b, SIGSTOP));
  wait_for_stop_nowait(child_b);
  test_assert(0 == kill(child_a, SIGCONT));
  test_assert(1 == read(cont_fds[0], &ch, 1));
  test_assert(0 == kill(child_a, SIGSTOP));
  wait_for_stop_nowait(child_a);
  if (reap_before_unblock) {
    wait_for_stop(child_a);
    wait_for_stop(child_b);
    kill_and_reap(child_a);
    kill_and_reap(child_b);
  }

  check_a_stop_sigchld(child_a);
  if (!reap_before_unblock) {
    kill_and_reap(child_a);
    kill_and_reap(child_b);
  }
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(cont_fds));

  run_two_children(1, 0);
  run_two_children(1, 1);
  run_two_children(0, 0);
  run_two_children(0, 1);
  run_stop_again(0);
  run_stop_again(1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
