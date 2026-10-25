/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread that blocks SIGCHLD has a SIGCHLD from pthread_kill() pending,
   which is pending for that thread alone. We block SIGCHLD and:
   - stop a child, take the SIGCHLD for the stop with sigwaitinfo(), kill
     and reap the child, and take the SIGCHLD for the exit. When we then
     handle another signal, no SIGCHLD is pending.
   - stop a child C and take the SIGCHLD for the stop with sigwaitinfo().
     Once the SIGCHLD for the stop of a child E is pending, we kill and reap
     C and then E. When we unblock SIGCHLD, our handler gets one SIGCHLD, for
     E's stop. */

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
  test_assert(0 == pthread_sigmask(how, &sigs, NULL));
}

static void wait_for_sigchld_pending(void) {
  sigset_t pending;
  do {
    sched_yield();
    test_assert(0 == sigpending(&pending));
  } while (!sigismember(&pending, SIGCHLD));
}

static void take_sigchld(void) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo(&sigs, NULL));
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

static void kill_and_reap(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void* idle_thread_main(__attribute__((unused)) void* p) {
  for (;;) {
    pause();
  }
  return NULL;
}

static void take_stop_and_exit(void) {
  sigset_t pending;
  pid_t child;

  set_sigchld_blocked(SIG_BLOCK);
  child = fork_child();
  test_assert(0 == kill(child, SIGSTOP));
  take_sigchld();
  kill_and_reap(child);
  take_sigchld();

  test_assert(0 == raise(SIGUSR1));
  test_assert(0 == sigpending(&pending));
  test_assert(!sigismember(&pending, SIGCHLD));
  set_sigchld_blocked(SIG_UNBLOCK);
}

static void take_stop_then_stop_another(void) {
  pid_t child_c;
  pid_t child_e;

  set_sigchld_blocked(SIG_BLOCK);
  child_c = fork_child();
  test_assert(0 == kill(child_c, SIGSTOP));
  wait_for_sigchld_pending();
  take_sigchld();
  child_e = fork_child();
  test_assert(0 == kill(child_e, SIGSTOP));
  wait_for_sigchld_pending();
  kill_and_reap(child_c);
  kill_and_reap(child_e);

  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_STOPPED);
  test_assert(handler_si.si_pid == child_e);
  test_assert(handler_si.si_status == SIGSTOP);
}

int main(void) {
  struct sigaction sa;
  pthread_t idle_thread;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sigusr1;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));

  set_sigchld_blocked(SIG_BLOCK);
  test_assert(0 == pthread_create(&idle_thread, NULL, idle_thread_main, NULL));
  test_assert(0 == pthread_kill(idle_thread, SIGCHLD));
  set_sigchld_blocked(SIG_UNBLOCK);

  take_stop_and_exit();
  take_stop_then_stop_another();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
