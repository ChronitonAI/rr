/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* Check the siginfo of the SIGCHLD we get when a child stops, and when a
   tracee reaches a signal-delivery-stop, a group-stop or a ptrace event
   stop. SIGCHLD is blocked except while we wait for it, so we don't depend
   on timing. */

static volatile int handler_ran;
static siginfo_t handler_si;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  handler_si = *si;
  handler_ran = 1;
}

static void check_sigchld(pid_t child, int code, int status) {
  sigset_t unblocked;
  sigemptyset(&unblocked);
  handler_ran = 0;
  while (!handler_ran) {
    sigsuspend(&unblocked);
  }
  test_assert(handler_si.si_signo == SIGCHLD);
  test_assert(handler_si.si_code == code);
  test_assert(handler_si.si_pid == child);
  test_assert(handler_si.si_status == status);
}

/* Discard any SIGCHLD that is pending, e.g. for a child's exit. */
static void drain_sigchld(void) {
  sigset_t set;
  struct timespec ts = { 0, 0 };
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  while (SIGCHLD == sigtimedwait(&set, NULL, &ts)) {
  }
}

int main(void) {
  pid_t child;
  int status;
  int pipe_fds[2];
  char ch = 'x';
  struct sigaction sa;
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(pipe_fds));

  /* A child stops. */
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    return 77;
  }
  check_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a signal-delivery-stop. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    raise(SIGUSR1);
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    return 77;
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGUSR1);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a group-stop (a PTRACE_EVENT_STOP, since it was
     seized): CLD_STOPPED with the stop signal. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    raise(SIGSTOP);
    return 77;
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  check_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a ptrace event stop: CLD_TRAPPED with SIGTRAP. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    return 77;
  }
  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEEXIT));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGTRAP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
