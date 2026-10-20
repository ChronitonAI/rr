/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* Check the siginfo of the SIGCHLD we get when a child stops, and when a
   tracee reaches a signal-delivery-stop, a group-stop or a ptrace event
   stop, whether we take it in a handler, with sigwaitinfo() (in the thread
   that is the ptracer or in another one) or from a signalfd. SIGCHLD is
   blocked except while we wait for it, so we don't depend on timing.
   (Natively, whether two stops' SIGCHLDs merge depends on timing, so we
   check that only under rr; see below.)

   A sigwaitinfo() or sigtimedwait() that is woken up without a signal from
   its set to take fails with EINTR and isn't restarted, even when no signal
   has a handler: natively after a stop and SIGCONT (see signal(7)), and
   under rr when one of rr's own signals or a PTRACE_INTERRUPT wakes it up.
   So we retry it. */

enum { HANDLER, SIGWAITINFO, OTHER_THREAD, SIGNALFD, NUM_MODES };

static int mode;
static int sfd;

static volatile int handler_ran;
static siginfo_t handler_si;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  handler_si = *si;
  handler_ran = 1;
}

static int sigwaitinfo_retry(const sigset_t* set, siginfo_t* si) {
  int ret;
  do {
    ret = sigwaitinfo(set, si);
  } while (ret < 0 && errno == EINTR);
  return ret;
}

static void* sigwaitinfo_thread(void* p) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo_retry(&set, (siginfo_t*)p));
  return NULL;
}

static void check_sigchld(pid_t child, int code, int status) {
  sigset_t unblocked;
  sigset_t set;
  siginfo_t si;
  struct signalfd_siginfo ssi;
  pthread_t thread;

  sigemptyset(&unblocked);
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  memset(&si, 0, sizeof(si));
  switch (mode) {
    case HANDLER:
      handler_ran = 0;
      while (!handler_ran) {
        sigsuspend(&unblocked);
      }
      si = handler_si;
      break;
    case SIGWAITINFO:
      test_assert(SIGCHLD == sigwaitinfo_retry(&set, &si));
      break;
    case OTHER_THREAD:
      test_assert(0 == pthread_create(&thread, NULL, sigwaitinfo_thread, &si));
      test_assert(0 == pthread_join(thread, NULL));
      break;
    case SIGNALFD:
      test_assert(sizeof(ssi) == read(sfd, &ssi, sizeof(ssi)));
      test_assert(ssi.ssi_signo == SIGCHLD);
      test_assert(ssi.ssi_code == code);
      test_assert(ssi.ssi_pid == (uint32_t)child);
      test_assert(ssi.ssi_status == status);
      return;
  }
  test_assert(si.si_signo == SIGCHLD);
  test_assert(si.si_code == code);
  test_assert(si.si_pid == child);
  test_assert(si.si_status == status);
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

static void run_scenarios(int* pipe_fds);

int main(void) {
  int pipe_fds[2];
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
  test_assert(0 <= (sfd = signalfd(-1, &mask, 0)));

  for (mode = 0; mode < NUM_MODES; ++mode) {
    run_scenarios(pipe_fds);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

static void run_scenarios(int* pipe_fds) {
  pid_t child;
  int status;
  char ch = 'x';

  /* A child stops. */
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    exit(77);
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
    exit(77);
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
    exit(77);
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
    exit(77);
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

  if (mode != HANDLER) {
    /* A tracee stops, and while the SIGCHLD for that is pending, a child
       stops: Linux merges the child's SIGCHLD into the pending one, which is
       for the tracee. Once we've waited for both, another child stops, and
       the SIGCHLD must be for that one. (We poll for the first child's stop
       rather than wait for it: rr wouldn't wake a thread that waits for the
       child here, since it also owes us a SIGCHLD for the tracee. Under rr,
       the child's SIGCHLD is sent by the time we see its stop, so the merge
       is deterministic. Natively it isn't guaranteed: Linux marks the child
       stopped before it sends the SIGCHLD (do_signal_stop()), so the SIGCHLD
       can even arrive after we've waited for the stop. So we check the
       second child's SIGCHLD only under rr. In a handler, we'd get a
       SIGCHLD for the first child too, as rr sends another one for the
       stops it still owes us.) */
    pid_t tracee;
    pid_t stopped_child;
    pid_t child2;
    sigset_t pending;
    siginfo_t si;
    if (0 == (tracee = fork())) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    while (1) {
      test_assert(0 == sigpending(&pending));
      if (sigismember(&pending, SIGCHLD)) {
        break;
      }
      sched_yield();
    }
    if (0 == (stopped_child = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    while (1) {
      memset(&si, 0, sizeof(si));
      test_assert(
          0 == waitid(P_PID, stopped_child, &si, WSTOPPED | WNOWAIT | WNOHANG));
      if (si.si_pid == stopped_child) {
        break;
      }
      sched_yield();
    }
    test_assert(si.si_code == CLD_STOPPED);
    check_sigchld(tracee, CLD_TRAPPED, SIGUSR1);
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(stopped_child == waitpid(stopped_child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    if (0 == (child2 = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    if (running_under_rr()) {
      check_sigchld(child2, CLD_STOPPED, SIGSTOP);
    }
    test_assert(child2 == waitpid(child2, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(stopped_child, SIGCONT));
    test_assert(stopped_child == waitpid(stopped_child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(child2, SIGCONT));
    test_assert(child2 == waitpid(child2, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    drain_sigchld();
  }

  if (mode == SIGWAITINFO) {
    /* We take the SIGCHLD for a tracee's stop without asking for its
       siginfo (sigtimedwait(set, NULL, ...)). After we've resumed the
       tracee, another tracee stops, and the SIGCHLD must be for that one. */
    pid_t tracee;
    pid_t tracee2;
    int pipe2_fds[2];
    sigset_t set;
    int ret;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    test_assert(0 == pipe(pipe2_fds));
    if (0 == (tracee = fork())) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    do {
      ret = sigtimedwait(&set, NULL, NULL);
    } while (ret < 0 && errno == EINTR);
    test_assert(SIGCHLD == ret);
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
    if (0 == (tracee2 = fork())) {
      test_assert(1 == read(pipe2_fds[0], &ch, 1));
      raise(SIGUSR1);
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee2, NULL, NULL));
    test_assert(1 == write(pipe2_fds[1], &ch, 1));
    check_sigchld(tracee2, CLD_TRAPPED, SIGUSR1);
    test_assert(tracee2 == waitpid(tracee2, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, tracee2, NULL, NULL));
    test_assert(tracee2 == waitpid(tracee2, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    drain_sigchld();
    close(pipe2_fds[0]);
    close(pipe2_fds[1]);
  }
}
