/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Interval timers whose period (10us) is much shorter than the time it takes
   rr to record a signal. Whenever a handler returns, a timer has expired
   again and the next signal is already pending, yet the code between the
   signals must still make progress, as it does natively.
   1) ITIMER_REAL during a loop that reads the timestamp counter (which rr
      traps), takes and handles SIGSEGVs, checks its signal mask (a buffered
      syscall) and makes another syscall now and then.
   2) The same loop under ITIMER_REAL and ITIMER_PROF; both must be
      delivered.
   3) A child process that blocks SIGSEGV and faults during such a loop: the
      kernel unblocks SIGSEGV and the child dies of it.
   4) A loop without conditional branches under ITIMER_REAL, whose handler
      exits after a few signals.
   The handlers check the signals' siginfo. */

#define PERIOD_US 10
#define ITERATIONS 1000000
#define ITERATIONS_PER_SYSCALL 10000
#define ITERATIONS_PER_FAULT 100000
#define SIGNALS_IN_BRANCH_FREE_LOOP 10

static volatile int alarms;
static volatile int profs;
static volatile int wrong_siginfo;
static volatile int branch_free_loop;
static char* page;
static size_t page_size;
static volatile int faults;

static void handle_timer(int sig, siginfo_t* si,
                         __attribute__((unused)) void* context) {
  if (si->si_code != SI_KERNEL) {
    wrong_siginfo = 1;
  }
  if (sig == SIGPROF) {
    ++profs;
    return;
  }
  ++alarms;
  if (branch_free_loop && alarms >= SIGNALS_IN_BRANCH_FREE_LOOP) {
    atomic_puts("EXIT-SUCCESS");
    _exit(0);
  }
}

static void handle_segv(__attribute__((unused)) int sig, siginfo_t* si,
                        __attribute__((unused)) void* context) {
  if ((char*)si->si_addr != page ||
      mprotect(page, page_size, PROT_READ | PROT_WRITE)) {
    _exit(1);
  }
  ++faults;
}

static void work(void) {
  volatile int counter = 0;
  int i;
  for (i = 0; i < ITERATIONS; ++i) {
    counter = counter + 1;
    if (i % ITERATIONS_PER_SYSCALL == 0) {
      sigset_t mask;
      test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &mask));
      test_assert(!sigismember(&mask, SIGALRM));
      test_assert(!sigismember(&mask, SIGPROF));
      test_assert(getppid() > 0);
      trigger_timer_counter_trap();
    }
    if (i % ITERATIONS_PER_FAULT == 0) {
      test_assert(0 == mprotect(page, page_size, PROT_NONE));
      *page = 1;
    }
  }
  test_assert(counter == ITERATIONS);
}

static void fault_with_sigsegv_blocked(void) {
  struct itimerval timer = { { 0, PERIOD_US }, { 0, PERIOD_US } };
  struct rlimit no_core = { 0, 0 };
  sigset_t mask;
  volatile int counter = 0;
  int i;
  test_assert(0 == setrlimit(RLIMIT_CORE, &no_core));
  sigemptyset(&mask);
  sigaddset(&mask, SIGSEGV);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  for (i = 0; i < ITERATIONS; ++i) {
    counter = counter + 1;
  }
  crash_null_deref();
}

int main(void) {
  struct sigaction sa;
  struct itimerval timer = { { 0, PERIOD_US }, { 0, PERIOD_US } };
  struct itimerval timer_off = { { 0, 0 }, { 0, 0 } };
  pid_t child;
  int status;

  page_size = sysconf(_SC_PAGESIZE);
  page = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_timer;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGALRM, &sa, NULL));
  test_assert(0 == sigaction(SIGPROF, &sa, NULL));
  sa.sa_sigaction = handle_segv;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  work();
  test_assert(0 == setitimer(ITIMER_REAL, &timer_off, NULL));

  alarms = 0;
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  test_assert(0 == setitimer(ITIMER_PROF, &timer, NULL));
  work();
  while (!alarms || !profs) {
    test_assert(getppid() > 0);
  }
  test_assert(0 == setitimer(ITIMER_PROF, &timer_off, NULL));
  test_assert(0 == setitimer(ITIMER_REAL, &timer_off, NULL));

  test_assert(faults == 2 * ITERATIONS / ITERATIONS_PER_FAULT);
  test_assert(0 == sigaction(SIGSEGV, NULL, &sa));
  test_assert(sa.sa_sigaction == handle_segv);
  test_assert(!wrong_siginfo);

  child = fork();
  if (!child) {
    fault_with_sigsegv_blocked();
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  alarms = 0;
  branch_free_loop = 1;
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  for (;;) {
  }
  return 0;
}
