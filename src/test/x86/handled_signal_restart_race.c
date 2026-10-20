/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread waits in a syscall until SIGUSR1's handler ends the
   wait. A second thread sends it SIGWINCH, which this program ignores,
   whenever it finds it in the syscall. A traced task gets ignored signals
   too, so under rr each SIGWINCH interrupts the wait, and the syscall is
   restarted after SIGWINCH's stop. The SIGWINCHes come one at a time from
   the second thread, so under rr the main thread gets back into the
   syscall between them, and rr runs the second thread. The second thread
   also arms a timer for SIGUSR1 once it finds the main thread in the
   syscall. Sometimes SIGUSR1 arrives after rr has looked at the pending
   signals at SIGWINCH's stop, and the main thread stops for it before it
   has made the syscall again. The handler must then see the syscall
   interrupted, as when SIGUSR1 arrives while the main thread sleeps:
   - rt_sigsuspend fails with EINTR, and so does ppoll with a signal mask
     that unblocks SIGUSR1, with or without SA_RESTART.
   - read from an empty pipe fails with EINTR without SA_RESTART, and is
     restarted with it: the handler writes a byte to the pipe.
   - nanosleep fails with EINTR.
   The race it tests only happens in some recordings. */

#define ROUNDS 25

#if defined(__x86_64__)
#define RESULT_REG gregs[REG_RAX]
#else
#define RESULT_REG gregs[REG_EAX]
#endif

static pid_t main_tid;
/* /proc/<main_tid>/syscall */
static int syscall_fd;
static int read_fds[2];
static timer_t usr1_timer;
/* The syscall that the main thread waits in. */
static long wait_syscall;
/* Nonzero while the main thread waits, and different for each wait. */
static int wait_id;
static int done;
/* Whether the handler must find the syscall failed with EINTR. */
static volatile int expect_eintr;
static volatile int handler_ran;

static void handle_usr1(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = (ucontext_t*)p;
  long result = (long)ctx->uc_mcontext.RESULT_REG;
  char c = 'x';
  if (expect_eintr && result != -EINTR) {
    atomic_printf("Handler for SIGUSR1 in syscall %ld found result %ld\n",
                  __atomic_load_n(&wait_syscall, __ATOMIC_SEQ_CST), result);
    test_assert(0);
  }
  if (__atomic_load_n(&wait_syscall, __ATOMIC_SEQ_CST) == SYS_read) {
    test_assert(1 == write(read_fds[1], &c, 1));
  }
  handler_ran = 1;
}

/* Whether the main thread is in the syscall that it waits in, asleep or
   stopped by rr. /proc/<tid>/syscall has the syscall number only while
   the thread is blocked. A nanosleep that a signal has interrupted
   continues in restart_syscall. */
static int main_thread_waits(void) {
  char buf[1024];
  long nr;
  long syscallno;
  ssize_t len = pread(syscall_fd, buf, sizeof(buf) - 1, 0);
  test_assert(len > 0);
  buf[len] = 0;
  if (sscanf(buf, "%ld", &nr) != 1) {
    return 0;
  }
  syscallno = __atomic_load_n(&wait_syscall, __ATOMIC_SEQ_CST);
  return nr == syscallno ||
         (syscallno == SYS_nanosleep && nr == SYS_restart_syscall);
}

static void* interrupt_waits(__attribute__((unused)) void* arg) {
  sigset_t mask;
  int armed_id = 0;

  test_assert(main_tid > 1);
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGWINCH);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));
  while (!__atomic_load_n(&done, __ATOMIC_SEQ_CST)) {
    int id = __atomic_load_n(&wait_id, __ATOMIC_SEQ_CST);
    if (id && main_thread_waits() &&
        id == __atomic_load_n(&wait_id, __ATOMIC_SEQ_CST)) {
      if (id != armed_id) {
        /* SIGUSR1 arrives 1 to 11 ms later, at a varying point between
           SIGWINCHes. */
        struct itimerspec value;
        memset(&value, 0, sizeof(value));
        value.it_value.tv_nsec = 1000000 + (id * 523000) % 10000000;
        test_assert(0 == timer_settime(usr1_timer, 0, &value, NULL));
        armed_id = id;
      }
      test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGWINCH));
    }
    sched_yield();
  }
  return NULL;
}

static void wait_rounds(long syscallno, int sa_restart) {
  struct sigaction sa;
  sigset_t unblocked;
  struct pollfd pfd;
  int poll_fds[2];
  int i;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_usr1;
  sa.sa_flags = SA_SIGINFO | (sa_restart ? SA_RESTART : 0);
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  expect_eintr = !(syscallno == SYS_read && sa_restart);
  sigemptyset(&unblocked);
  test_assert(0 == pipe(poll_fds));
  pfd.fd = poll_fds[0];
  pfd.events = POLLIN;

  for (i = 0; i < ROUNDS; ++i) {
    struct timespec request = { 1000, 0 };
    long ret;
    char c;

    handler_ran = 0;
    __atomic_store_n(&wait_syscall, syscallno, __ATOMIC_SEQ_CST);
    __atomic_store_n(&wait_id, i + 1, __ATOMIC_SEQ_CST);
    if (syscallno == SYS_rt_sigsuspend) {
      ret = syscall(SYS_rt_sigsuspend, &unblocked, 8);
    } else if (syscallno == SYS_ppoll) {
      ret = syscall(SYS_ppoll, &pfd, 1, NULL, &unblocked, 8);
    } else if (syscallno == SYS_read) {
      ret = syscall(SYS_read, read_fds[0], &c, 1);
    } else {
      ret = syscall(SYS_nanosleep, &request, NULL);
    }
    __atomic_store_n(&wait_id, 0, __ATOMIC_SEQ_CST);
    test_assert(handler_ran);
    if (expect_eintr) {
      test_assert(ret == -1 && errno == EINTR);
    } else {
      test_assert(ret == 1);
    }
    if (syscallno == SYS_read && !sa_restart) {
      test_assert(1 == read(read_fds[0], &c, 1));
    }
  }
  test_assert(0 == close(poll_fds[0]));
  test_assert(0 == close(poll_fds[1]));
}

int main(void) {
  struct sigevent sev;
  sigset_t mask;
  pthread_t thread;
  char path[64];

  main_tid = sys_gettid();
  sprintf(path, "/proc/%d/syscall", main_tid);
  syscall_fd = open(path, O_RDONLY);
  test_assert(syscall_fd >= 0);
  test_assert(0 == pipe(read_fds));
  test_assert(SIG_ERR != signal(SIGWINCH, SIG_IGN));
  memset(&sev, 0, sizeof(sev));
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGUSR1;
  test_assert(0 == timer_create(CLOCK_MONOTONIC, &sev, &usr1_timer));
  test_assert(0 == pthread_create(&thread, NULL, interrupt_waits, NULL));

  /* SIGUSR1 can only arrive in rt_sigsuspend and ppoll. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  wait_rounds(SYS_rt_sigsuspend, 0);
  wait_rounds(SYS_ppoll, 0);
  wait_rounds(SYS_ppoll, 1);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &mask, NULL));
  wait_rounds(SYS_read, 0);
  wait_rounds(SYS_read, 1);
  wait_rounds(SYS_nanosleep, 0);

  __atomic_store_n(&done, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_join(thread, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
