/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child stops and is continued several times. Check what waitpid() and
   waitid() with WCONTINUED report, and the SIGCHLDs we get. SIGCHLD is
   blocked except while we wait for the next one, so we control which
   SIGCHLDs are merged.
   Linux takes the si_status of the SIGCHLD for a stop from the report that
   our wait for the stop clears, so we make sure we have the SIGCHLD before
   we wait for the stop. */

static volatile int sigchld_codes[16];
static volatile int sigchld_statuses[16];
static volatile pid_t sigchld_pids[16];
static volatile int num_sigchlds;

static int to_child[2];
static int from_child[2];
static int sigchld_fd;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  if (num_sigchlds < 16) {
    sigchld_codes[num_sigchlds] = si->si_code;
    sigchld_statuses[num_sigchlds] = si->si_status;
    sigchld_pids[num_sigchlds] = si->si_pid;
  }
  ++num_sigchlds;
}

static void wait_for_sigchld(pid_t child, int code, int status) {
  sigset_t unblocked;
  sigset_t pending;
  int n = num_sigchlds;
  sigemptyset(&unblocked);
  while (num_sigchlds == n) {
    sigsuspend(&unblocked);
  }
  test_assert(num_sigchlds == n + 1);
  test_assert(sigchld_codes[n] == code);
  test_assert(status < 0 || sigchld_statuses[n] == status);
  test_assert(sigchld_pids[n] == child);
  /* There is no other SIGCHLD. */
  test_assert(0 == sigpending(&pending));
  test_assert(!sigismember(&pending, SIGCHLD));
}

/* Wait until a SIGCHLD is pending, without taking it. */
static void wait_for_pending_sigchld(void) {
  struct pollfd pfd = { sigchld_fd, POLLIN, 0 };
  test_assert(1 == poll(&pfd, 1, -1));
}

static void* leader_exited_thread(void* p) {
  char ch;
  /* Wait until the main thread has exited. */
  test_assert(0 == pthread_join(*(pthread_t*)p, NULL));
  test_assert(1 == write(from_child[1], &ch, 1));
  test_assert(1 == read(to_child[0], &ch, 1));
  exit(77);
  return NULL;
}

static void child_main(void) {
  char ch = 'c';
  static pthread_t main_thread;
  pthread_t thread;

  raise(SIGSTOP);
  /* Wait here, so we can't exit before our parent waited for us. */
  test_assert(1 == read(to_child[0], &ch, 1));
  raise(SIGSTOP);
  test_assert(1 == read(to_child[0], &ch, 1));
  raise(SIGSTOP);
  /* We have sent the SIGCHLD for the continue by now. */
  test_assert(1 == write(from_child[1], &ch, 1));
  test_assert(1 == read(to_child[0], &ch, 1));
  raise(SIGSTOP);
  /* Our process is reported as continued after the main thread exits. */
  main_thread = pthread_self();
  test_assert(
      0 == pthread_create(&thread, NULL, leader_exited_thread, &main_thread));
  pthread_exit(NULL);
}

int main(void) {
  pid_t child;
  int status;
  siginfo_t si;
  char ch = 'x';
  struct sigaction sa;
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  sigchld_fd = signalfd(-1, &mask, 0);
  test_assert(sigchld_fd >= 0);
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(to_child));
  test_assert(0 == pipe(from_child));

  if (0 == (child = fork())) {
    child_main();
  }

  /* Stop, continue, and waitpid(). */
  wait_for_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == waitpid(child, &status, WCONTINUED | WNOHANG));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, WCONTINUED));
  test_assert(WIFCONTINUED(status));
  /* The continue is reported only once. */
  test_assert(0 == waitpid(child, &status, WCONTINUED | WNOHANG));
  wait_for_sigchld(child, CLD_CONTINUED, SIGCONT);
  test_assert(1 == write(to_child[1], &ch, 1));

  /* Stop, continue, and waitid(). */
  wait_for_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED));
  test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED | WNOWAIT));
  test_assert(si.si_signo == SIGCHLD && si.si_code == CLD_CONTINUED);
  test_assert(si.si_status == SIGCONT && si.si_pid == child);
  /* WNOWAIT leaves the continue to be reported again. */
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED));
  test_assert(si.si_code == CLD_CONTINUED && si.si_pid == child);
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WCONTINUED | WNOHANG));
  test_assert(si.si_pid == 0);
  wait_for_sigchld(child, CLD_CONTINUED, SIGCONT);
  test_assert(1 == write(to_child[1], &ch, 1));

  /* Stop and continue before we take the SIGCHLD for the stop. The SIGCHLD
     for the continue is dropped, since the one for the stop is pending. */
  wait_for_pending_sigchld();
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, WCONTINUED));
  test_assert(WIFCONTINUED(status));
  test_assert(1 == read(from_child[0], &ch, 1));
  wait_for_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(1 == write(to_child[1], &ch, 1));

  /* Stop and continue, and wait for the continue after the thread that
     stopped has exited. */
  wait_for_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == read(from_child[0], &ch, 1));
  test_assert(child == waitpid(child, &status, WCONTINUED));
  test_assert(WIFCONTINUED(status));
  wait_for_sigchld(child, CLD_CONTINUED, SIGCONT);
  test_assert(1 == write(to_child[1], &ch, 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  /* Its si_status may be the exit code of the main thread or of the
     process. */
  wait_for_sigchld(child, CLD_EXITED, -1);

  /* Continue another child, and let it exit and wait for that before we
     take the SIGCHLD for the continue. The SIGCHLD for the exit is dropped,
     and the one for the continue still reports the continue. */
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    return 77;
  }
  wait_for_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  wait_for_sigchld(child, CLD_CONTINUED, SIGCONT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
