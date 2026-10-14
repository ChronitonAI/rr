/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread's blocking read() is interrupted by a signal whose handler stops
   the process with SIGSTOP, and restarts when the handler returns. The read()
   is made from a site rr doesn't patch, so rr sees the restarted read()'s
   entry at a PTRACE_SYSCALL stop, and a PTRACE_EVENT_SECCOMP stop follows.
   The thread reaches that stop during the group stop.
   With the argument "signalfd", the thread reads a signalfd for SIGUSR2,
   which the parent sends after the SIGCONT, instead of a pipe. Reading a
   signalfd recomputes whether the thread has a signal pending before it
   blocks. */

#define NUM_ITERATIONS 20

static int pipe_a[2];
static int pipe_b[2];
static int ack_fds[2];
static int use_signalfd;
static int sig_fd;
static volatile pid_t main_tid;
static volatile pid_t reader_tid;

static char task_state(pid_t tid) {
  char path[100];
  char buf[1000];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/stat", tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  /* The state follows the command name in parentheses. */
  p = strrchr(buf, ')');
  test_assert(p && p[1] == ' ');
  return p[2];
}

static void handle_usr1(__attribute__((unused)) int sig) {
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGSTOP));
}

static void* reader_thread(__attribute__((unused)) void* p) {
  struct sched_param param;
  char ch;
  int i;

  /* Run this thread only when its CPU has nothing else to do, so that rr
     handles the SIGSTOP before this thread reaches the PTRACE_EVENT_SECCOMP
     stop of its restarted read(). */
  memset(&param, 0, sizeof(param));
  sched_setscheduler(0, SCHED_IDLE, &param);

  reader_tid = sys_gettid();
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    if (use_signalfd) {
      struct signalfd_siginfo si;
      test_assert(sizeof(si) == unbufferable_syscall(SYS_read, sig_fd,
                                                     (uintptr_t)&si,
                                                     sizeof(si)));
      test_assert(si.ssi_signo == SIGUSR2);
    } else {
      test_assert(1 ==
                  unbufferable_syscall(SYS_read, pipe_a[0], (uintptr_t)&ch, 1));
      test_assert(ch == 'x');
    }
    test_assert(1 == write(ack_fds[1], "x", 1));
  }
  return NULL;
}

static int child_main(void) {
  struct sigaction sa;
  pthread_t thread;
  char ch;
  int i;

  main_tid = sys_gettid();
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_usr1;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));

  if (use_signalfd) {
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGUSR2);
    test_assert(0 == sigprocmask(SIG_BLOCK, &sigs, NULL));
    sig_fd = signalfd(-1, &sigs, 0);
    test_assert(sig_fd >= 0);
  }

  test_assert(0 == pthread_create(&thread, NULL, reader_thread, NULL));
  while (!reader_tid) {
    sched_yield();
  }

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    /* Wait until the reader thread is blocked in its read(). */
    while (task_state(reader_tid) != 'S') {
      sched_yield();
    }
    /* Interrupt the read() with a signal whose handler stops the process and
       returns; the read() restarts. */
    test_assert(0 == syscall(SYS_tgkill, getpid(), reader_tid, SIGUSR1));
    test_assert(1 ==
                unbufferable_syscall(SYS_read, pipe_b[0], (uintptr_t)&ch, 1));
    test_assert(ch == 'x');
    test_assert(1 == read(ack_fds[0], &ch, 1));
  }
  test_assert(0 == pthread_join(thread, NULL));
  return 77;
}

int main(int argc, char* argv[]) {
  pid_t child;
  int status;
  int i;

  use_signalfd = argc > 1 && !strcmp(argv[1], "signalfd");
  test_assert(0 == pipe(pipe_a));
  test_assert(0 == pipe(pipe_b));
  test_assert(0 == pipe(ack_fds));

  child = fork();
  if (!child) {
    return child_main();
  }

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    test_assert(0 == kill(child, SIGCONT));
    if (use_signalfd) {
      test_assert(0 == kill(child, SIGUSR2));
    } else {
      test_assert(1 == write(pipe_a[1], "x", 1));
    }
    test_assert(1 == write(pipe_b[1], "x", 1));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
