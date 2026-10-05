/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Linux discards a signal that a task ignores when it's generated, unless the
   task is traced. So signals that a child ignores and that come before
   PTRACE_SEIZE or PTRACE_ATTACH don't give its new tracer any stops. A signal
   that comes after does, even if the child ignores it. */

static int to_child_fds[2];
static int from_child_fds[2];
static int to_thread_fds[2];

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(from_child_fds[1], &tid, sizeof(tid)));
  test_assert(1 == read(to_thread_fds[0], &ch, 1));
  return NULL;
}

/* Fork a child that waits for a character, ignoring SIGUSR1 and SIGTSTP. With
   |with_thread|, it has a second thread, whose tid we return in |*tid|. */
static pid_t fork_child(int with_thread, pid_t* tid) {
  pthread_t thread;
  pid_t child;
  char ch;

  if (0 == (child = fork())) {
    /* SIGCONT, SIGURG and SIGWINCH are ignored by default. */
    signal(SIGUSR1, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    if (with_thread) {
      test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    } else {
      test_assert(1 == write(from_child_fds[1], "r", 1));
    }
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    exit(77);
  }
  if (with_thread) {
    test_assert(sizeof(*tid) == read(from_child_fds[0], tid, sizeof(*tid)));
  } else {
    test_assert(1 == read(from_child_fds[0], &ch, 1));
  }
  return child;
}

static void wait_for_stop(pid_t t, int expected_status) {
  int status;
  test_assert(t == waitpid(t, &status, __WALL));
  test_assert(status == expected_status);
}

static void let_child_exit(pid_t child) {
  int status;
  test_assert(1 == write(to_child_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Returns true if |sig| is pending for the whole process |pid|. */
static int shared_signal_pending(pid_t pid, int sig) {
  char path[PATH_MAX];
  char buf[4096];
  char* p;
  unsigned long long mask;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/status", pid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strstr(buf, "ShdPnd:");
  test_assert(p != NULL);
  test_assert(1 == sscanf(p + 7, "%llx", &mask));
  return (mask >> (sig - 1)) & 1;
}

int main(void) {
  pid_t child;
  pid_t tid;
  int status;

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));
  test_assert(0 == pipe(to_thread_fds));

  /* PTRACE_SEIZE */
  child = fork_child(0, NULL);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == kill(child, SIGURG));
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == kill(child, SIGWINCH));
  wait_for_stop(child, (SIGWINCH << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  let_child_exit(child);

  /* PTRACE_ATTACH. Its SIGSTOP would discard a pending SIGCONT anyway. A
     SIGCONT after the PTRACE_ATTACH must give a stop. */
  child = fork_child(0, NULL);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == kill(child, SIGURG));
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  wait_for_stop(child, (SIGSTOP << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  wait_for_stop(child, (SIGCONT << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  let_child_exit(child);

  /* A SIGTSTP before the PTRACE_ATTACH that a SIGCONT after it discards.
     A SIGTSTP after that must give a stop. */
  child = fork_child(0, NULL);
  test_assert(0 == kill(child, SIGTSTP));
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  wait_for_stop(child, (SIGSTOP << 8) | 0x7f);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_stop(child, (SIGCONT << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == kill(child, SIGTSTP));
  wait_for_stop(child, (SIGTSTP << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  let_child_exit(child);

  /* A signal for the whole process that the main thread takes, while we
     have seized the other thread and hold it in a signal-delivery stop.
     Then the same signal for the other thread must give a stop. */
  child = fork_child(1, &tid);
  test_assert(0 == kill(child, SIGURG));
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGUSR2));
  wait_for_stop(tid, (SIGUSR2 << 8) | 0x7f);
  while (shared_signal_pending(child, SIGURG)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGURG));
  wait_for_stop(tid, (SIGURG << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(1 == write(to_thread_fds[1], "x", 1));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  let_child_exit(child);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
