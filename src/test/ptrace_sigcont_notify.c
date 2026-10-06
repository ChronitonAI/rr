/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* After a SIGCONT, Linux reports a PTRACE_EVENT_STOP to the ptracer of a
   seized tracee, before the SIGCONT's signal-delivery stop. A SIGCONT from
   before the PTRACE_SEIZE doesn't give one, whether it's still pending at
   the PTRACE_SEIZE or not. */

static int to_child_fds[2];
static int from_child_fds[2];
static int to_thread_fds[2];

static void expect_sigcont_stops(pid_t child) {
  int status;

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGCONT << 8) | 0x7f));
}

static pid_t fork_child(int block_sigcont, int raise_sigcont) {
  pid_t child;
  sigset_t sigs;
  char ch;

  if (0 == (child = fork())) {
    if (block_sigcont) {
      sigemptyset(&sigs);
      sigaddset(&sigs, SIGCONT);
      test_assert(0 == sigprocmask(SIG_BLOCK, &sigs, NULL));
    }
    if (raise_sigcont) {
      test_assert(0 == kill(getpid(), SIGCONT));
    }
    test_assert(1 == write(from_child_fds[1], "r", 1));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(1 == read(from_child_fds[0], &ch, 1));
  return child;
}

static pid_t start_child(void) {
  pid_t child = fork_child(0, 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  return child;
}

static void let_child_exit(pid_t child) {
  int status;

  test_assert(1 == write(to_child_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void wait_for_notify_stop(pid_t t) {
  int status;
  test_assert(t == waitpid(t, &status, __WALL));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
}

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(from_child_fds[1], &tid, sizeof(tid)));
  test_assert(1 == read(to_thread_fds[0], &ch, 1));
  return NULL;
}

static void finish_child(pid_t child) {
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  let_child_exit(child);
}

int main(void) {
  pid_t child;
  int status;

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));

  /* A tracee that isn't stopped. */
  child = start_child();
  test_assert(0 == kill(child, SIGCONT));
  expect_sigcont_stops(child);
  finish_child(child);

  /* A tracee in a group stop. It stays stopped until we resume it. */
  child = start_child();
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  expect_sigcont_stops(child);
  finish_child(child);

  /* A SIGCONT before the PTRACE_SEIZE. The tracee mustn't stop. (It blocks
     SIGCONT, which keeps the SIGCONT pending.) */
  child = fork_child(1, 0);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  let_child_exit(child);

  /* Same with a SIGCONT that the tracee sent itself. A SIGCONT after the
     PTRACE_SEIZE must give a PTRACE_EVENT_STOP. */
  child = fork_child(1, 1);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  finish_child(child);

  /* A SIGCONT before the PTRACE_SEIZE that a SIGSTOP discards. The first
     stop must be the SIGSTOP's (a group stop, if the tracee stopped before
     the PTRACE_SEIZE). */
  child = fork_child(0, 0);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  /* A SIGCONT while the tracee is at the PTRACE_EVENT_STOP gives another
     one. A detach discards that. */
  child = fork_child(1, 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  wait_for_notify_stop(child);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_notify_stop(child);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  let_child_exit(child);

  /* A SIGCONT for another process doesn't concern our tracee. */
  child = fork_child(1, 0);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  {
    pid_t other = fork_child(0, 0);
    test_assert(0 == kill(other, SIGCONT));
    /* Both read from the same pipe. */
    test_assert(2 == write(to_child_fds[1], "xx", 2));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(other == waitpid(other, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  /* A SIGCONT for one thread notifies the ptracer of another. */
  {
    pthread_t thread;
    pid_t tid;
    char ch;
    test_assert(0 == pipe(to_thread_fds));
    if (0 == (child = fork())) {
      test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
      test_assert(1 == read(to_child_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(sizeof(tid) == read(from_child_fds[0], &tid, sizeof(tid)));
    test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
    test_assert(0 == syscall(SYS_tgkill, child, child, SIGCONT));
    wait_for_notify_stop(tid);
    test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
    test_assert(1 == write(to_thread_fds[1], "x", 1));
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    let_child_exit(child);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
