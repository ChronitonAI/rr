/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* waitid() reports a ptrace stop or exit with the tracee's tid and, for
   every kind of ptrace stop, CLD_TRAPPED:
   - the signal-delivery stop and the exit of a traced thread that isn't
     its process's main thread;
   - the group stop of a child that stops itself after we seized it;
   - the stop of a child that we attach to while it is stopped. */

static int ready_fds[2];

static void* child_thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(ready_fds[1], &tid, sizeof(tid)));
  for (;;) {
    pause();
  }
  return NULL;
}

static void check_siginfo(siginfo_t* si, pid_t pid, int code, int status) {
  test_assert(si->si_signo == SIGCHLD);
  test_assert(si->si_pid == pid);
  test_assert(si->si_code == code);
  test_assert(si->si_status == status);
}

static void traced_thread(void) {
  pthread_t thread;
  siginfo_t si;
  pid_t child;
  pid_t tid;
  int status;

  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, child_thread_main, NULL));
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(sizeof(tid) == read(ready_fds[0], &tid, sizeof(tid)));
  test_assert(tid > 1);
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));

  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGUSR1));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, tid, &si, WSTOPPED | __WALL));
  check_siginfo(&si, tid, CLD_TRAPPED, SIGUSR1);

  test_assert(0 == kill(child, SIGKILL));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, tid, &si, WEXITED | __WALL));
  check_siginfo(&si, tid, CLD_KILLED, SIGKILL);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void seized_group_stop(void) {
  int seized_fds[2];
  siginfo_t si;
  pid_t child;
  int status;
  char ch;

  test_assert(0 == pipe(seized_fds));
  if (0 == (child = fork())) {
    test_assert(1 == read(seized_fds[0], &ch, 1));
    kill(getpid(), SIGSTOP);
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(seized_fds[1], "s", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED));
  check_siginfo(&si, child, CLD_TRAPPED, (PTRACE_EVENT_STOP << 8) | SIGSTOP);

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(0 == close(seized_fds[0]));
  test_assert(0 == close(seized_fds[1]));
}

static void attach_to_stopped_child(void) {
  siginfo_t si;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED));
  check_siginfo(&si, child, CLD_TRAPPED, SIGSTOP);

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
  test_assert(0 == pipe(ready_fds));
  traced_thread();
  seized_group_stop();
  attach_to_stopped_child();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
