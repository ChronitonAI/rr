/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* A child is traced by a ptracer that is not its parent (a sibling), and
   stops in a group-stop. Its real parent must be able to wait for that
   group-stop (once) and get a SIGCHLD for it, and the ptracer must still get
   its own notification of the stop. Then the parent traces only the second
   thread of another child, and that child stops: the parent's wait for the
   child must report the stop too, since Linux only looks at the child's
   main thread there. */

static volatile int handler_ran;
static siginfo_t handler_si;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  handler_si = *si;
  handler_ran = 1;
}

static void ptracer_is_sibling(void) {
  pid_t child;
  pid_t ptracer;
  int status;
  int ready_pipe[2];
  int go_pipe[2];
  int ran_pipe[2];
  int exit_pipe[2];
  int to_ptracer[2];
  int to_parent[2];
  char ch = 'x';
  siginfo_t si;
  struct sigaction sa;
  sigset_t mask;
  sigset_t unblocked;

  /* We check the SIGCHLD in sigsuspend() below. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigemptyset(&unblocked);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(ran_pipe));
  test_assert(0 == pipe(to_ptracer));
  test_assert(0 == pipe(to_parent));
  test_assert(0 == pipe(exit_pipe));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(1 == write(ran_pipe[1], &ch, 1));
    exit(77);
  }

  /* Only the child keeps exit_pipe open for writing. */
  test_assert(0 == close(exit_pipe[1]));
  /* Make sure the prctl has happened before the ptracer attaches. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  if (0 == (ptracer = fork())) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    /* Let the SIGSTOP put the child into a group-stop. */
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
    test_assert(1 == write(to_parent[1], &ch, 1));
    /* Wait until the parent has waited for the stop. */
    test_assert(1 == read(to_ptracer[0], &ch, 1));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
    /* Let the child run on, then exit. */
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    test_assert(1 == read(to_ptracer[0], &ch, 1));
    exit(44);
  }

  test_assert(1 == read(to_parent[0], &ch, 1));
  /* The ptracer hasn't waited for the group-stop yet. */
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT));
  test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
  test_assert(si.si_pid == child);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == waitpid(child, &status, WUNTRACED | WNOHANG));
  while (!handler_ran) {
    sigsuspend(&unblocked);
  }
  test_assert(handler_si.si_code == CLD_STOPPED);
  test_assert(handler_si.si_pid == child);
  test_assert(1 == write(to_ptracer[1], &ch, 1));

  /* The ptracer resumes the child, which exits. The child's process is
     still stopped, so if the child weren't exiting yet when the ptracer
     exits, it would stop again. When we see the end of exit_pipe, it is. */
  test_assert(1 == read(ran_pipe[0], &ch, 1));
  test_assert(0 == read(exit_pipe[0], &ch, 1));
  test_assert(1 == write(to_ptracer[1], &ch, 1));
  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static volatile pid_t* thread_tid;
static volatile int thread_done;

static void* thread_func(__attribute__((unused)) void* p) {
  /* Don't be in a syscall while the process is stopped. */
  *thread_tid = sys_gettid();
  while (!thread_done) {
  }
  return NULL;
}

static void parent_traces_other_thread(void) {
  pid_t child;
  pid_t tid;
  int status;
  int go_pipe[2];
  char ch = 'x';

  thread_tid =
      (volatile pid_t*)mmap(NULL, sizeof(pid_t), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(thread_tid != MAP_FAILED);
  *thread_tid = 0;
  test_assert(0 == pipe(go_pipe));
  if (0 == (child = fork())) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, thread_func, NULL));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    raise(SIGSTOP);
    thread_done = 1;
    test_assert(0 == pthread_join(thread, NULL));
    exit(77);
  }

  while (!(tid = *thread_tid)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(1 == write(go_pipe[1], &ch, 1));
  /* The main thread stops first, so the group-stop is complete once the
     thread reports its stop. (Linux doesn't wake a real parent that waits
     for the child when the last thread to stop is one that it traces.) */
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  ptracer_is_sibling();
  parent_traces_other_thread();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
