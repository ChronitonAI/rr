/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* Waits of a tracer for the threads of its child that it traces:
   - A ptrace stop of a traced thread isn't a job-control stop of the child
     process, so waitpid(child, WUNTRACED) doesn't report it.
   - A wait from another thread of the tracer reports and consumes one
     ptrace stop.
   The tracer kills the child at the end, without letting it get the
   SIGUSR1s.
   Then a tracer that traces just the main thread of its child stops the
   child with SIGSTOP and kills it. It must get the child's exit, although
   it never waited for the child's job-control stop.
   Finally a tracer traces the second thread of a child whose main thread
   has exited, and stops the child. A waitid() with WNOWAIT for the child's
   job-control stop must leave it for the next waitid(). */

static int to_child_fds[2];
static int from_child_fds[2];
static pid_t child;
static pid_t tid;

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t my_tid = sys_gettid();
  char ch;
  test_assert(sizeof(my_tid) ==
              write(from_child_fds[1], &my_tid, sizeof(my_tid)));
  test_assert(1 == read(to_child_fds[0], &ch, 1));
  return NULL;
}

static void wait_for_sigusr1_stop(pid_t t) {
  int status;
  test_assert(t == waitpid(t, &status, __WALL));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
}

static void* waiter_main(__attribute__((unused)) void* p) {
  wait_for_sigusr1_stop(tid);
  wait_for_sigusr1_stop(child);
  return NULL;
}

static void kill_stopped_child(void) {
  pthread_t thread;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(sizeof(tid) == read(from_child_fds[0], &tid, sizeof(tid)));

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* Returns true if |pid|'s main thread is a zombie. */
static int main_thread_exited(pid_t pid) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/stat", pid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  return p[2] == 'Z';
}

static void wait_nowait_with_exited_main_thread(void) {
  pthread_t thread;
  siginfo_t si;
  int status;

  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    pthread_exit(NULL);
  }
  test_assert(sizeof(tid) == read(from_child_fds[0], &tid, sizeof(tid)));
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  while (!main_thread_exited(child)) {
    sched_yield();
  }

  test_assert(0 == kill(child, SIGSTOP));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, (void*)SIGSTOP));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT));
  test_assert(si.si_pid == child && si.si_code == CLD_STOPPED);
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOHANG));
  test_assert(si.si_pid == child && si.si_code == CLD_STOPPED);

  test_assert(0 == kill(child, SIGKILL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
  pthread_t thread;
  siginfo_t si;
  int status;
  char ch;

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));

  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    return 77;
  }
  test_assert(sizeof(tid) == read(from_child_fds[0], &tid, sizeof(tid)));

  /* A signal-delivery stop of the second thread. Wait until it's there
     without consuming it. */
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGUSR1));
  test_assert(0 == waitid(P_PID, tid, &si, WSTOPPED | WNOWAIT | __WALL));
  test_assert(0 == waitpid(child, &status, WUNTRACED | WNOHANG));
  wait_for_sigusr1_stop(tid);

  /* Signal-delivery stops of both threads, which another thread of ours
     waits for. */
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGUSR1));
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGUSR1));
  test_assert(0 == pthread_create(&thread, NULL, waiter_main, NULL));
  test_assert(0 == pthread_join(thread, NULL));

  test_assert(0 == kill(child, SIGKILL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  kill_stopped_child();
  wait_nowait_with_exited_main_thread();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
