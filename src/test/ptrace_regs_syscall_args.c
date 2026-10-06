/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A ptracer has attached to a thread of a child, which is blocked in
   readv() at the lowest scheduling priority. Another thread of the child
   stops the process with SIGSTOP, and the ptracer waits for the thread's
   group-stop and continues the process with SIGCONT, which doesn't end the
   ptrace stop. It writes to the pipe the thread reads from, waits until
   the thread is in a ptrace stop (polling /proc) and reads the thread's
   registers, which must hold readv()'s arguments. (Under rr, the group-stop
   doesn't stop the thread, so its readv() returns and the thread stops at
   the syscall's exit. Once the child's main thread is blocked, the ptracer
   is the only task that isn't, so rr can collect that stop while it runs
   the ptracer. rr must process that stop, which points the second argument
   back from rr's scratch memory to |iov|, before the ptracer reads the
   registers. The race it tests only happens in some recordings.) */

static int tid_pipe[2];
static int thread_pipe[2];
static int main_thread_pipe[2];
static int data_pipe[2];
static char data;
static struct iovec iov = { &data, 1 };

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 19));
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  /* The ptracer has attached to us. */
  test_assert(1 == readv(data_pipe[0], &iov, 1));
  test_assert(data == 'x');
  return NULL;
}

int main(void) {
  pid_t child;
  pid_t tid;
  struct user_regs_struct regs;
  int status;
  pid_t ret;
  char ch = 'x';

  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(thread_pipe));
  test_assert(0 == pipe(main_thread_pipe));
  test_assert(0 == pipe(data_pipe));
  if (0 == (child = fork())) {
    pthread_t t;
    test_assert(0 == pthread_create(&t, NULL, thread_func, NULL));
    test_assert(1 == read(main_thread_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(0 == pthread_join(t, NULL));
    exit(77);
  }
  test_assert(child > 0);
  test_assert(sizeof(tid) == read(tid_pipe[0], &tid, sizeof(tid)));
  test_assert(tid > 1);

  test_assert(0 == ptrace(PTRACE_ATTACH, tid, NULL, NULL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  wait_for_task_asleep_in_syscall(tid, SYS_readv, data_pipe[0]);

  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  while (0 == (ret = waitpid(tid, &status, __WALL | WNOHANG))) {
  }
  test_assert(ret == tid);
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(data_pipe[1], &ch, 1));
  while (get_task_state(tid) != 't') {
  }
  ptrace_getregs(tid, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_readv);
  test_assert((uintptr_t)regs.SYSCALL_ARG2 == (uintptr_t)&iov);

  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
