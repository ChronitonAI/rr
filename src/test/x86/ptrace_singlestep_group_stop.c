/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_ERESTARTSYS 512

/* A ptracer single-steps a thread of a child into a readv() that blocks,
   and the child's main thread stops the process with SIGSTOP, which
   interrupts the readv(). Linux reports the thread's group stop after the
   readv() exits, and then the single-step's SIGTRAP. rr reports the group
   stop at once, while the thread is still in the readv(), and stops the
   thread when the ptracer reads its registers. The syscall buffer doesn't
   handle readv(). */

static int tid_pipe[2];
static int go_pipe[2];
static int main_thread_pipe[2];
static int data_pipe[2];

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  struct iovec iov;
  long ret;
  char ch;

  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  /* Wait until the ptracer has seized us. */
  test_assert(1 == read(go_pipe[0], &ch, 1));
  iov.iov_base = &ch;
  iov.iov_len = 1;
  /* The ptracer single-steps from the int3 into the syscall. */
#if defined(__x86_64__)
  __asm__ __volatile__("int3\n\t"
                       "syscall\n\t"
                       : "=a"(ret)
                       : "a"(SYS_readv), "D"(data_pipe[0]), "S"(&iov), "d"(1)
                       : "rcx", "r11", "memory");
#else
  __asm__ __volatile__("int3\n\t"
                       "int $0x80\n\t"
                       : "=a"(ret)
                       : "a"(SYS_readv), "b"(data_pipe[0]), "c"(&iov), "d"(1)
                       : "memory");
#endif
  test_assert(ret == 1);
  test_assert(ch == 'x');
  return NULL;
}

static void wait_for_stop(pid_t tid, int expected_status) {
  int status;
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(status == expected_status);
}

/* The thread is at the exit of the interrupted readv(). */
static void check_regs(pid_t tid) {
  struct user_regs_struct regs;
  ptrace_getregs(tid, &regs);
  test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
  test_assert((long)regs.SYSCALL_RESULT == -RR_ERESTARTSYS);
}

int main(void) {
  pid_t child;
  pid_t tid;
  int status;

  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(main_thread_pipe));
  test_assert(0 == pipe(data_pipe));
  if (0 == (child = fork())) {
    pthread_t t;
    char ch;
    test_assert(0 == pthread_create(&t, NULL, thread_func, NULL));
    test_assert(1 == read(main_thread_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(0 == pthread_join(t, NULL));
    exit(77);
  }
  test_assert(child > 1);
  test_assert(sizeof(tid) == read(tid_pipe[0], &tid, sizeof(tid)));
  test_assert(tid > 1);

  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(1 == write(go_pipe[1], "g", 1));
  wait_for_stop(tid, (SIGTRAP << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL));
  wait_for_task_asleep_in_syscall(tid, SYS_readv, data_pipe[0]);

  test_assert(1 == write(main_thread_pipe[1], "s", 1));
  wait_for_stop(tid, (PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f);
  check_regs(tid);
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  wait_for_stop(tid, (SIGTRAP << 8) | 0x7f);
  check_regs(tid);

  /* The readv() restarts. */
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(data_pipe[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
