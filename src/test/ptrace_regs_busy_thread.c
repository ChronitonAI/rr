/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A ptracer has attached to a thread of a child, which is blocked in read()
   at the lowest scheduling priority. Another thread of the child stops the
   process with SIGSTOP, and the ptracer waits for the thread's group-stop
   and reads its registers. Meanwhile another thread of the ptracer counts
   until the ptracer has the registers. (Under rr, the group-stop doesn't
   stop the thread right away, so the ptracer's PTRACE_GETREGS waits until
   rr has stopped it, and rr must get to the thread although the counting
   thread, which has a higher priority, can always run.) */

static int tid_pipe[2];
static int thread_pipe[2];
static int main_thread_pipe[2];
static int got_regs;
static volatile unsigned long counter;

static void* count(__attribute__((unused)) void* p) {
  while (!__atomic_load_n(&got_regs, __ATOMIC_SEQ_CST)) {
    ++counter;
  }
  return NULL;
}

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 19));
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  /* The ptracer has attached to us. */
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  return NULL;
}

int main(void) {
  pid_t child;
  pid_t tid;
  pthread_t thread;
  struct user_regs_struct regs;
  int status;
  pid_t ret;
  char ch = 'x';

  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(thread_pipe));
  test_assert(0 == pipe(main_thread_pipe));
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
  /* Let the thread block in its second read() before its process stops. */
  wait_for_task_asleep_in_syscall(tid, SYS_read, thread_pipe[0]);
  {
    /* Make sure the read is the second one: the first has returned once the
       pipe is empty. */
    int n;
    do {
      test_assert(0 == ioctl(thread_pipe[0], FIONREAD, &n));
    } while (n > 0);
    wait_for_task_asleep_in_syscall(tid, SYS_read, thread_pipe[0]);
  }

  test_assert(0 == pthread_create(&thread, NULL, count, NULL));
  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  while (0 == (ret = waitpid(tid, &status, __WALL | WNOHANG))) {
  }
  test_assert(ret == tid);
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  ptrace_getregs(tid, &regs);
  __atomic_store_n(&got_regs, 1, __ATOMIC_SEQ_CST);
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
  test_assert(0 == pthread_join(thread, NULL));

  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
