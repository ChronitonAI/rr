/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A ptracer has attached to a thread of a child, which is blocked in
   read(). Another thread of the child stops the child with SIGSTOP, and the
   ptracer waits for the thread's group-stop and reads its registers.
   Meanwhile another thread of the ptracer stops the ptracer's process with
   SIGSTOP, and then our main thread continues it with SIGCONT. The read of
   the registers must succeed. (Under rr, the group-stop doesn't stop the
   thread right away, and the ptracer can still be waiting to make its
   PTRACE_GETREGS when its own process stops; scheduling priorities make rr
   stop the thread only after that.) */

static pid_t main_tid;
static int about_to_get_regs;
static int got_regs;
static int tid_pipe[2];
static int thread_pipe[2];
static int main_thread_pipe[2];

static void* stopper(__attribute__((unused)) void* p) {
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 10));
  /* Natively, wait until the main thread has the registers. Under rr, it
     may still be waiting to make its PTRACE_GETREGS (in a ptrace-stop for
     rr). */
  while (!__atomic_load_n(&about_to_get_regs, __ATOMIC_SEQ_CST) ||
         !(__atomic_load_n(&got_regs, __ATOMIC_SEQ_CST) ||
           get_task_state(main_tid) == 't')) {
  }
  raise(SIGSTOP);
  return NULL;
}

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 15));
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  /* The ptracer has attached to us. */
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  return NULL;
}

static int ptracer(void) {
  pid_t tracee_process;
  pid_t tid;
  pthread_t thread;
  struct user_regs_struct regs;
  int status;
  pid_t ret;
  char ch = 'x';

  main_tid = sys_gettid();
  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(thread_pipe));
  test_assert(0 == pipe(main_thread_pipe));
  if (0 == (tracee_process = fork())) {
    pthread_t t;
    test_assert(0 == pthread_create(&t, NULL, thread_func, NULL));
    test_assert(1 == read(main_thread_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(0 == pthread_join(t, NULL));
    exit(77);
  }
  test_assert(tracee_process > 0);
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

  test_assert(0 == pthread_create(&thread, NULL, stopper, NULL));
  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  while (0 == (ret = waitpid(tid, &status, __WALL | WNOHANG))) {
  }
  test_assert(ret == tid);
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  __atomic_store_n(&about_to_get_regs, 1, __ATOMIC_SEQ_CST);
  ptrace_getregs(tid, &regs);
  __atomic_store_n(&got_regs, 1, __ATOMIC_SEQ_CST);
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
  test_assert(0 == pthread_join(thread, NULL));

  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(0 == kill(tracee_process, SIGCONT));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  test_assert(tracee_process == waitpid(tracee_process, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  return 66;
}

int main(void) {
  pid_t child;
  siginfo_t si;
  int status;

  if (0 == (child = fork())) {
    exit(ptracer());
  }
  test_assert(child > 0);
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 19));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED));
  test_assert(si.si_pid == child);
  test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
