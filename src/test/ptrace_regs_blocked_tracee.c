/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A thread of a child, at the lowest scheduling priority, is blocked in
   read() when another thread of its process stops the process with SIGSTOP,
   and a ptracer reads the thread's registers at its group-stop. In the
   first case, the ptracer has attached to the thread before the process
   stops. In the second, it attaches to the thread of the stopped process.
   The ptracer polls with WNOHANG, so that it never blocks. (Under rr, the
   group-stop doesn't stop the thread right away, and rr's scheduler doesn't
   look at the thread while the ptracer can run.) */

static int tid_pipe[2];
static int thread_pipe[2];
static int main_thread_pipe[2];

static void* thread_func(void* p) {
  int reads = (int)(uintptr_t)p;
  pid_t tid = sys_gettid();
  char ch;
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 19));
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  while (reads-- > 0) {
    test_assert(1 == read(thread_pipe[0], &ch, 1));
  }
  return NULL;
}

/* Fork a child whose second thread reads |reads| bytes from thread_pipe and
   whose main thread stops the process when it reads from main_thread_pipe.
   Returns the child's pid and stores the thread's tid in |*tid|. */
static pid_t fork_child(int reads, pid_t* tid) {
  pid_t child;
  char ch;

  if (0 == (child = fork())) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, thread_func,
                                    (void*)(uintptr_t)reads));
    test_assert(1 == read(main_thread_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(0 == pthread_join(thread, NULL));
    exit(77);
  }
  test_assert(child > 0);
  test_assert(sizeof(*tid) == read(tid_pipe[0], tid, sizeof(*tid)));
  test_assert(*tid > 1);
  return child;
}

/* Wait for the SIGSTOP stop of tracee |tid|. */
static void wait_for_ptrace_stop(pid_t tid) {
  int status;
  pid_t ret;
  while (0 == (ret = waitpid(tid, &status, __WALL | WNOHANG))) {
  }
  test_assert(ret == tid);
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
}

/* Wait for the group-stop of process |child|. */
static void wait_for_process_stop(pid_t child) {
  siginfo_t si;
  do {
    memset(&si, 0, sizeof(si));
    test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOHANG));
  } while (si.si_pid == 0);
  test_assert(si.si_pid == child);
  test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
}

static void check_regs(pid_t tid) {
  struct user_regs_struct regs;
  ptrace_getregs(tid, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
}

static void finish(pid_t child) {
  int status;
  char ch = 'x';
  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void attach_then_stop(void) {
  pid_t tid;
  pid_t child = fork_child(2, &tid);
  int status;
  char ch = 'x';

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
  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  wait_for_ptrace_stop(tid);
  check_regs(tid);
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  finish(child);
}

static void stop_then_attach(void) {
  pid_t tid;
  pid_t child = fork_child(1, &tid);
  char ch = 'x';

  wait_for_task_asleep_in_syscall(tid, SYS_read, thread_pipe[0]);
  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  wait_for_process_stop(child);
  test_assert(0 == ptrace(PTRACE_ATTACH, tid, NULL, NULL));
  wait_for_ptrace_stop(tid);
  check_regs(tid);
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  finish(child);
}

int main(void) {
  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(thread_pipe));
  test_assert(0 == pipe(main_thread_pipe));

  attach_then_stop();
  stop_then_attach();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
