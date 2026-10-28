/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_ERESTARTSYS 512

/* A ptracer follows a thread of a child with PTRACE_SYSCALL. The thread is
   blocked in readv() when the child's main thread stops the process with
   SIGSTOP, which interrupts the readv(). The ptracer must get one exit of
   the interrupted readv() and one group stop. Linux reports the exit
   first. rr reports the group stop first, at once, while the thread is
   still in the readv(), and stops the thread when the ptracer reads its
   registers, which the ptracer does at every stop. From the group stop
   on, the ptracer resumes the thread with PTRACE_SYSCALL, and after both
   stops must get the entry and exit of the restarted readv(); or with
   PTRACE_CONT, and after both stops must get no stop before it
   interrupts the restarted readv(). It seizes the thread, or attaches to
   it. The syscall buffer doesn't handle readv(). */

static int tid_pipe[2];
static int go_pipe[2];
static int main_thread_pipe[2];
static int data_pipe[2];

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  struct iovec iov;
  char ch;

  iov.iov_base = &ch;
  iov.iov_len = 1;
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  /* The ptracer attaches to us while we wait here. */
  test_assert(1 == readv(go_pipe[0], &iov, 1));
  test_assert(1 == readv(data_pipe[0], &iov, 1));
  test_assert(ch == 'x');
  return NULL;
}

static int syscall_stop_status(void) {
  return ((SIGTRAP | 0x80) << 8) | 0x7f;
}

static int event_stop_status(int sig) {
  return (PTRACE_EVENT_STOP << 16) | (sig << 8) | 0x7f;
}

static int group_stop_status(int seize) {
  return seize ? event_stop_status(SIGSTOP) : ((SIGSTOP << 8) | 0x7f);
}

static void wait_for_stop(pid_t tid, struct user_regs_struct* regs,
                          int* status) {
  test_assert(tid == waitpid(tid, status, __WALL));
  test_assert(WIFSTOPPED(*status));
  ptrace_getregs(tid, regs);
}

static void run(int seize, int cont_command) {
  pid_t child;
  pid_t tid;
  struct user_regs_struct regs;
  int status;
  int saw_exit = 0;
  int saw_group_stop = 0;

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

  wait_for_task_asleep_in_syscall(tid, SYS_readv, go_pipe[0]);
  if (seize) {
    test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL,
                            (void*)PTRACE_O_TRACESYSGOOD));
    test_assert(0 == ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(status == event_stop_status(SIGTRAP));
  } else {
    test_assert(0 == ptrace(PTRACE_ATTACH, tid, NULL, NULL));
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_SETOPTIONS, tid, NULL,
                            (void*)PTRACE_O_TRACESYSGOOD));
  }

  /* Follow the thread to the entry of its readv() from |data_pipe|. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
  test_assert(1 == write(go_pipe[1], "g", 1));
  while (1) {
    wait_for_stop(tid, &regs, &status);
    test_assert(status == syscall_stop_status());
    test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
    if ((long)regs.SYSCALL_ARG1 == data_pipe[0]) {
      break;
    }
    test_assert(0 == ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
  }
  test_assert(0 == ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
  wait_for_task_asleep_in_syscall(tid, SYS_readv, data_pipe[0]);

  test_assert(1 == write(main_thread_pipe[1], "s", 1));
  while (1) {
    wait_for_stop(tid, &regs, &status);
    if (status == syscall_stop_status()) {
      test_assert(!saw_exit);
      test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
      test_assert((long)regs.SYSCALL_RESULT == -RR_ERESTARTSYS);
      saw_exit = 1;
    } else {
      test_assert(!saw_group_stop);
      test_assert(status == group_stop_status(seize));
      saw_group_stop = 1;
    }
    if (saw_exit && saw_group_stop) {
      break;
    }
    test_assert(0 == ptrace(saw_group_stop ? cont_command : PTRACE_SYSCALL,
                            tid, NULL, NULL));
  }

  if (cont_command == PTRACE_SYSCALL) {
    /* Follow the restarted readv(). */
    int saw_entry = 0;
    test_assert(0 == kill(child, SIGCONT));
    test_assert(1 == write(data_pipe[1], "x", 1));
    while (1) {
      test_assert(0 == ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
      wait_for_stop(tid, &regs, &status);
      if (status != syscall_stop_status()) {
        /* What SIGCONT brings. */
        test_assert(status == ((SIGCONT << 8) | 0x7f) ||
                    (seize && status == event_stop_status(SIGTRAP)));
        continue;
      }
      test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
      if (!saw_entry) {
        test_assert((long)regs.SYSCALL_ARG1 == data_pipe[0]);
        saw_entry = 1;
      } else {
        test_assert((long)regs.SYSCALL_RESULT == 1);
        break;
      }
    }
  } else {
    /* The readv() restarts and blocks. */
    test_assert(0 == ptrace(cont_command, tid, NULL, NULL));
    wait_for_task_asleep_in_syscall(tid, SYS_readv, data_pipe[0]);
    test_assert(0 == ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(status == event_stop_status(SIGSTOP));
    test_assert(0 == kill(child, SIGCONT));
    test_assert(1 == write(data_pipe[1], "x", 1));
  }

  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(0 == close(tid_pipe[0]));
  test_assert(0 == close(tid_pipe[1]));
  test_assert(0 == close(go_pipe[0]));
  test_assert(0 == close(go_pipe[1]));
  test_assert(0 == close(main_thread_pipe[0]));
  test_assert(0 == close(main_thread_pipe[1]));
  test_assert(0 == close(data_pipe[0]));
  test_assert(0 == close(data_pipe[1]));
}

int main(void) {
  run(1, PTRACE_SYSCALL);
  run(0, PTRACE_SYSCALL);
  /* PTRACE_INTERRUPT needs a seized thread. */
  run(1, PTRACE_CONT);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
