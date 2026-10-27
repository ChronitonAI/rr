/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"

/* The main thread blocks in a read() of a pipe, which it makes with
   unbufferable_syscall() so that the syscall buffer doesn't handle it. A
   signal interrupts the read(), and the signal's SA_RESTART handler
   installs a seccomp filter that makes read()s of that pipe fail with
   ERRNO_RESULT. The read() restarts and fails.

   rr resumes the main thread with PTRACE_SYSCALL after the handler, since
   the interrupted read() may restart. On kernels that report the
   syscall-entry stop before the PTRACE_EVENT_SECCOMP stop, the filter's
   result comes after the syscall-entry stop of the restarted read(). rr
   must record the read() failing with ERRNO_RESULT. */

#define ERRNO_RESULT E2BIG

static int pipe_fds[2];
static pid_t main_tid;

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, pipe_fds[0], 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_RESULT),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

static void handle_usr1(__attribute__((unused)) int sig) { install_filter(); }

static void* signal_thread(__attribute__((unused)) void* p) {
  wait_for_task_asleep_in_syscall(main_tid, SYS_read, pipe_fds[0]);
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1));
  return NULL;
}

int main(void) {
  struct sigaction sa;
  pthread_t thread;
  char ch;
  intptr_t ret;

  test_assert(0 == pipe(pipe_fds));
  sa.sa_handler = handle_usr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

  main_tid = sys_gettid();
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  test_assert(ret == -ERRNO_RESULT);
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
