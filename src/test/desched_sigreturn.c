/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

pid_t main_thread_tid;
int fds[2];
char zeros[8192];

void sigproc_and_hang(void) {
  sigset_t sigs;
  sigfillset(&sigs);
  sigdelset(&sigs, SIGUSR2);
  sigprocmask(SIG_SETMASK, &sigs, NULL);
  /* Fill the pipe until a write blocks. The signal handler leaves this
     function. */
  while (1) {
    write(fds[1], &zeros, sizeof(zeros));
  }
}

void print_and_exit(void) {
  atomic_printf("EXIT-SUCCESS\n");
  exit(0);
}

int counter;
void usr2_handler(__attribute__((unused)) int signum,
                  __attribute__((unused)) siginfo_t* siginfo_ptr,
                  void* ucontext_ptr) {
  uintptr_t target = __atomic_fetch_add(&counter, 1, __ATOMIC_SEQ_CST) == 0
                         ? (uintptr_t)&sigproc_and_hang
                         : (uintptr_t)&print_and_exit;
#if defined(__i386__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)target;
#elif defined(__x86_64__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.gregs[REG_RIP] = (long long)target;
#elif defined(__aarch64__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.pc = (long)target;
#else
#error "Unsupported architecture"
#endif
}

static void* signaler_thread(__attribute__((unused)) void* p) {
  pid_t tid = __atomic_load_n(&main_thread_tid, __ATOMIC_SEQ_CST);
  test_assert(tid > 1);
  wait_for_task_asleep_in_syscall(tid, SYS_read, fds[0]);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR2));
  wait_for_task_asleep_in_syscall(tid, SYS_write, fds[1]);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR2));
  return NULL;
}

int main(void) {
  int err = pipe(fds);
  test_assert(err == 0);

  err = fcntl(fds[1], F_SETPIPE_SZ, 4096);
  test_assert(err > 0);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = usr2_handler;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_RESTART;
  err = sigaction(SIGUSR2, &sa, NULL);
  test_assert(err == 0);

  __atomic_store_n(&main_thread_tid, sys_gettid(), __ATOMIC_SEQ_CST);

  pthread_t thread;
  test_assert(0 == pthread_create(&thread, NULL, signaler_thread, NULL));

  // Block on pipe read.
  int ch = 0;
  err = read(fds[0], &ch, sizeof(int));
  test_assert(0);

  return 0;
}
