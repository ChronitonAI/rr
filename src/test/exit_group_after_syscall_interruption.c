/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We ptrace a thread of a child process while it's blocked in pselect6(),
   which the syscall buffer doesn't handle, and interrupt the pselect6()
   with a signal. At the signal-delivery stop we make the thread call
   exit_group() instead of restarting the pselect6(), and detach. rr resumes
   the thread with PTRACE_SYSCALL in case it restarts the pselect6(), so on
   kernels that report the syscall-entry stop before the PTRACE_EVENT_SECCOMP
   stop, rr handles the exit_group()'s entry at the syscall-entry stop, and
   the thread's own PTRACE_EVENT_SECCOMP stop follows. rr must run the
   exit_group() from there.

   In the second child, the process's seccomp filter makes that exit_group()
   raise SIGSYS instead of running. The main thread then calls exit_group(),
   and rr must handle the main thread's PTRACE_EVENT_SECCOMP stop. */

#define VETOED_STATUS 66
#define EXIT_STATUS 77

/* The thread runs exit_group() from here. rr doesn't patch the syscall
   instruction: on x86, none of rr's syscall hooks matches the instruction
   after it, and on aarch64, rr leaves an svc that follows
   `mov x8, 0xdc` alone. The thread never runs that mov, since the parent
   sets its pc to exit_group_insn. */
extern char exit_group_insn __attribute__((visibility("hidden")));
static __attribute__((noinline, used)) void exit_group_insn_holder(void) {
#if defined(__i386__)
  __asm__ __volatile__("exit_group_insn: int $0x80\n\tud2\n\t");
#elif defined(__x86_64__)
  __asm__ __volatile__("exit_group_insn: syscall\n\tud2\n\t");
#elif defined(__aarch64__)
  __asm__ __volatile__("mov x8, 0xdc\n\t"
                       "exit_group_insn: svc #0\n\tbrk #0\n\t");
#else
#error unsupported architecture
#endif
}

static int tid_fds[2];
static int vetoed_fds[2];

static void sigsys_handler(__attribute__((unused)) int sig) {
  char ch = 'v';
  test_assert(1 == write(vetoed_fds[1], &ch, 1));
  while (1) {
    pause();
  }
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, VETOED_STATUS, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(tid_fds[1], &tid, sizeof(tid)));
  syscall(SYS_pselect6, 0, NULL, NULL, NULL, NULL, NULL);
  test_assert(0 && "pselect6() returned");
  return NULL;
}

static void run_child(int veto) {
  pthread_t thread;
  char ch;

  if (veto) {
    struct sigaction sa;
    sa.sa_handler = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    test_assert(0 == sigaction(SIGSYS, &sa, NULL));
    install_filter();
  }
  test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
  if (veto) {
    test_assert(1 == read(vetoed_fds[0], &ch, 1));
    syscall(SYS_exit_group, EXIT_STATUS);
  } else {
    pthread_join(thread, NULL);
  }
  test_assert(0 && "Still alive");
}

static void redirect_to_exit_group(pid_t tid, int status) {
  struct user_regs_struct regs;
  struct iovec iov;

  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  test_assert(0 == ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov));
#if defined(__i386__)
  regs.eip = (uintptr_t)&exit_group_insn;
  regs.eax = SYS_exit_group;
  regs.orig_eax = -1;
  regs.ebx = status;
#elif defined(__x86_64__)
  regs.rip = (uintptr_t)&exit_group_insn;
  regs.rax = SYS_exit_group;
  regs.orig_rax = -1;
  regs.rdi = status;
#elif defined(__aarch64__)
  regs.pc = (uintptr_t)&exit_group_insn;
  regs.regs[8] = SYS_exit_group;
  regs.regs[0] = status;
#endif
  test_assert(0 == ptrace(PTRACE_SETREGSET, tid, (void*)NT_PRSTATUS, &iov));
}

static void run_test(int veto) {
  pid_t child;
  pid_t tid;
  int status;

  test_assert(0 == pipe(tid_fds));
  test_assert(0 == pipe(vetoed_fds));
  if (0 == (child = fork())) {
    run_child(veto);
  }
  test_assert(child > 0);
  test_assert(sizeof(tid) == read(tid_fds[0], &tid, sizeof(tid)));
  test_assert(tid > 1);
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  wait_for_task_asleep_in_syscall(tid, SYS_pselect6, 0);
  /* SIGURG is ignored by default, but a tracee stops for it. */
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGURG));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGURG);
  redirect_to_exit_group(tid, veto ? VETOED_STATUS : EXIT_STATUS);
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_STATUS);
  test_assert(0 == close(tid_fds[0]));
  test_assert(0 == close(tid_fds[1]));
  test_assert(0 == close(vetoed_fds[0]));
  test_assert(0 == close(vetoed_fds[1]));
}

int main(void) {
  run_test(0);
  run_test(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
