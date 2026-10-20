/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"
#include "ptrace_util.h"

/* A tracer interrupts its child's read() of a pipe with a signal. At the
   signal-delivery stop it suppresses the signal and changes the syscall
   number, so that the kernel restarts the read() as an execve(). The
   child's seccomp filter refuses the execve(), with SECCOMP_RET_ERRNO in
   the first child and SECCOMP_RET_TRAP in the second.

   rr resumes the child with PTRACE_SYSCALL, since the interrupted read()
   may restart, so on kernels that report the syscall-entry stop before the
   PTRACE_EVENT_SECCOMP stop, the execve()'s syscall-entry stop comes
   before the filter's result. rr must record the execve() failing. */

#define CHILD_STATUS 77

static int pipe_fds[2];
static volatile int sigsys_syscall = -1;

static void handle_sigsys(__attribute__((unused)) int sig, siginfo_t* si,
                          __attribute__((unused)) void* context) {
  sigsys_syscall = si->si_syscall;
}

static void install_filter(uint32_t action) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, action),
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

static int run_child(uint32_t action) {
  struct sigaction sa;
  char ch;
  intptr_t ret;

  sa.sa_sigaction = handle_sigsys;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSYS, &sa, NULL));
  install_filter(action);

  /* The syscall buffer doesn't handle this read(). */
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  if (action == SECCOMP_RET_TRAP) {
    test_assert(sigsys_syscall == SYS_execve);
  } else {
    test_assert(ret == -E2BIG);
    test_assert(sigsys_syscall == -1);
  }
  return CHILD_STATUS;
}

static void run_test(uint32_t action) {
  struct user_regs_struct regs;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    exit(run_child(action));
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, pipe_fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  ptrace_getregs(child, &regs);
  regs.ORIG_SYSCALLNO = SYS_execve;
  regs.SYSCALL_ARG1 = 0;
  ptrace_setregs(child, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));

  while (1) {
    test_assert(child == waitpid(child, &status, 0));
    if (!WIFSTOPPED(status)) {
      break;
    }
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL,
                            (void*)(uintptr_t)WSTOPSIG(status)));
  }
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == CHILD_STATUS);
}

int main(void) {
  test_assert(0 == pipe(pipe_fds));
  run_test(SECCOMP_RET_ERRNO | E2BIG);
  run_test(SECCOMP_RET_TRAP);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
