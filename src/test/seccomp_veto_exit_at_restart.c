/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"
#include "ptrace_util.h"

/* A tracer interrupts its single-threaded child's read() of a pipe with a
   signal. At the signal-delivery stop it suppresses the signal and changes
   the syscall, so that the kernel restarts the read() as
   exit_group(VETOED_STATUS) in the first child and exit(VETOED_STATUS) in
   the second. The child's seccomp filter makes those fail with E2BIG.

   rr resumes the child with PTRACE_SYSCALL, since the interrupted read()
   may restart, so on kernels that report the syscall-entry stop before the
   PTRACE_EVENT_SECCOMP stop, the exit syscall's syscall-entry stop comes
   before the filter's result. rr must record the exit syscall failing. */

#define VETOED_STATUS 66
#define CHILD_STATUS 77

static int pipe_fds[2];

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, VETOED_STATUS, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E2BIG),
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

static int run_child(void) {
  char ch;
  intptr_t ret;

  install_filter();
  /* The syscall buffer doesn't handle this read(). */
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  test_assert(ret == -E2BIG);
  return CHILD_STATUS;
}

static void run_test(int syscallno) {
  struct user_regs_struct regs;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    exit(run_child());
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, pipe_fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  ptrace_getregs(child, &regs);
  regs.ORIG_SYSCALLNO = syscallno;
  regs.SYSCALL_ARG1 = VETOED_STATUS;
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
  run_test(SYS_exit_group);
  run_test(SYS_exit);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
