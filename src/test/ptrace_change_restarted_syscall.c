/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_syscall.h"
#include "ptrace_util.h"

/* A tracer interrupts its child's read() of a pipe with a signal. At the
   signal-delivery stop it suppresses the signal and changes the syscall,
   so that the kernel restarts the read() as another syscall:
   - fork() (clone(SIGCHLD, 0, ...) on aarch64), which must create a
     process;
   - execve(NULL, ...), which the child's seccomp filter refuses with
     SECCOMP_RET_ERRNO (E2BIG) or SECCOMP_RET_TRAP;
   - exit_group(VETOED_STATUS) or exit(VETOED_STATUS), which the
     single-threaded child's seccomp filter makes fail with E2BIG.

   rr resumes the child with PTRACE_SYSCALL, since the interrupted read()
   may restart, so on kernels that report the syscall-entry stop before the
   PTRACE_EVENT_SECCOMP stop, the new syscall's syscall-entry stop comes
   before the filter's result. rr must record what the syscall does. */

#define VETOED_STATUS 66
#define CHILD_STATUS 77
#define GRANDCHILD_STATUS 78

enum Restart { FORK, EXECVE_ERRNO, EXECVE_TRAP, EXIT_GROUP, EXIT };

static int pipe_fds[2];
static volatile int sigsys_syscall = -1;

static void handle_sigsys(__attribute__((unused)) int sig, siginfo_t* si,
                          __attribute__((unused)) void* context) {
  sigsys_syscall = si->si_syscall;
}

static void install_filter(enum Restart restart) {
  struct sock_filter execve_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K,
             restart == EXECVE_TRAP ? SECCOMP_RET_TRAP
                                    : SECCOMP_RET_ERRNO | E2BIG),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_filter exit_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, VETOED_STATUS, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E2BIG),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog;
  int ret;

  if (restart == EXECVE_ERRNO || restart == EXECVE_TRAP) {
    prog.len = (unsigned short)(sizeof(execve_filter) /
                                sizeof(execve_filter[0]));
    prog.filter = execve_filter;
  } else {
    prog.len = (unsigned short)(sizeof(exit_filter) / sizeof(exit_filter[0]));
    prog.filter = exit_filter;
  }
  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

static int run_child(enum Restart restart) {
  struct sigaction sa;
  char ch;
  intptr_t ret;
  int status;

  sa.sa_sigaction = handle_sigsys;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSYS, &sa, NULL));
  if (restart != FORK) {
    install_filter(restart);
  }

  /* The syscall buffer doesn't handle this read(). */
  ret = unbufferable_syscall(SYS_read, pipe_fds[0], (uintptr_t)&ch, 1);
  switch (restart) {
    case FORK:
      if (ret == 0) {
        return GRANDCHILD_STATUS;
      }
      test_assert(ret > 0);
      test_assert(ret == waitpid(ret, &status, 0));
      test_assert(WIFEXITED(status) &&
                  WEXITSTATUS(status) == GRANDCHILD_STATUS);
      break;
    case EXECVE_TRAP:
      test_assert(sigsys_syscall == SYS_execve);
      break;
    default:
      test_assert(ret == -E2BIG);
      test_assert(sigsys_syscall == -1);
      break;
  }
  return CHILD_STATUS;
}

static void run_test(enum Restart restart) {
  struct user_regs_struct regs;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    exit(run_child(restart));
  }
  test_assert(child > 0);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, pipe_fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  ptrace_getregs(child, &regs);
  switch (restart) {
    case FORK:
#if defined(__aarch64__)
      regs.ORIG_SYSCALLNO = SYS_clone;
      regs.regs[0] = SIGCHLD;
      regs.regs[1] = 0;
      regs.regs[2] = 0;
      regs.regs[3] = 0;
      regs.regs[4] = 0;
#else
      regs.ORIG_SYSCALLNO = SYS_fork;
#endif
      break;
    case EXECVE_ERRNO:
    case EXECVE_TRAP:
      regs.ORIG_SYSCALLNO = SYS_execve;
      regs.SYSCALL_ARG1 = 0;
      break;
    case EXIT_GROUP:
      regs.ORIG_SYSCALLNO = SYS_exit_group;
      regs.SYSCALL_ARG1 = VETOED_STATUS;
      break;
    case EXIT:
      regs.ORIG_SYSCALLNO = SYS_exit;
      regs.SYSCALL_ARG1 = VETOED_STATUS;
      break;
  }
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
  run_test(FORK);
  run_test(EXECVE_ERRNO);
  run_test(EXECVE_TRAP);
  run_test(EXIT_GROUP);
  run_test(EXIT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
