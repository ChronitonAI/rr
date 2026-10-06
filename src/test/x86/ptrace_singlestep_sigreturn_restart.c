/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

/* The tracee blocks in a read() and a SIGUSR2 with an SA_RESTART handler
   interrupts it. The handler stops the tracee, and its tracer single-steps
   it until it has stepped over the sigreturn syscall. That step must end
   at the read()'s syscall instruction, before the restarted read() runs:
   only then does the tracer write the data that the read() waits for.
   Under rr, the read() can go through rr's syscall hooks. */

static int fds[2];

static void handler(__attribute__((unused)) int sig) {
  syscall(SYS_tgkill, getpid(), sys_gettid(), SIGSTOP);
}

/* Wait until |pid| sleeps, i.e. blocks in its read(). */
static void wait_for_sleep(pid_t pid) {
  struct timespec ts = { 0, 1000000 };
  char path[64];
  sprintf(path, "/proc/%d/stat", pid);
  while (1) {
    char line[1024];
    char* p;
    int fd = open(path, O_RDONLY);
    ssize_t len;
    test_assert(fd >= 0);
    len = read(fd, line, sizeof(line) - 1);
    test_assert(len > 0);
    test_assert(0 == close(fd));
    line[len] = 0;
    p = strrchr(line, ')');
    test_assert(p != NULL);
    if (p[2] == 'S') {
      return;
    }
    nanosleep(&ts, NULL);
  }
}

static int is_syscall_insn(pid_t pid, uintptr_t ip) {
  long insn;
  errno = 0;
  insn = ptrace(PTRACE_PEEKTEXT, pid, (void*)ip, NULL);
  test_assert(errno == 0);
#if defined(__x86_64__)
  return (insn & 0xffff) == 0x050f;
#else
  return (insn & 0xffff) == 0x80cd;
#endif
}

static int is_sigreturn(long syscallno) {
#ifdef SYS_sigreturn
  /* 32-bit glibc returns from a handler without SA_SIGINFO with sigreturn. */
  if (syscallno == SYS_sigreturn) {
    return 1;
  }
#endif
  return syscallno == SYS_rt_sigreturn;
}

int main(void) {
  struct user_regs_struct regs;
  pid_t pid;
  int status;
  int steps = 0;
  char ch;

  test_assert(0 == pipe(fds));
  /* rr doesn't patch syscalls in a task that has a ptracer. Do a read() and
     a tgkill here, so that rr patches them in libc. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(1 == read(fds[0], &ch, 1));
  test_assert(0 == syscall(SYS_tgkill, getpid(), sys_gettid(), SIGWINCH));

  if (0 == (pid = fork())) {
    struct sigaction sa;
    /* If the tracer dies, our read() fails. */
    test_assert(0 == close(fds[1]));
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    test_assert(0 == sigaction(SIGUSR2, &sa, NULL));
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    test_assert(1 == read(fds[0], &ch, 1));
    test_assert(ch == 'y');
    return 77;
  }

  /* If a step blocks, fail instead of hanging: the tracee's read() then
     fails too. */
  alarm(30);

  wait_for_sleep(pid);
  test_assert(0 == kill(pid, SIGUSR2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR2);
  /* Run the handler, which stops the tracee. */
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, (void*)SIGUSR2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  while (1) {
    int sigreturn;
    ptrace_getregs(pid, &regs);
    sigreturn = is_syscall_insn(pid, (uintptr_t)regs.IP) &&
                is_sigreturn((long)regs.SYSCALL_RESULT);
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    test_assert(++steps < 100000);
    if (sigreturn) {
      break;
    }
  }
  /* The step over sigreturn ends at the syscall instruction of the
     interrupted read(). */
  ptrace_getregs(pid, &regs);
  test_assert(is_syscall_insn(pid, (uintptr_t)regs.IP));
  test_assert(regs.SYSCALL_RESULT == SYS_read);

  test_assert(1 == write(fds[1], "y", 1));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
