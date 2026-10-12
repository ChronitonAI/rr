/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* The kernel forces the SIGTRAP of a single-step: if SIGTRAP is blocked or
   ignored, it unblocks it and resets its handler to SIG_DFL. A tracer
   single-steps its tracee, which has SIGTRAP blocked:
   1. with a SIGTRAP handler, over an ordinary instruction;
   2. (x86) with a SIGTRAP handler, over a syscall instruction;
   3. (x86) with a SIGTRAP handler, over an rt_sigsuspend() whose temporary
      mask blocks SIGTRAP, which a SIGUSR1 interrupts. After the SIGUSR1
      handler, the tracee must have its original mask again. (Natively,
      SIGTRAP's handler is SIG_DFL then. rr doesn't emulate that, so we
      don't check it.);
   4. (x86) with a SIGTRAP handler, over a read() that a SIGUSR1
      interrupts. The step starts at the read()'s syscall-entry stop;
   5. (x86) the same with a ppoll() without a signal mask;
   6. with SIGTRAP ignored, over an ordinary instruction. Then the tracer
      resumes the tracee with SIGTRAP, which kills it.
   After 1, 2, 4 and 5, the tracee checks that SIGTRAP is unblocked and
   that its handler is SIG_DFL. */

static volatile int handled;
static volatile int usr1_handled;
static int fds[2];

static void handler(__attribute__((unused)) int sig) { ++handled; }

static void usr1_handler(__attribute__((unused)) int sig) { ++usr1_handled; }

#if defined(__x86_64__) || defined(__i386__)
extern char step_syscall[];
extern char step_syscall_end[];

/* The tracer runs this syscall instruction with a getpid() in the
   registers. */
__asm__(".text\n"
        "step_syscall:\n"
#if defined(__x86_64__)
        "  syscall\n"
#else
        "  int $0x80\n"
#endif
        "step_syscall_end:\n"
        "  hlt\n");

extern char blocking_syscall_insn[];

/* A syscall from an instruction that the tracer can find. */
static long __attribute__((noinline)) raw_syscall5(long no, long a1, long a2,
                                                   long a3, long a4, long a5) {
  long ret;
#if defined(__x86_64__)
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  __asm__ __volatile__("blocking_syscall_insn: syscall"
                       : "=a"(ret)
                       : "a"(no), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                       : "rcx", "r11", "memory");
#else
  __asm__ __volatile__("blocking_syscall_insn: int $0x80"
                       : "=a"(ret)
                       : "a"(no), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5)
                       : "memory");
#endif
  return ret;
}

/* Wait until |pid| sleeps. */
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
#endif

static void block_sigtrap(void (*h)(int)) {
  struct sigaction sa;
  sigset_t mask;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = h;
  test_assert(0 == sigaction(SIGTRAP, &sa, NULL));
  sigemptyset(&mask);
  sigaddset(&mask, SIGTRAP);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
}

static void stop(void) {
  /* Not raise(): glibc's raise() blocks all signals around the tgkill. */
  syscall(SYS_tgkill, getpid(), sys_gettid(), SIGSTOP);
}

static void check_sigtrap_forced(void) {
  struct sigaction sa;
  sigset_t mask;
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &mask));
  test_assert(!sigismember(&mask, SIGTRAP));
  test_assert(0 == sigaction(SIGTRAP, NULL, &sa));
  test_assert(sa.sa_handler == SIG_DFL);
  test_assert(!handled);
}

static void wait_for_stop(pid_t pid, int sig) {
  int status;
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == sig);
}

#if defined(__x86_64__) || defined(__i386__)
/* Resume |pid| to the entry of its next syscall, which must be
   |syscallno| at blocking_syscall_insn, single-step it from there,
   interrupt the syscall with SIGUSR1, and deliver that. (We don't
   single-step to the syscall instruction: those steps' SIGTRAPs would
   already change SIGTRAP's state.) */
static void step_over_interrupted_syscall(pid_t pid, long syscallno) {
  struct user_regs_struct regs;
  test_assert(0 == ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
  wait_for_stop(pid, SIGTRAP);
  ptrace_getregs(pid, &regs);
  test_assert((long)regs.ORIG_SYSCALLNO == syscallno);
  test_assert((uintptr_t)regs.IP ==
              (uintptr_t)blocking_syscall_insn + SYSCALL_SIZE);
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
  wait_for_sleep(pid);
  test_assert(0 == kill(pid, SIGUSR1));
  /* The kernel reports the step first. */
  wait_for_stop(pid, SIGTRAP);
  ptrace_getregs(pid, &regs);
  test_assert((uintptr_t)regs.IP ==
              (uintptr_t)blocking_syscall_insn + SYSCALL_SIZE);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  wait_for_stop(pid, SIGUSR1);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, (void*)SIGUSR1));
}
#endif

int main(void) {
  pid_t pid;
  int status;

  test_assert(0 == pipe(fds));

  if (0 == (pid = fork())) {
    struct rlimit no_core = { 0, 0 };
    test_assert(0 == setrlimit(RLIMIT_CORE, &no_core));
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));

    block_sigtrap(handler);
    stop();
    check_sigtrap_forced();

#if defined(__x86_64__) || defined(__i386__)
    block_sigtrap(handler);
    stop();
    check_sigtrap_forced();

    {
      struct sigaction sa;
      sigset_t mask;
      uint64_t suspend_mask = ~(uint64_t)0 & ~((uint64_t)1 << (SIGUSR1 - 1));
      char ch;
      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = usr1_handler;
      test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
      sa.sa_handler = handler;
      test_assert(0 == sigaction(SIGTRAP, &sa, NULL));
      sigemptyset(&mask);
      sigaddset(&mask, SIGUSR2);
      test_assert(0 == sigprocmask(SIG_SETMASK, &mask, NULL));
      stop();
      test_assert(-EINTR == raw_syscall5(SYS_rt_sigsuspend, (long)&suspend_mask,
                                         8, 0, 0, 0));
      test_assert(usr1_handled == 1);
      test_assert(!handled);
      test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &mask));
      test_assert(sigismember(&mask, SIGUSR2));
      test_assert(!sigismember(&mask, SIGTRAP));
      test_assert(!sigismember(&mask, SIGINT));
      test_assert(!sigismember(&mask, SIGUSR1));

      block_sigtrap(handler);
      stop();
      test_assert(-EINTR == raw_syscall5(SYS_read, fds[0], (long)&ch, 1, 0, 0));
      test_assert(usr1_handled == 2);
      check_sigtrap_forced();

      block_sigtrap(handler);
      stop();
      test_assert(-EINTR == raw_syscall5(SYS_ppoll, 0, 0, 0, 0, 8));
      test_assert(usr1_handled == 3);
      check_sigtrap_forced();
    }
#endif

    block_sigtrap(SIG_IGN);
    stop();
    /* The tracer resumes us with SIGTRAP, which must kill us. */
    test_assert(0 && "SIGTRAP didn't kill us");
    return 0;
  }

  /* 1: step over an ordinary instruction. */
  wait_for_stop(pid, SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
  wait_for_stop(pid, SIGTRAP);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));

#if defined(__x86_64__) || defined(__i386__)
  /* 2: step over a syscall instruction. */
  {
    struct user_regs_struct regs;
    struct user_regs_struct saved_regs;
    wait_for_stop(pid, SIGSTOP);
    ptrace_getregs(pid, &saved_regs);
    regs = saved_regs;
    regs.IP = (uintptr_t)step_syscall;
    regs.SYSCALL_RESULT = SYS_getpid;
    regs.ORIG_SYSCALLNO = -1;
    ptrace_setregs(pid, &regs);
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    wait_for_stop(pid, SIGTRAP);
    ptrace_getregs(pid, &regs);
    test_assert((uintptr_t)regs.IP == (uintptr_t)step_syscall_end);
    test_assert((pid_t)regs.SYSCALL_RESULT == pid);
    ptrace_setregs(pid, &saved_regs);
    test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  }

  /* 3: step over an rt_sigsuspend() that SIGUSR1 interrupts. */
  wait_for_stop(pid, SIGSTOP);
  step_over_interrupted_syscall(pid, SYS_rt_sigsuspend);
  /* 4: step over a read() that SIGUSR1 interrupts. */
  wait_for_stop(pid, SIGSTOP);
  step_over_interrupted_syscall(pid, SYS_read);
  /* 5: step over a ppoll() without a mask that SIGUSR1 interrupts. */
  wait_for_stop(pid, SIGSTOP);
  step_over_interrupted_syscall(pid, SYS_ppoll);
#endif

  /* 6: step with SIGTRAP ignored, then deliver SIGTRAP. */
  wait_for_stop(pid, SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
  wait_for_stop(pid, SIGTRAP);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, (void*)SIGTRAP));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTRAP);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
