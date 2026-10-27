/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_PTRACE_GET_SYSCALL_INFO 0x420e
#define RR_PTRACE_SYSCALL_INFO_ENTRY 1
#define RR_PTRACE_SYSCALL_INFO_EXIT 2
#define RR_ERESTARTSYS 512

/* A tracer follows its child through a readv() on a pipe that a signal or a
   PTRACE_INTERRUPT interrupts, while the child has a signal handler with
   SA_RESTART. (The syscall buffer doesn't handle readv().) At some of the
   stops at the exit of the interrupted readv(), the tracer changes the
   result or sets the syscall number to -1, so that Linux doesn't restart
   the readv(). */

static int fds[2];

static void handle_signal(__attribute__((unused)) int sig,
                          __attribute__((unused)) siginfo_t* si,
                          __attribute__((unused)) void* ctx) {}

/* Read a byte with readv() until we get 'q'. Each result must match the
   next character of |expected|: the byte we read, '0' for 0, 'E' for EINTR,
   or 'R' or 'r' for ERESTARTSYS. After 'r', read again right away, with the
   same arguments. After each other result but 'q', send ourselves
   SIGUSR2. */
static void child(const char* expected) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_signal;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  test_assert(0 == sigaction(SIGUSR2, &sa, NULL));
  for (;;) {
    ssize_t ret;
    char ch = 0;
    char result;
    struct iovec iov;
    iov.iov_base = &ch;
    iov.iov_len = 1;
    ret = readv(fds[0], &iov, 1);
    if (ret < 0 && errno == EINTR) {
      result = 'E';
    } else if (ret < 0) {
      test_assert(errno == RR_ERESTARTSYS);
      result = 'R';
    } else if (ret == 0) {
      result = '0';
    } else {
      test_assert(ret == 1);
      result = ch;
    }
    if (*expected == 'r') {
      test_assert(result == 'R');
      ++expected;
      continue;
    }
    test_assert(result == *expected);
    ++expected;
    if (result == 'q') {
      break;
    }
    test_assert(0 == kill(getpid(), SIGUSR2));
  }
  test_assert(!*expected);
  exit(77);
}

/* Wait for a syscall stop. If the kernel can tell us, check that it's a
   stop of kind |op|, store the syscall number (at an entry) or result (at an
   exit) in |*value| and return 1. */
static int wait_for_syscall_stop(pid_t pid, int op, int64_t* value) {
  uint8_t info[128];
  int status;
  long ret;

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  ret = ptrace(RR_PTRACE_GET_SYSCALL_INFO, pid, (void*)sizeof(info), info);
  if (ret < 0) {
    /* PTRACE_GET_SYSCALL_INFO was added in Linux 5.3. */
    test_assert(errno == EIO);
    return 0;
  }
  test_assert(info[0] == op);
  /* struct ptrace_syscall_info's entry.nr or exit.rval */
  memcpy(value, info + 24, sizeof(*value));
  return 1;
}

static void wait_for_syscall_entry(pid_t pid, long nr) {
  int64_t value;
  if (wait_for_syscall_stop(pid, RR_PTRACE_SYSCALL_INFO_ENTRY, &value)) {
    test_assert(value == nr);
  }
}

static void wait_for_syscall_exit(pid_t pid, int64_t rval) {
  int64_t value;
  if (wait_for_syscall_stop(pid, RR_PTRACE_SYSCALL_INFO_EXIT, &value)) {
    test_assert(value == rval);
  }
}

static void wait_for_stop(pid_t pid, int expected_status) {
  int status;
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == expected_status);
}

/* Wait for the SIGUSR2 that the child sends itself after a read returned,
   and resume the child with PTRACE_CONT. The child then blocks in its next
   read. We may get a signal-delivery stop for the SIGUSR1 that we passed at
   a syscall-exit stop before (Linux sends that signal again, see
   ptrace_report_syscall()); we pass it on. */
static void finish_read(pid_t pid) {
  int status;
  for (;;) {
    test_assert(pid == waitpid(pid, &status, 0));
    if (status != ((SIGUSR1 << 8) | 0x7f)) {
      break;
    }
    test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, (void*)SIGUSR1));
  }
  test_assert(status == ((SIGUSR2 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  wait_for_task_asleep_in_syscall(pid, SYS_readv, fds[0]);
}

/* The child is blocked in a read after PTRACE_CONT. Interrupt it, and
   have the read restart and block again with PTRACE_SYSCALL in effect. */
static void restart_with_ptrace_syscall(pid_t pid) {
  test_assert(0 == ptrace(PTRACE_INTERRUPT, pid, NULL, NULL));
  wait_for_stop(pid, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
  wait_for_syscall_entry(pid, SYS_readv);
  test_assert(0 == ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
  wait_for_task_asleep_in_syscall(pid, SYS_readv, fds[0]);
}

/* The child is blocked in a read after PTRACE_CONT. Get to the
   syscall-exit stop of the restarted read with -ERESTARTSYS. */
static void interrupt_to_syscall_exit(pid_t pid) {
  restart_with_ptrace_syscall(pid);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, pid, NULL, NULL));
  wait_for_syscall_exit(pid, -RR_ERESTARTSYS);
}

static void set_result(pid_t pid, long result) {
  struct user_regs_struct regs;
  ptrace_getregs(pid, &regs);
  regs.SYSCALL_RESULT = result;
  ptrace_setregs(pid, &regs);
}

#if defined(__i386__) || defined(__x86_64__)
/* On x86, Linux decides whether to restart the syscall after the
   PTRACE_EVENT_STOP and signal-delivery stops at its exit, which show the
   syscall's result. (On aarch64, it has already set up the restart.) It
   restarts the syscall only if the syscall number isn't -1. */
#define X86_RESULTS "EEEErRr"

/* At a stop at the exit of the interrupted read, check that the read is
   to be restarted and set the result and the syscall number. */
static void set_regs_at_exit(pid_t pid, long result, long nr) {
  struct user_regs_struct regs;
  ptrace_getregs(pid, &regs);
  test_assert((long)regs.ORIG_SYSCALLNO == SYS_readv);
  test_assert((long)regs.SYSCALL_RESULT == -RR_ERESTARTSYS);
  regs.SYSCALL_RESULT = result;
  regs.ORIG_SYSCALLNO = nr;
  ptrace_setregs(pid, &regs);
}

/* Set the result to -EINTR. */
static void set_eintr_at_exit(pid_t pid) {
  set_regs_at_exit(pid, -EINTR, SYS_readv);
}

/* Set the syscall number to -1, as debuggers do when they set the
   instruction pointer. */
static void cancel_restart_at_exit(pid_t pid) {
  set_regs_at_exit(pid, -RR_ERESTARTSYS, -1);
}
#else
#define X86_RESULTS ""
#endif

static void run(void) {
  pid_t child_pid;
  pid_t tracer;
  int status;

  if (0 == (child_pid = fork())) {
    child("abcdE" X86_RESULTS "0q");
  }
  test_assert(child_pid > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child_pid, NULL,
                          (void*)PTRACE_O_TRACESYSGOOD));
  wait_for_task_asleep_in_syscall(child_pid, SYS_readv, fds[0]);

  /* A signal interrupts the read, and we follow the handler's sigreturn
     with PTRACE_SYSCALL. The read restarts after the sigreturn. */
  test_assert(0 == kill(child_pid, SIGUSR1));
  wait_for_stop(child_pid, (SIGUSR1 << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child_pid, NULL, (void*)SIGUSR1));
  wait_for_syscall_entry(child_pid, SYS_rt_sigreturn);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL));
  test_assert(child_pid == waitpid(child_pid, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL));
  wait_for_syscall_entry(child_pid, SYS_readv);
  test_assert(1 == write(fds[1], "a", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL));
  wait_for_syscall_exit(child_pid, 1);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, NULL));
  finish_read(child_pid);

  /* We resume the child from the syscall-exit stop of an interrupted read
     with a signal, using PTRACE_CONT. The read restarts after the
     handler. */
  interrupt_to_syscall_exit(child_pid);
  test_assert(1 == write(fds[1], "b", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

  /* A signal interrupts the read while we follow it with PTRACE_SYSCALL.
     We get the syscall-exit stop and then the signal-delivery stop, where we
     pass the signal, using PTRACE_CONT. The read restarts after the
     handler. */
  restart_with_ptrace_syscall(child_pid);
  test_assert(0 == kill(child_pid, SIGUSR1));
  wait_for_syscall_exit(child_pid, -RR_ERESTARTSYS);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL));
  wait_for_stop(child_pid, (SIGUSR1 << 8) | 0x7f);
  test_assert(1 == write(fds[1], "c", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

  /* A signal interrupts the read, and we pass it at its signal-delivery
     stop, using PTRACE_CONT. The read restarts after the handler. */
  test_assert(0 == kill(child_pid, SIGUSR1));
  wait_for_stop(child_pid, (SIGUSR1 << 8) | 0x7f);
  test_assert(1 == write(fds[1], "d", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

  /* We resume the child from the syscall-exit stop of an interrupted read
     with a signal, but change the result to -EINTR first. The read
     doesn't restart. */
  interrupt_to_syscall_exit(child_pid);
  set_result(child_pid, -EINTR);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

#if defined(__i386__) || defined(__x86_64__)
  /* We change the result to -EINTR at the PTRACE_EVENT_STOP of a
     PTRACE_INTERRUPT. The read doesn't restart. */
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL));
  wait_for_stop(child_pid, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);
  set_eintr_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, NULL));
  finish_read(child_pid);

  /* We change the result to -EINTR at the signal-delivery stop of a signal
     that interrupts the read, and pass the signal. The read doesn't
     restart. */
  test_assert(0 == kill(child_pid, SIGUSR1));
  wait_for_stop(child_pid, (SIGUSR1 << 8) | 0x7f);
  set_eintr_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

  /* The same, but we suppress the signal. */
  test_assert(0 == kill(child_pid, SIGUSR1));
  wait_for_stop(child_pid, (SIGUSR1 << 8) | 0x7f);
  set_eintr_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, NULL));
  finish_read(child_pid);

  /* The same with a signal that has no handler (SIGWINCH is ignored by
     default), which we pass. */
  test_assert(0 == kill(child_pid, SIGWINCH));
  wait_for_stop(child_pid, (SIGWINCH << 8) | 0x7f);
  set_eintr_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGWINCH));
  finish_read(child_pid);

  /* We set the syscall number to -1 at the syscall-exit stop of an
     interrupted read. The read doesn't restart and returns -ERESTARTSYS,
     and the child reads again with the same arguments, which isn't a
     restart. */
  interrupt_to_syscall_exit(child_pid);
  cancel_restart_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, NULL));
  wait_for_task_asleep_in_syscall(child_pid, SYS_readv, fds[0]);

  /* The same, but we pass a signal. */
  interrupt_to_syscall_exit(child_pid);
  cancel_restart_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, (void*)SIGUSR1));
  finish_read(child_pid);

  /* We set the syscall number to -1 at the PTRACE_EVENT_STOP of a
     PTRACE_INTERRUPT, and the child reads again as above. */
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL));
  wait_for_stop(child_pid, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);
  cancel_restart_at_exit(child_pid);
  test_assert(0 == ptrace(PTRACE_CONT, child_pid, NULL, NULL));
  wait_for_task_asleep_in_syscall(child_pid, SYS_readv, fds[0]);
#endif

  /* We change the result to 0 and detach. */
  interrupt_to_syscall_exit(child_pid);
  set_result(child_pid, 0);
  test_assert(0 == ptrace(PTRACE_DETACH, child_pid, NULL, NULL));
  test_assert(1 == write(fds[1], "q", 1));
  wait_for_stop(child_pid, 77 << 8);

  /* A tracer of its own changes the result to 0 and exits. The child, which
     the tracer forked, becomes our child. */
  test_assert(0 == prctl(PR_SET_CHILD_SUBREAPER, 1));
  if (0 == (tracer = fork())) {
    if (0 == (child_pid = fork())) {
      child("0q");
    }
    test_assert(child_pid > 0);
    test_assert(0 == ptrace(PTRACE_SEIZE, child_pid, NULL,
                            (void*)PTRACE_O_TRACESYSGOOD));
    wait_for_task_asleep_in_syscall(child_pid, SYS_readv, fds[0]);
    interrupt_to_syscall_exit(child_pid);
    set_result(child_pid, 0);
    exit(66);
  }
  test_assert(tracer > 0);
  wait_for_stop(tracer, 66 << 8);
  test_assert(1 == write(fds[1], "q", 1));
  child_pid = wait(&status);
  test_assert(child_pid > 0);
  test_assert(status == 77 << 8);
  test_assert(0 == prctl(PR_SET_CHILD_SUBREAPER, 0));
}

int main(void) {
  test_assert(0 == pipe(fds));
  run();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
