/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_ERESTARTSYS 512

/* A tracer follows its child with PTRACE_SYSCALL through read()s that were
   blocked when the tracer stopped or interrupted the child. Under rr with
   the syscall buffer, those read()s are buffered syscalls that rr
   descheduled. */

static int fds[2];

/* Wait for a syscall stop, of kind |op| if the kernel can tell us. For an
   exit, check that the syscall returned |expected_rval|. */
static void wait_for_syscall_stop(pid_t child, int op, int64_t expected_rval) {
  struct rr_ptrace_syscall_info info;
  int status;
  long ret;

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, (void*)sizeof(info), &info);
  if (ret < 0) {
    /* PTRACE_GET_SYSCALL_INFO was added in Linux 5.3. */
    test_assert(errno == EIO);
    return;
  }
  test_assert(info.op == op);
  if (op == RR_PTRACE_SYSCALL_INFO_EXIT) {
    test_assert(info.exit.rval == expected_rval);
  }
}

static void handle_usr1(__attribute__((unused)) int sig) {}

/* Under rr, this runs us in user space for longer than a timeslice, making
   syscalls that the syscall buffer handles, so that rr processes the
   child's next stop meanwhile. With SIGCHLD blocked, the next event that rr
   records for us after that flushes our syscall buffer. */
static void spin(void) {
  int i;
  volatile int j;
  for (i = 0; i < 1000; ++i) {
    getppid();
    for (j = 0; j < 10000; ++j) {
    }
  }
}

int main(void) {
  struct user_regs_struct regs;
  sigset_t sigchld;
  pid_t child;
  int status;
  ssize_t ret;
  char ch;

  test_assert(0 == pipe(fds));
  /* Let rr patch read() for the syscall buffer before the child is
     created. */
  test_assert(1 == write(fds[1], "a", 1));
  test_assert(1 == read(fds[0], &ch, 1));

  if (0 == (child = fork())) {
    int zero_results = 0;
    int eintr_results = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_usr1;
    test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
    do {
      ch = 0;
      ret = read(fds[0], &ch, 1);
      if (ret == 0) {
        ++zero_results;
      } else if (ret < 0) {
        test_assert(errno == EINTR);
        ++eintr_results;
      } else {
        test_assert(ret == 1);
      }
    } while (ch != 'q');
    /* The results that the tracer set, and the signal handler's EINTR. */
    test_assert(zero_results == 2);
    test_assert(eintr_results == 2);
    return 77;
  }
  test_assert(child > 0);

  /* See spin(). */
  sigemptyset(&sigchld);
  sigaddset(&sigchld, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigchld, NULL));

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  /* Linux restarts the read(). The child must see the result that we set
     at the syscall-exit stop. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, 1);
  ptrace_getregs(child, &regs);
  regs.SYSCALL_RESULT = 0;
  ptrace_setregs(child, &regs);

  /* Skip a restarted read() with PTRACE_SYSEMU, setting its result at the
     syscall-entry stop. The child must see that result too. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  ptrace_getregs(child, &regs);
  regs.SYSCALL_RESULT = 0;
  ptrace_setregs(child, &regs);

  /* With PTRACE_CONT, a PTRACE_INTERRUPT right after we wrote to the pipe
     stops the child after its read() returned: at the read()'s exit or,
     natively, outside a syscall or at the exit of the next read(), which
     the PTRACE_INTERRUPT interrupts, if the child got there first. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(1 == write(fds[1], "y", 1));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
#if defined(__i386__) || defined(__x86_64__)
  ptrace_getregs(child, &regs);
  if ((long)regs.ORIG_SYSCALLNO != -1) {
    test_assert((long)regs.ORIG_SYSCALLNO == SYS_read);
    test_assert((long)regs.SYSCALL_RESULT == 1 ||
                (long)regs.SYSCALL_RESULT == -RR_ERESTARTSYS);
  }
#endif

  /* With PTRACE_CONT, PTRACE_INTERRUPT gives just a PTRACE_EVENT_STOP, and
     the next PTRACE_SYSCALL the syscall-entry stop of the restarted
     read(). */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* With PTRACE_SYSCALL, PTRACE_INTERRUPT gives just the syscall-exit
     stop. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* A signal handler (without SA_RESTART) interrupts the read(). We get
     syscall stops for the handler's sigreturn too. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == kill(child, SIGUSR1));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)SIGUSR1));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  spin();
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -EINTR);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* If we change the result of an interrupted read() at its syscall-exit
     stop, Linux doesn't restart it, and the child sees our result. */
  test_assert(1 == write(fds[1], "z", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);
  ptrace_getregs(child, &regs);
  regs.SYSCALL_RESULT = -EINTR;
  ptrace_setregs(child, &regs);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  test_assert(1 == write(fds[1], "q", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, 1);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
