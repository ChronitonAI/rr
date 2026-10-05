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

/* A tracer follows its child with PTRACE_SYSCALL through read()s that were
   blocked when the tracer stopped or interrupted the child. Under rr with
   the syscall buffer, those read()s are buffered syscalls that rr
   descheduled. */

static int fds[2];

/* Returns true if the child is sleeping in a read() of fds[0]. */
static int child_blocked_in_read(pid_t child) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  long nr;
  unsigned long arg1;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/stat", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  if (p[2] != 'S') {
    return 0;
  }

  sprintf(path, "/proc/%d/syscall", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_read &&
         arg1 == (unsigned long)fds[0];
}

/* Wait for a syscall stop, of kind |op| if the kernel can tell us. For an
   exit, check that the syscall returned |expected_rval|. */
static void wait_for_syscall_stop(pid_t child, int op, int64_t expected_rval) {
  uint8_t info[128];
  int64_t rval;
  int status;
  long ret;

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  ret = ptrace(RR_PTRACE_GET_SYSCALL_INFO, child, (void*)sizeof(info), info);
  if (ret < 0) {
    /* PTRACE_GET_SYSCALL_INFO was added in Linux 5.3. */
    test_assert(errno == EIO);
    return;
  }
  test_assert(info[0] == op);
  if (op == RR_PTRACE_SYSCALL_INFO_EXIT) {
    /* struct ptrace_syscall_info's exit.rval */
    memcpy(&rval, info + 24, sizeof(rval));
    test_assert(rval == expected_rval);
  }
}

static void handle_usr1(__attribute__((unused)) int sig) {}

static void wait_for_child_blocked_in_read(pid_t child) {
  while (!child_blocked_in_read(child)) {
    sched_yield();
  }
}

int main(void) {
  struct user_regs_struct regs;
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
      } else {
        test_assert(ret == 1);
      }
    } while (ch != 'q');
    /* The results that the tracer set. */
    test_assert(zero_results == 2);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  wait_for_child_blocked_in_read(child);
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
  wait_for_child_blocked_in_read(child);
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  ptrace_getregs(child, &regs);
  regs.SYSCALL_RESULT = 0;
  ptrace_setregs(child, &regs);

  /* With PTRACE_CONT, PTRACE_INTERRUPT gives just a PTRACE_EVENT_STOP, and
     the next PTRACE_SYSCALL the syscall-entry stop of the restarted
     read(). */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_child_blocked_in_read(child);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* With PTRACE_SYSCALL, PTRACE_INTERRUPT gives just the syscall-exit
     stop. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_child_blocked_in_read(child);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* A signal handler (without SA_RESTART) interrupts the read(). We get
     syscall stops for the handler's sigreturn too. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_child_blocked_in_read(child);
  test_assert(0 == kill(child, SIGUSR1));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)SIGUSR1));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -EINTR);
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
