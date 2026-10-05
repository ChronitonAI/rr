/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_PTRACE_GET_SYSCALL_INFO 0x420e
#define RR_PTRACE_SYSCALL_INFO_ENTRY 1

/* A tracer resumes its child with PTRACE_CONT from a PTRACE_SYSEMU
   syscall-entry stop and interrupts it with PTRACE_INTERRUPT. Linux skips the
   syscall, and there's no syscall-exit stop for it, even if the tracer
   resumes the child from the PTRACE_EVENT_STOP with PTRACE_SYSCALL. */

static int fds[2];

static void wait_for_stop(pid_t child, int expected_status) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == expected_status);
}

int main(void) {
  struct iovec iov;
  pid_t child;
  uint8_t info[128];
  long ret;
  int status;
  char ch;

  test_assert(0 == pipe(fds));

  if (0 == (child = fork())) {
    /* The tracer skips some readv()s (they return -ENOSYS on x86, their
       first argument on aarch64), so we only look at ch. The syscall buffer
       doesn't handle readv(). */
    iov.iov_base = &ch;
    iov.iov_len = 1;
    do {
      ch = 0;
      readv(fds[0], &iov, 1);
    } while (ch != 'q');
    return 77;
  }
  test_assert(child > 0);

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  wait_for_task_asleep_in_syscall(child, SYS_readv, fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_stop(child, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);

  /* Let the restarted readv() read a character, and skip the next readv(). */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_stop(child, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);

  /* The next stop must be the syscall-entry stop of a readv(). */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  ret = ptrace(RR_PTRACE_GET_SYSCALL_INFO, child, (void*)sizeof(info), info);
  if (ret < 0) {
    /* PTRACE_GET_SYSCALL_INFO was added in Linux 5.3. */
    test_assert(errno == EIO);
  } else {
    test_assert(info[0] == RR_PTRACE_SYSCALL_INFO_ENTRY);
  }

  /* A PTRACE_INTERRUPT at a PTRACE_SYSEMU syscall-entry stop takes effect
     when the child leaves the stop: with PTRACE_CONT, the PTRACE_EVENT_STOP
     follows the skipped syscall. */
  test_assert(1 == write(fds[1], "y", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, NULL));
  wait_for_stop(child, ((SIGTRAP | 0x80) << 8) | 0x7f);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_for_stop(child, (PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f);

  test_assert(1 == write(fds[1], "q", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
