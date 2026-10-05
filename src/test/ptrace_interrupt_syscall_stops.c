/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define RR_PTRACE_GET_SYSCALL_INFO 0x420e
#define RR_PTRACE_SYSCALL_INFO_ENTRY 1
#define RR_PTRACE_SYSCALL_INFO_EXIT 2
#define RR_ERESTARTSYS 512

static int fds[2];

/* The child reads with readv() because rr's syscall buffer doesn't handle it,
   so it's always a traced syscall. */

/* Returns true if the child is sleeping in its readv() of fds[0]. */
static int child_blocked_in_readv(pid_t child) {
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
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_readv &&
         arg1 == (unsigned long)fds[0];
}

/* Wait for a syscall stop, of kind |op| if the kernel can tell us. For an
   exit, check that the syscall returned |rval|. */
static void wait_for_syscall_stop(pid_t child, int op, int64_t rval) {
  uint8_t info[128];
  int64_t actual_rval;
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
    memcpy(&actual_rval, info + 24, sizeof(actual_rval));
    test_assert(actual_rval == rval);
  }
}

static void wait_for_event_stop(pid_t child) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
}

/* Follow the child from the stop we have it in to the exit of the
   restarted readv(), then resume it and interrupt it right away. */
static void follow_readv(pid_t child) {
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, 1);

  /* The child left its syscall-exit stop, so PTRACE_INTERRUPT must stop it
     with a PTRACE_EVENT_STOP. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_event_stop(child);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
}

/* The child reads characters until it gets 'e', when it execs this program
   again to do the same, or 'q', when it execs this program to exit. */
static void child_loop(const char* exe) {
  char fd_str[20];
  char* loop_argv[] = { (char*)exe, "loop", fd_str, NULL };
  char* exit_argv[] = { (char*)exe, "exit", NULL };
  struct iovec iov;
  char ch;

  iov.iov_base = &ch;
  iov.iov_len = 1;
  do {
    test_assert(1 == readv(fds[0], &iov, 1));
  } while (ch != 'e' && ch != 'q');
  sprintf(fd_str, "%d", fds[0]);
  execve(exe, ch == 'e' ? loop_argv : exit_argv, environ);
  test_assert(0);
}

/* Wait for the PTRACE_EVENT_EXEC stop, which must be the first stop after a
   PTRACE_INTERRUPT right after the child was resumed from its syscall-entry
   stop of execve(), and resume the child with PTRACE_CONT. */
static void wait_for_exec_stop(pid_t child) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_EXEC << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
}

/* If the child reached its PTRACE_EVENT_EXEC stop before the
   PTRACE_INTERRUPT, Linux reports a PTRACE_EVENT_STOP after it. Wait until
   the child is blocked in readv() and resume it from that stop if there is
   one. */
static void wait_for_child_blocked_after_exec(pid_t child) {
  int status;
  while (!child_blocked_in_readv(child)) {
    pid_t ret = waitpid(child, &status, WNOHANG);
    if (ret == child) {
      test_assert(status ==
                  ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    } else {
      test_assert(ret == 0);
    }
    sched_yield();
  }
}

int main(int argc, char** argv) {
  pid_t child;
  int status;

  if (argc > 1 && !strcmp(argv[1], "exit")) {
    return 77;
  }
  if (argc > 2 && !strcmp(argv[1], "loop")) {
    fds[0] = atoi(argv[2]);
    child_loop(argv[0]);
  }

  test_assert(0 == pipe(fds));

  if (0 == (child = fork())) {
    child_loop(argv[0]);
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC)));

  /* Interrupt the child in readv(). The readv() exits before the
     PTRACE_INTERRUPT stop, so with PTRACE_SYSCALL, the next stop is the
     syscall-entry stop of the restarted readv(). */
  while (!child_blocked_in_readv(child)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_event_stop(child);
  follow_readv(child);

  /* Same with a SIGSTOP signal-delivery stop in readv(). */
  while (!child_blocked_in_readv(child)) {
    sched_yield();
  }
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  follow_readv(child);

  /* With PTRACE_SYSCALL in effect, the syscall-exit stop is the only stop
     for a PTRACE_INTERRUPT in a syscall: any ptrace stop discards a pending
     PTRACE_INTERRUPT trap. */
  while (!child_blocked_in_readv(child)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_event_stop(child);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  while (!child_blocked_in_readv(child)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);

  /* Same when the PTRACE_INTERRUPT follows a PTRACE_SYSCALL from the
     syscall-entry stop right away. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, -RR_ERESTARTSYS);

  /* With PTRACE_CONT from the syscall-entry stop, the syscall finishes
     without a syscall-exit stop before the PTRACE_EVENT_STOP, so the next
     syscall stop is the next readv()'s entry. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(1 == write(fds[1], "y", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_event_stop(child);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);

  /* A ptrace event stop in the syscall discards the PTRACE_INTERRUPT trap
     too, e.g. the PTRACE_EVENT_EXEC stop of execve(), with PTRACE_CONT ... */
  test_assert(1 == write(fds[1], "e", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, 1);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_exec_stop(child);
  wait_for_child_blocked_after_exec(child);

  /* ... and with PTRACE_SYSCALL. Then there's no syscall-exit stop either,
     after the PTRACE_CONT from the PTRACE_EVENT_EXEC stop. */
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_event_stop(child);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(1 == write(fds[1], "q", 1));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_EXIT, 1);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child, RR_PTRACE_SYSCALL_INFO_ENTRY, 0);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  wait_for_exec_stop(child);
  test_assert(child == waitpid(child, &status, 0));
  if (status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f)) {
    /* See wait_for_child_blocked_after_exec. */
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));
  }
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
