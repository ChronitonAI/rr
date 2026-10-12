/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

/* A perf event with sigtrap set sends a SIGTRAP (si_code TRAP_PERF) when
   it fires. The kernel doesn't force that SIGTRAP (since Linux 5.19, and
   5.15.46, 5.17.15 and 5.18.5), so when SIGTRAP is ignored, it stays
   ignored. Older kernels force it; the test checks for that in a child
   and passes trivially then. */

static volatile int watched;

/* Older headers don't have these bits of perf_event_attr's flags word,
   which follows read_format. */
#define REMOVE_ON_EXEC_BIT 36
#define SIGTRAP_BIT 37

/* Ignores SIGTRAP and opens the perf event. Returns -1 if that fails. */
static int open_event(void) {
  struct perf_event_attr attr;
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  test_assert(0 == sigaction(SIGTRAP, &sa, NULL));

  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.size = sizeof(attr);
  attr.bp_type = HW_BREAKPOINT_W;
  attr.bp_addr = (uintptr_t)&watched;
  attr.bp_len = HW_BREAKPOINT_LEN_4;
  attr.sample_period = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  *(uint64_t*)((char*)&attr.read_format + sizeof(attr.read_format)) |=
      ((uint64_t)1 << REMOVE_ON_EXEC_BIT) | ((uint64_t)1 << SIGTRAP_BIT);
  return syscall(SYS_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
}

int main(void) {
  struct sigaction sa;
  pid_t pid;
  int status;
  int fd;

  pid = fork();
  if (!pid) {
    struct rlimit no_core = { 0, 0 };
    test_assert(0 == setrlimit(RLIMIT_CORE, &no_core));
    if (open_event() >= 0) {
      watched = 1;
    }
    return 77;
  }
  test_assert(pid == waitpid(pid, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTRAP) {
    atomic_puts("The kernel forces the perf SIGTRAP, skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  fd = open_event();
  if (fd < 0) {
    atomic_printf("perf_event_open failed (errno %d), skipping\n", errno);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  watched = 1;
  watched = 2;

  test_assert(0 == sigaction(SIGTRAP, NULL, &sa));
  test_assert(sa.sa_handler == SIG_IGN);
  test_assert(0 == close(fd));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
