/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* A ptracer waits with an i386 waitpid() (int $0x80) for a tracee that isn't
   its child: its grandchild, which it seizes. The grandchild stops only once
   the tracer sleeps in its wait. */

#if defined(__x86_64__)

#define I386_ppoll 309

/* Waits until pid sleeps in syscall nr1 or nr2 (under rr, the wait can be a
   ppoll()). */
static void wait_for_sleep_in(pid_t pid, long nr1, long nr2) {
  char path[64];
  char buf[512];
  while (1) {
    int fd;
    ssize_t n;
    long nr;
    sprintf(path, "/proc/%d/task/%d/syscall", pid, pid);
    fd = open(path, O_RDONLY);
    test_assert(fd >= 0);
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0 && buf[0] != 'r') {
      buf[n] = 0;
      nr = strtol(buf, NULL, 10);
      if (nr == nr1 || nr == nr2) {
        char* p;
        sprintf(path, "/proc/%d/stat", pid);
        fd = open(path, O_RDONLY);
        test_assert(fd >= 0);
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        test_assert(n > 0);
        buf[n] = 0;
        p = strrchr(buf, ')');
        if (p && p[2] == 'S') {
          return;
        }
      }
    }
    sched_yield();
  }
}

int main(void) {
  int* status = int80_low_alloc(4096);
  pid_t tracer = getpid();
  int pid_pipe[2];
  int start_pipe[2];
  int go_pipe[2];
  int done_pipe[2];
  pid_t child;
  pid_t grandchild;
  char c;
  long ret;

  int80_setup();
  test_assert(0 == pipe(pid_pipe));
  test_assert(0 == pipe(start_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(done_pipe));
  child = fork();
  if (!child) {
    pid_t g;
    /* If the test fails, these read()s see EOF. */
    close(start_pipe[1]);
    close(done_pipe[1]);
    g = fork();
    if (!g) {
      /* Stop once the tracer waits */
      read(go_pipe[0], &c, 1);
      raise(SIGSTOP);
      read(done_pipe[0], &c, 1);
      return 0;
    }
    test_assert(sizeof(g) == write(pid_pipe[1], &g, sizeof(g)));
    if (1 == read(start_pipe[0], &c, 1)) {
      wait_for_sleep_in(tracer, I386_waitpid, I386_ppoll);
      test_assert(1 == write(go_pipe[1], "g", 1));
    }
    test_assert(g == waitpid(g, NULL, 0));
    return 0;
  }
  test_assert(sizeof(grandchild) ==
              read(pid_pipe[0], &grandchild, sizeof(grandchild)));

  test_assert(0 == ptrace(PTRACE_SEIZE, grandchild, NULL, NULL));
  test_assert(1 == write(start_pipe[1], "s", 1));
  *status = -1;
  ret = int80_3(I386_waitpid, grandchild, LOW(status), __WALL);
  test_assert(ret == grandchild);
  test_assert(WIFSTOPPED(*status));
  test_assert(WSTOPSIG(*status) == SIGSTOP);

  test_assert(0 == ptrace(PTRACE_DETACH, grandchild, NULL, NULL));
  test_assert(1 == write(done_pipe[1], "x", 1));
  test_assert(child == waitpid(child, NULL, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
