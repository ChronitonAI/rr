/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* A ptracer waits with i386 waitpid()s (int $0x80) for a tracee that isn't
   its child: its grandchild, which it seizes. A WNOHANG wait returns 0 while
   the grandchild runs. The grandchild stops only once the tracer sleeps in a
   wait, which another thread of the tracer watches for. */

#if defined(__x86_64__)

#define I386_ppoll 309

static pid_t tracer;
static int go_pipe[2];

static void* go_thread(__attribute__((unused)) void* p) {
  /* Under rr, the wait can be a ppoll(). */
  while (!task_asleep_in_syscall(tracer, I386_waitpid, -1) &&
         !task_asleep_in_syscall(tracer, I386_ppoll, -1)) {
    sched_yield();
  }
  test_assert(1 == write(go_pipe[1], "g", 1));
  return NULL;
}

int main(void) {
  int* status = int80_low_alloc(4096);
  int pid_pipe[2];
  int done_pipe[2];
  pid_t child;
  pid_t grandchild;
  pthread_t thread;
  char c;
  long ret;

  int80_setup();
  tracer = getpid();
  test_assert(0 == pipe(pid_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(done_pipe));
  child = fork();
  if (!child) {
    pid_t g;
    /* If the test fails, these read()s see EOF. */
    close(go_pipe[1]);
    close(done_pipe[1]);
    g = fork();
    if (!g) {
      /* Stop once the tracer waits */
      if (1 == read(go_pipe[0], &c, 1)) {
        raise(SIGSTOP);
      }
      read(done_pipe[0], &c, 1);
      return 0;
    }
    test_assert(g > 0);
    test_assert(sizeof(g) == write(pid_pipe[1], &g, sizeof(g)));
    test_assert(g == waitpid(g, NULL, 0));
    return 0;
  }
  test_assert(child > 0);
  test_assert(sizeof(grandchild) ==
              read(pid_pipe[0], &grandchild, sizeof(grandchild)));
  test_assert(grandchild > 1);

  test_assert(0 == ptrace(PTRACE_SEIZE, grandchild, NULL, NULL));
  *status = -1;
  ret = int80_3(I386_waitpid, grandchild, LOW(status), WNOHANG | __WALL);
  test_assert(ret == 0);
  test_assert(*status == -1);

  test_assert(0 == pthread_create(&thread, NULL, go_thread, NULL));
  ret = int80_3(I386_waitpid, grandchild, LOW(status), __WALL);
  test_assert(ret == grandchild);
  test_assert(WIFSTOPPED(*status));
  test_assert(WSTOPSIG(*status) == SIGSTOP);
  test_assert(0 == pthread_join(thread, NULL));

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
