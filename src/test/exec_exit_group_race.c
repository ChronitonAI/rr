/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread execs while the main thread wakes up from a blocking read and
   calls exit_group. The exec has to wait for the main thread to exit, which
   can happen while rr is busy with the main thread's read, so rr must still
   handle that exit while the exec is in progress. Either the exit_group or
   the exec wins; both are fine. This doesn't reproduce the problem every
   time, so do many rounds. */

#define NUM_ROUNDS 50
/* Lots of arguments make the exec take a while to copy them before it kills
   the other threads, so the main thread has time to get going. */
#define NUM_ARGS 20000

static char exe[4096];
static char* exec_argv[NUM_ARGS + 3];
static int fds[2];

static void* do_exec(__attribute__((unused)) void* p) {
  test_assert(1 == write(fds[1], "x", 1));
  /* Not /proc/self/exe: that may be gone by the time we get there. */
  execve(exe, exec_argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

int main(int argc, __attribute__((unused)) char** argv) {
  static char arg[] = "0123456789012345678901234567890123456789";
  int i;
  ssize_t len;

  if (argc > 1) {
    return 77;
  }

  len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  test_assert(len > 0);
  exe[len] = 0;
  exec_argv[0] = exe;
  exec_argv[1] = "exec";
  for (i = 2; i < NUM_ARGS + 2; ++i) {
    exec_argv[i] = arg;
  }

  for (i = 0; i < NUM_ROUNDS; ++i) {
    int status;
    pid_t child = fork();
    if (!child) {
      pthread_t thread;
      char ch;
      test_assert(0 == pipe(fds));
      test_assert(0 == pthread_create(&thread, NULL, do_exec, NULL));
      test_assert(1 == read(fds[0], &ch, 1));
      syscall(SYS_exit_group, 0);
      test_assert(0 && "exit_group returned");
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) &&
                (WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 77));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
