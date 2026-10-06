/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A ptracer exits while its tracee is in a PTRACE_EVENT_CLONE, _FORK,
   _VFORK or _EXEC stop. The tracee should resume and finish the syscall. */

static const int events[] = { PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK,
                              PTRACE_EVENT_VFORK, PTRACE_EVENT_EXEC };

static char* exe;
static int status_pipe[2];

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

static void report_done(int fd) {
  char ok = 'K';
  test_assert(1 == write(fd, &ok, 1));
}

static void run_tracee(int event, int ready_fd) {
  char ch = 0;
  int status;
  pthread_t thread;
  pid_t pid;
  char fd_str[20];

  test_assert(1 == read(ready_fd, &ch, 1));
  test_assert(ch == 'R');
  switch (event) {
    case PTRACE_EVENT_CLONE:
      test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
      test_assert(0 == pthread_join(thread, NULL));
      break;
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
      pid = event == PTRACE_EVENT_FORK ? fork() : vfork();
      if (!pid) {
        _exit(0);
      }
      test_assert(pid == waitpid(pid, &status, 0));
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      break;
    case PTRACE_EVENT_EXEC:
      sprintf(fd_str, "%d", status_pipe[1]);
      execl(exe, exe, fd_str, NULL);
      test_assert(0);
      break;
  }
  report_done(status_pipe[1]);
}

static int run_ptracer(int event) {
  pid_t child;
  int status;
  int ready_pipe[2];
  char ready = 'R';

  test_assert(0 == pipe(ready_pipe));

  if (0 == (child = fork())) {
    run_tracee(event, ready_pipe[0]);
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                                  PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)));
  test_assert(1 == write(ready_pipe[1], &ready, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((event << 16) | (SIGTRAP << 8) | 0x7f));
  /* Now just exit, and the child should resume */
  return 44;
}

int main(int argc, char* argv[]) {
  pid_t ptracer;
  int status;
  size_t i;

  if (argc == 2) {
    /* We were exec'ed by a tracee. */
    report_done(atoi(argv[1]));
    return 77;
  }
  exe = argv[0];

  test_assert(0 == pipe(status_pipe));

  for (i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
    char ch = 0;

    if (0 == (ptracer = fork())) {
      return run_ptracer(events[i]);
    }

    test_assert(ptracer == waitpid(ptracer, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);

    test_assert(1 == read(status_pipe[0], &ch, 1));
    test_assert(ch == 'K');
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
