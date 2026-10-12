/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif

/* A ptracer that set PTRACE_O_EXITKILL exits. Its tracee must get SIGKILL,
   whether it's running, in a signal-delivery-stop or in a group-stop.
   But if the tracee's process is already exiting (at the PTRACE_EVENT_EXIT
   of its exit_group(), or of the exit() of its last thread), Linux 6.1 and
   later drop the SIGKILL and the tracee exits normally. (Some older
   distribution kernels do too.) The ptracer is not the tracee's parent. */

enum {
  RUNNING,
  SIGNAL_STOP,
  GROUP_STOP,
  /* The ptracer exits at the tracee's PTRACE_EVENT_EXIT for exit_group(). */
  EXIT_EVENT,
  /* The tracee is the second thread of its process. The main thread has
     exited, and the ptracer exits at the tracee's PTRACE_EVENT_EXIT for
     exit(). */
  LAST_THREAD_EXIT,
  /* As LAST_THREAD_EXIT, but there are two such threads, and the ptracer
     traces both, and exits when both are at their PTRACE_EVENT_EXIT. */
  TWO_THREADS_EXIT,
  NUM_CASES
};

/* The second thread of TWO_THREADS_EXIT uses ready_pipe2 and go_pipe2. */
static int ready_pipe[2];
static int go_pipe[2];
static int ready_pipe2[2];
static int go_pipe2[2];
static int main_gone_pipe[2];
static pthread_t main_thread;

/* Linux 6.1 and later mark a process as exiting at the start of an
   exit_group(), even for a single thread (do_group_exit()), and when its
   last thread exits. Some older distribution kernels do too, so we can't
   tell from the version. */
static int kernel_marks_process_exit_early(void) {
  struct utsname buf;
  int major = 0;
  int minor = 0;
  test_assert(0 == uname(&buf));
  test_assert(2 == sscanf(buf.release, "%d.%d", &major, &minor));
  return major > 6 || (major == 6 && minor >= 1);
}

static void* last_thread(void* p) {
  pid_t tid = sys_gettid();
  char ch = 'x';
  test_assert(sizeof(tid) ==
              write((p ? ready_pipe2 : ready_pipe)[1], &tid, sizeof(tid)));
  test_assert(1 == read((p ? go_pipe2 : go_pipe)[0], &ch, 1));
  /* Wait until the main thread has exited. */
  if (p) {
    test_assert(1 == read(main_gone_pipe[0], &ch, 1));
  } else {
    test_assert(0 == pthread_join(main_thread, NULL));
    test_assert(1 == write(main_gone_pipe[1], &ch, 1));
  }
  syscall(SYS_exit, 77);
  return NULL;
}

static void run_case(int c) {
  pid_t child;
  pid_t traced;
  pid_t traced2 = 0;
  pid_t ptracer;
  int status;
  int cont_pipe[2];
  char ch = 'X';

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(ready_pipe2));
  test_assert(0 == pipe(go_pipe2));
  test_assert(0 == pipe(cont_pipe));
  test_assert(0 == pipe(main_gone_pipe));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    if (c == LAST_THREAD_EXIT || c == TWO_THREADS_EXIT) {
      pthread_t thread;
      main_thread = pthread_self();
      test_assert(0 == pthread_create(&thread, NULL, last_thread, NULL));
      if (c == TWO_THREADS_EXIT) {
        test_assert(0 == pthread_create(&thread, NULL, last_thread, (void*)1));
      }
      pthread_exit(NULL);
    }
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    if (c == SIGNAL_STOP) {
      raise(SIGUSR1);
    } else if (c == GROUP_STOP) {
      raise(SIGSTOP);
    } else if (c == EXIT_EVENT) {
      exit(77);
    }
    /* If we weren't killed, this lets us exit normally. */
    test_assert(1 == read(cont_pipe[0], &ch, 1));
    exit(77);
  }

  /* Make sure the prctl has happened before the ptracer attaches. */
  if (c == LAST_THREAD_EXIT || c == TWO_THREADS_EXIT) {
    test_assert(sizeof(traced) == read(ready_pipe[0], &traced, sizeof(traced)));
    if (c == TWO_THREADS_EXIT) {
      test_assert(sizeof(traced2) ==
                  read(ready_pipe2[0], &traced2, sizeof(traced2)));
    }
  } else {
    test_assert(1 == read(ready_pipe[0], &ch, 1));
    traced = child;
  }
  if (0 == (ptracer = fork())) {
    long options = PTRACE_O_EXITKILL;
    if (c == EXIT_EVENT || c == LAST_THREAD_EXIT || c == TWO_THREADS_EXIT) {
      options |= PTRACE_O_TRACEEXIT;
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, traced, NULL, (void*)options));
    test_assert(1 == write(go_pipe[1], &ch, 1));
    if (traced2) {
      test_assert(0 == ptrace(PTRACE_SEIZE, traced2, NULL, (void*)options));
      test_assert(1 == write(go_pipe2[1], &ch, 1));
    }
    if (c == SIGNAL_STOP) {
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    } else if (c == GROUP_STOP) {
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGSTOP << 8) | 0x7f));
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status ==
                  ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
    } else if (c != RUNNING) {
      test_assert(traced == waitpid(traced, &status, __WALL));
      test_assert(status ==
                  ((PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f));
      if (traced2) {
        test_assert(traced2 == waitpid(traced2, &status, __WALL));
        test_assert(status ==
                    ((PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f));
      }
    }
    /* Now just exit. The child should get SIGKILL. */
    exit(44);
  }

  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);

  if (c == EXIT_EVENT || c == LAST_THREAD_EXIT || c == TWO_THREADS_EXIT) {
    test_assert(child == waitpid(child, &status, 0));
    if (kernel_marks_process_exit_early()) {
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    } else {
      test_assert((WIFEXITED(status) && WEXITSTATUS(status) == 77) ||
                  (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL));
    }
    return;
  }
  /* The ptracer's exit sent the child SIGKILL before we could see that
     exit, so the child can't exit normally anymore. */
  test_assert(1 == write(cont_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
  int c;
  for (c = 0; c < NUM_CASES; ++c) {
    run_case(c);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
