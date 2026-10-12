/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* If our SIGCHLD handler has SA_NOCLDSTOP, or we ignore SIGCHLD, a child
   that stops or is continued must not send us a SIGCHLD, and neither must a
   tracee's ptrace stop. Our waits must still report the stops. We keep
   SIGCHLD blocked, so a SIGCHLD that is sent stays pending. Each mode runs
   in its own process. */

enum {
  /* The SIGCHLD handler has SA_NOCLDSTOP. */
  NOCLDSTOP,
  /* SIGCHLD is ignored. */
  IGNORED,
  /* The SIGCHLD handler has SA_NOCLDSTOP, and a tracee stops. */
  PTRACE_STOP,
  /* SIGCHLD was SIG_DFL with SA_NOCLDSTOP before an exec, which clears
     SA_NOCLDSTOP. */
  AFTER_EXEC,
  /* The SIGCHLD handler had SA_RESETHAND and SA_NOCLDSTOP, and ran once.
     Only the handler is reset, so SA_NOCLDSTOP stays. */
  AFTER_RESETHAND,
  NUM_MODES
};

static volatile int sigchld_codes[8];
static volatile int num_sigchlds;

static int pipe_fds[2];

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  if (num_sigchlds < 8) {
    sigchld_codes[num_sigchlds] = si->si_code;
  }
  ++num_sigchlds;
}

static void set_sigchld_handler(int flags) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART | flags;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
}

static void set_sigchld_disposition(sighandler_t disposition, int flags) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = disposition;
  sa.sa_flags = flags;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
}

static void block_sigchld(void) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
}

static int is_sigchld_pending(void) {
  sigset_t pending;
  test_assert(0 == sigpending(&pending));
  return sigismember(&pending, SIGCHLD);
}

static void wait_for_sigchld(int code) {
  sigset_t unblocked;
  int n = num_sigchlds;
  sigemptyset(&unblocked);
  while (num_sigchlds == n) {
    sigsuspend(&unblocked);
  }
  test_assert(num_sigchlds == n + 1);
  test_assert(sigchld_codes[n] == code);
}

/* Fork a child that stops itself, wait for the stop, continue the child and
   wait for that. */
static pid_t stop_and_continue_child(void) {
  pid_t child;
  int status;
  char ch;

  test_assert(0 == pipe(pipe_fds));
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, WCONTINUED));
  test_assert(WIFCONTINUED(status));
  return child;
}

static void finish_child(pid_t child) {
  int status;
  char ch = 'x';
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void run(int mode, char* exe) {
  pid_t child;
  int status;

  block_sigchld();
  switch (mode) {
    case NOCLDSTOP:
      set_sigchld_handler(SA_NOCLDSTOP);
      child = stop_and_continue_child();
      test_assert(!is_sigchld_pending());
      finish_child(child);
      wait_for_sigchld(CLD_EXITED);
      break;
    case IGNORED:
      set_sigchld_disposition(SIG_IGN, 0);
      child = stop_and_continue_child();
      test_assert(!is_sigchld_pending());
      /* Otherwise the child would be reaped when it exits. */
      set_sigchld_disposition(SIG_DFL, 0);
      finish_child(child);
      break;
    case PTRACE_STOP:
      set_sigchld_handler(SA_NOCLDSTOP);
      if (0 == (child = fork())) {
        test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
        raise(SIGUSR1);
        exit(77);
      }
      test_assert(child == waitpid(child, &status, 0));
      test_assert(status == ((SIGUSR1 << 8) | 0x7f));
      test_assert(!is_sigchld_pending());
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
      test_assert(child == waitpid(child, &status, 0));
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
      wait_for_sigchld(CLD_EXITED);
      break;
    case AFTER_EXEC: {
      char* argv[] = { exe, "after-exec", NULL };
      set_sigchld_disposition(SIG_DFL, SA_NOCLDSTOP);
      execv("/proc/self/exe", argv);
      test_assert(0);
      break;
    }
    case AFTER_RESETHAND:
      set_sigchld_handler(SA_NOCLDSTOP | SA_RESETHAND);
      if (0 == (child = fork())) {
        exit(0);
      }
      test_assert(child == waitpid(child, &status, 0));
      wait_for_sigchld(CLD_EXITED);
      child = stop_and_continue_child();
      test_assert(!is_sigchld_pending());
      finish_child(child);
      break;
  }
}

static void run_after_exec(void) {
  pid_t child = stop_and_continue_child();
  /* SIGCHLD is still blocked, and we get it for the stop. */
  test_assert(is_sigchld_pending());
  finish_child(child);
}

int main(int argc, char** argv) {
  int mode;
  pid_t runner;
  int status;

  if (argc > 1 && !strcmp(argv[1], "after-exec")) {
    run_after_exec();
    return 0;
  }

  for (mode = 0; mode < NUM_MODES; ++mode) {
    if (0 == (runner = fork())) {
      run(mode, argv[0]);
      return 0;
    }
    test_assert(runner == waitpid(runner, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
