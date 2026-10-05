/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

/* Group-stop |child| with SIGSTOP. */
static void group_stop(pid_t child) {
  int status;

  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
}

/* A SIGCONT ends a group stop when it's sent. Then PTRACE_INTERRUPT stops
   have SIGTRAP, also while the SIGCONT is pending, and if the process never
   dequeues it: a stop signal sent after it discards it. This child doesn't
   make syscalls, so its stops aren't in one. */
static void sigcont_sent(void) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    for (;;) {
    }
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  group_stop(child);

  /* Linux also reports a PTRACE_EVENT_STOP for the SIGCONT, before its
     signal-delivery stop. That may be the same stop as the
     PTRACE_INTERRUPT's. (Under rr, the child may get to the signal-delivery
     stop first.) */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  for (;;) {
    test_assert(child == waitpid(child, &status, 0));
    if (status == ((SIGCONT << 8) | 0x7f)) {
      break;
    }
    test_assert(status ==
                ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  }

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  group_stop(child);

  test_assert(0 == kill(child, SIGCONT));
  test_assert(0 == kill(child, SIGTSTP));
  /* Linux reports a PTRACE_EVENT_STOP for the SIGCONT before the SIGTSTP's
     signal-delivery stop, but rr doesn't emulate that. */
  do {
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
    test_assert(child == waitpid(child, &status, 0));
  } while (status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(status == ((SIGTSTP << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));

  test_assert(0 == kill(child, SIGKILL));
  do {
    test_assert(child == waitpid(child, &status, 0));
  } while (!WIFSIGNALED(status));
}

int main(void) {
  pid_t child;
  char ch;
  int status;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(child_to_parent_fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    test_assert(1 == write(child_to_parent_fds[1], "x", 1));
    sleep(10000);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  /* Make sure child is still running */
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));

  /* Stop it */
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  /* Most likely there is no context switch between these two syscalls, rr does
   * not actually restart the tracee, and this PTRACE_INTERRUPT sees the task
   * is already stopped internally, and is emulated as a noop.
   */
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  test_assert(WIFSTOPPED(status));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  /* Use a sched_yield() to force rr to context switch and restart the tracee,
   * so when we PTRACE_INTERRUPT below rr is forced to PTRACE_INTERRUPT the
   * tracee.
   */
  sched_yield();
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  test_assert(WIFSTOPPED(status));

  /* SIGCONT ends the group stop. Linux reports a PTRACE_EVENT_STOP for it
     before the signal-delivery stop, but rr doesn't emulate that. */
  test_assert(0 == kill(child, SIGCONT));
  do {
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
    test_assert(child == waitpid(child, &status, 0));
  } while (status != ((SIGCONT << 8) | 0x7f));

  /* Without a group stop, PTRACE_INTERRUPT stops have SIGTRAP. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, 0));
  sched_yield();
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGTRAP << 8) | 0x7f));

  test_assert(0 == kill(child, SIGKILL));

  sigcont_sent();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
