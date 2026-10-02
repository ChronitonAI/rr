/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer watches the buffer of its tracee's read() with hardware
   watchpoints. The kernel's copy to the buffer doesn't trigger them, so the
   tracer must see no SIGTRAP until the tracee itself writes to the buffer. */

// The 4 lowest bits of DR6.
#define DR_TRAP_BITS 0xf
#define DR_OFFSET(i) ((void*)offsetof(struct user, u_debugreg[i]))
/* DR7: DR0 and DR1 enabled, break on write, DR0 1 byte, DR1 4 bytes. */
#define DR7_VALUE 0xd10005

static char buf[4096] __attribute__((aligned(8)));
static int go_fds[2];
static int data_fds[2];

static void child(void) {
  struct sigaction sa;
  sigset_t set;
  char ch;
  size_t i;

  /* When the kernel sends a SIGTRAP for a watchpoint, it unblocks it and
     resets its handler to SIG_DFL. That must not happen here either. */
  test_assert(SIG_ERR != signal(SIGTRAP, SIG_IGN));
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));

  test_assert(1 == read(go_fds[0], &ch, 1));
  test_assert(sizeof(buf) == read(data_fds[0], buf, sizeof(buf)));
  for (i = 0; i < sizeof(buf); ++i) {
    test_assert(buf[i] == (char)i);
  }

  test_assert(0 == sigaction(SIGTRAP, NULL, &sa));
  test_assert(sa.sa_handler == SIG_IGN);
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &set));
  test_assert(sigismember(&set, SIGTRAP));

  raise(SIGUSR1);

  /* This write triggers the DR0 watchpoint. */
  *(volatile char*)&buf[0] = 1;
  exit(77);
}

int main(void) {
  static char data[sizeof(buf)];
  pid_t pid;
  int status;
  char ch;
  size_t i;

  test_assert(0 == pipe(go_fds));
  test_assert(0 == pipe(data_fds));

  /* rr doesn't patch syscalls in a task that has a ptracer. Do a read() here,
     so that the child's read()s can use the syscall buffer. */
  test_assert(1 == write(go_fds[1], "x", 1));
  test_assert(1 == read(go_fds[0], &ch, 1));

  if (0 == (pid = fork())) {
    child();
  }

  test_assert(0 == ptrace(PTRACE_ATTACH, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(0), &buf[0]));
  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(1), &buf[2048]));
  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7),
                          (void*)DR7_VALUE));

  for (i = 0; i < sizeof(data); ++i) {
    data[i] = (char)i;
  }
  test_assert(sizeof(data) == write(data_fds[1], data, sizeof(data)));
  test_assert(1 == write(go_fds[1], "x", 1));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == (ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET(6), NULL) &
                    DR_TRAP_BITS));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0x1 == (ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET(6), NULL) &
                      DR_TRAP_BITS));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
