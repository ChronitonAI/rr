/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer watches the buffers of its tracee's read()s with hardware
   watchpoints. The kernel's copies to the buffers don't trigger them, so the
   tracer must see no SIGTRAP until the tracee itself writes to a buffer. */

// The 4 lowest bits of DR6.
#define DR_TRAP_BITS 0xf
#define DR_OFFSET(i) ((void*)offsetof(struct user, u_debugreg[i]))
/* DR7: DR0-DR3 enabled, break on write, DR0 and DR2 1 byte, DR1 and DR3
   4 bytes. */
#define DR7_VALUE 0xd1d10055

#define SIZE 4096
/* The bytes that DR0-DR3 watch. */
#define WATCHED(i) ((i) * SIZE / 4 + 64)

static char buf[SIZE] __attribute__((aligned(8)));
static int go_fds[2];
static int data_fds[2];

static void check_sigtrap(void (*handler)(int), int blocked) {
  struct sigaction sa;
  sigset_t set;
  test_assert(0 == sigaction(SIGTRAP, NULL, &sa));
  test_assert(sa.sa_handler == handler);
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &set));
  test_assert(sigismember(&set, SIGTRAP) == blocked);
}

/* Wait until |pid| sleeps, i.e. blocks in its second read(). */
static void wait_for_sleep(pid_t pid) {
  struct timespec ts = { 0, 1000000 };
  char path[64];
  sprintf(path, "/proc/%d/stat", pid);
  while (1) {
    char line[1024];
    char* p;
    int fd = open(path, O_RDONLY);
    ssize_t len;
    test_assert(fd >= 0);
    len = read(fd, line, sizeof(line) - 1);
    test_assert(len > 0);
    test_assert(0 == close(fd));
    line[len] = 0;
    p = strrchr(line, ')');
    test_assert(p != NULL);
    if (p[2] == 'S') {
      return;
    }
    nanosleep(&ts, NULL);
  }
}

static void child(void) {
  sigset_t set;
  char ch;
  int i;

  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  test_assert(1 == read(go_fds[0], &ch, 1));

  /* When the kernel sends a SIGTRAP for a watchpoint, it unblocks it and
     resets its handler to SIG_DFL. That must not happen here. Each read()
     triggers two watchpoints. The first read() doesn't block, the second
     does. */
  test_assert(SIG_ERR != signal(SIGTRAP, SIG_IGN));
  test_assert(SIZE / 2 == read(data_fds[0], buf, SIZE / 2));
  check_sigtrap(SIG_IGN, 0);

  test_assert(SIG_ERR != signal(SIGTRAP, SIG_DFL));
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
  test_assert(SIZE / 2 == read(data_fds[0], buf + SIZE / 2, SIZE / 2));
  check_sigtrap(SIG_DFL, 1);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &set, NULL));

  for (i = 0; i < SIZE; ++i) {
    test_assert(buf[i] == (char)i);
  }

  raise(SIGUSR1);

  /* This write triggers the DR0 watchpoint. */
  *(volatile char*)&buf[WATCHED(0)] = 1;
  exit(77);
}

int main(void) {
  static char data[SIZE];
  pid_t pid;
  int status;
  char ch;
  int i;

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

  for (i = 0; i < 4; ++i) {
    test_assert(0 ==
                ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(i), &buf[WATCHED(i)]));
  }
  test_assert(0 ==
              ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), (void*)DR7_VALUE));

  for (i = 0; i < SIZE; ++i) {
    data[i] = (char)i;
  }
  test_assert(SIZE / 2 == write(data_fds[1], data, SIZE / 2));
  test_assert(1 == write(go_fds[1], "x", 1));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  wait_for_sleep(pid);
  test_assert(SIZE / 2 == write(data_fds[1], data + SIZE / 2, SIZE / 2));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(
      0 == (ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET(6), NULL) & DR_TRAP_BITS));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(
      0x1 == (ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET(6), NULL) & DR_TRAP_BITS));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
