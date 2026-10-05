/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer watches the buffers of its tracee's read()s, poll() and
   sigprocmask()s with hardware watchpoints. The kernel's accesses to the
   buffers don't trigger them, so the tracer must see no SIGTRAP until the
   tracee itself accesses a buffer. */

// The 4 lowest bits of DR6.
#define DR_TRAP_BITS 0xf
#define DR_OFFSET(i) ((void*)offsetof(struct user, u_debugreg[i]))
/* DR7: DR0-DR3 enabled, break on write, DR0 and DR2 1 byte, DR1 and DR3
   4 bytes. */
#define DR7_VALUE 0xd1d10055
/* DR7: DR0 enabled, break on read or write, 4 bytes; DR1 enabled, break on
   write, 4 bytes. */
#define DR7_VALUE_POLL 0xdf0005

#define SIZE 4096
/* The bytes that DR0-DR3 watch. */
#define WATCHED(i) ((i) * SIZE / 4 + 64)

static char buf[SIZE] __attribute__((aligned(8)));
static struct pollfd pfd __attribute__((aligned(8)));
static sigset_t oldset __attribute__((aligned(8)));
static volatile int sigtrap_count;

static void sigtrap_handler(__attribute__((unused)) int sig) {
  ++sigtrap_count;
}
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
  pfd.fd = data_fds[1];
  pfd.events = POLLOUT;

  raise(SIGUSR1);

  /* Now DR0 watches pfd.events and pfd.revents for reads and writes. poll()
     reads and writes them. DR1 watches oldset for writes. */
  test_assert(1 == poll(&pfd, 1, 0));
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, &oldset));
  check_sigtrap(SIG_DFL, 1);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &set, NULL));
  raise(SIGUSR1);

  /* SIGUSR2 is pending when sigprocmask() unblocks it, so the tracer gets it
     right after the syscall. Meanwhile, rr blocks all signals, SIGTRAP too, so
     the kernel resets SIGTRAP's handler. That must not happen here either. */
  test_assert(SIG_ERR != signal(SIGTRAP, sigtrap_handler));
  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
  raise(SIGUSR2);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &set, &oldset));
  test_assert(sigismember(&oldset, SIGUSR2));
  check_sigtrap(sigtrap_handler, 0);
  raise(SIGUSR1);

  /* This read triggers the DR0 watchpoint. The tracer suppresses the
     SIGTRAP. */
  test_assert(*(volatile short*)&pfd.revents == POLLOUT);
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

  /* rr doesn't patch syscalls in a task that has a ptracer. Do a read(), a
     poll() and a sigprocmask() here, so that the child's can use the syscall
     buffer. */
  test_assert(1 == write(go_fds[1], "x", 1));
  test_assert(1 == read(go_fds[0], &ch, 1));
  pfd.fd = go_fds[1];
  pfd.events = POLLOUT;
  test_assert(1 == poll(&pfd, 1, 0));
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &oldset));

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

  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), NULL));
  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(0), &pfd.events));
  test_assert(0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(1), &oldset));
  test_assert(
      0 == ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), (void*)DR7_VALUE_POLL));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(
      0 == (ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET(6), NULL) & DR_TRAP_BITS));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR2 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
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
