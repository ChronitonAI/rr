/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A tracer watches the buffers of its tracee's read()s, poll() and
   sigprocmask()s with hardware watchpoints. The kernel's accesses to the
   buffers don't trigger them, so the tracer must see no SIGTRAP until the
   tracee itself accesses a buffer. On aarch64, a watchpoint traps before the
   access. */

struct hwdebug_state {
  uint32_t dbg_info;
  uint32_t pad;
  struct {
    uint64_t addr;
    uint32_t ctrl;
    uint32_t pad;
  } dbg_regs[16];
};

/* Watchpoint control: enabled, EL0, the given load/store type and byte
   address select mask (within the 8-byte aligned doubleword). */
#define WATCH_LOAD 1
#define WATCH_STORE 2
#define WCR(type, bytes) (((bytes) << 5) | ((type) << 3) | (2 << 1) | 1)

#define SIZE 4096
/* The bytes that the two watchpoints watch during the read()s. */
#define WATCHED(i) ((i) * SIZE / 2 + 64)

static char buf[SIZE] __attribute__((aligned(8)));
static struct pollfd pfd __attribute__((aligned(8)));
static sigset_t oldset __attribute__((aligned(8)));
static volatile int sigtrap_count;

static void sigtrap_handler(__attribute__((unused)) int sig) {
  ++sigtrap_count;
}
static int go_fds[2];
static int data_fds[2];

static void set_watchpoints(pid_t pid, uint64_t addr0, uint32_t ctrl0,
                            uint64_t addr1, uint32_t ctrl1) {
  struct hwdebug_state state;
  struct iovec iov = { &state, offsetof(struct hwdebug_state, dbg_regs[2]) };
  memset(&state, 0, sizeof(state));
  state.dbg_regs[0].addr = addr0;
  state.dbg_regs[0].ctrl = ctrl0;
  state.dbg_regs[1].addr = addr1;
  state.dbg_regs[1].ctrl = ctrl1;
  test_assert(0 == ptrace(PTRACE_SETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov));
}

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
     triggers a watchpoint. The first read() doesn't block, the second
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

  /* Now a watchpoint watches pfd.events and pfd.revents for loads and
     stores. poll() reads and writes them. Another one watches oldset for
     stores. */
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

  /* This load triggers the watchpoint. */
  test_assert(*(volatile short*)&pfd.revents == POLLOUT);
  exit(77);
}

int main(void) {
  static char data[SIZE];
  struct hwdebug_state state;
  struct iovec iov = { &state, sizeof(state) };
  siginfo_t si;
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

  memset(&state, 0, sizeof(state));
  test_assert(0 == ptrace(PTRACE_GETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov));
  /* The architecture guarantees at least two watchpoints. */
  test_assert((state.dbg_info & 0xff) >= 2);
  set_watchpoints(pid, (uintptr_t)&buf[WATCHED(0)], WCR(WATCH_STORE, 0x1),
                  (uintptr_t)&buf[WATCHED(1)], WCR(WATCH_STORE, 0x1));

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

  /* pfd.events and pfd.revents are bytes 4 to 7 of pfd. */
  set_watchpoints(pid, (uintptr_t)&pfd, WCR(WATCH_LOAD | WATCH_STORE, 0xf0),
                  (uintptr_t)&oldset, WCR(WATCH_STORE, 0xff));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR2 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, pid, NULL, &si));
  test_assert(si.si_code == TRAP_HWBKPT);

  /* The load hasn't happened yet. Let it. */
  set_watchpoints(pid, 0, 0, 0, 0);
  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
