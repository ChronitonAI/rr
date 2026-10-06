/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrcalls.h"
#include "util.h"
#include <linux/net.h>

/* Syscalls whose pointer arguments point to memory that isn't mapped, or
   whose counts are invalid, must fail as they do without rr. rr must not
   assert when it reads that memory, before or after the syscall, e.g. to
   record a failed syscall's output. Whatever the kernel wrote before it
   failed must be recorded. */

#define BAD ((void*)8)

static void check_error(long ret, int err) {
  test_assert(ret == -1);
  test_assert(errno == err);
}

static void check_efault(long ret) { check_error(ret, EFAULT); }

/* The syscall buffer handles this syscall unless it's disabled. */
static void check_syscallbuf_used(void) {
  long ret = syscall(SYS_rrcall_check_presence,
                     RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED, 0, 0, 0, 0, 0);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));
}

/* Syscalls that fail to write their results */
static void check_outputs(void) {
  int fd = open("/dev/zero", O_RDONLY);
  /* We can't write to shared memory that the tracee can't write either. */
  void* shared_ro = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  test_assert(fd >= 0);
  test_assert(shared_ro != MAP_FAILED);
  check_efault(syscall(SYS_uname, BAD));
  check_efault(syscall(SYS_uname, shared_ro));
  check_efault(syscall(SYS_sysinfo, BAD));
  check_efault(syscall(SYS_times, BAD));
  check_efault(syscall(SYS_getrusage, RUSAGE_SELF, BAD));
  check_efault(syscall(SYS_gettimeofday, BAD, NULL));
  check_efault(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, BAD));
  check_efault(syscall(SYS_getitimer, ITIMER_REAL, BAD));
  check_efault(syscall(SYS_rt_sigpending, BAD, 8));
  check_efault(syscall(SYS_pipe2, BAD, 0));
  check_efault(syscall(SYS_read, fd, BAD, 16));
  test_assert(0 == close(fd));
}

static void segv_handler(__attribute__((unused)) int sig) {
  atomic_puts("FAILED: SIGSEGV handler ran");
  _exit(1);
}

/* Make rr handle a SIGSEGV itself. The kernel resets SIGSEGV's disposition
   and unblocks it, and rr must restore them. */
static void trap(int zero_fd, char* ro_page) {
#if defined(__x86_64__) || defined(__i386__)
  /* rr traps rdtsc. */
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
#endif
  /* The syscall buffer's check of the buffer faults. */
  check_efault(read(zero_fd, ro_page, 1));
}

struct kernel_sigaction {
  void* handler;
  unsigned long flags;
  void* restorer;
  uint64_t mask;
};

/* rt_sigprocmask() and rt_sigaction() change the mask or the action before
   they fail to store the old one. rr must notice. */
static void check_signal_state(void) {
  char* ro_page = (char*)mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int zero_fd = open("/dev/zero", O_RDONLY);
  struct sigaction sa;
  struct kernel_sigaction ksa;
  sigset_t set;
  sigset_t old;

  test_assert(ro_page != MAP_FAILED);
  test_assert(zero_fd >= 0);
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = segv_handler;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

  sigemptyset(&set);
  sigaddset(&set, SIGSEGV);
  check_efault(syscall(SYS_rt_sigprocmask, SIG_BLOCK, &set, BAD, 8));
  trap(zero_fd, ro_page);
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &old));
  test_assert(sigismember(&old, SIGSEGV));
  test_assert(0 == sigaction(SIGSEGV, NULL, &sa));
  test_assert(sa.sa_handler == segv_handler);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &set, NULL));

  memset(&ksa, 0, sizeof(ksa));
  ksa.handler = (void*)SIG_IGN;
  check_efault(syscall(SYS_rt_sigaction, SIGSEGV, &ksa, BAD, 8));
  trap(zero_fd, ro_page);
  test_assert(0 == sigaction(SIGSEGV, NULL, &sa));
  test_assert(sa.sa_handler == SIG_IGN);
  test_assert(SIG_ERR != signal(SIGSEGV, SIG_DFL));
  test_assert(0 == close(zero_fd));
}

static void check_signals(void) {
  int hows[] = { SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK };
  size_t i;

  for (i = 0; i < sizeof(hows) / sizeof(hows[0]); ++i) {
    check_efault(syscall(SYS_rt_sigprocmask, hows[i], BAD, NULL, 8));
  }
  check_efault(syscall(SYS_rt_sigaction, SIGUSR1, BAD, NULL, 8));
  check_efault(syscall(SYS_rt_sigsuspend, BAD, 8));
  check_efault(syscall(SYS_rt_sigtimedwait, BAD, NULL, NULL, 8));
  check_efault(syscall(SYS_ppoll, NULL, 0, NULL, BAD, 8));
  check_efault(syscall(SYS_pselect6, 0, NULL, NULL, NULL, NULL, BAD));
}

static void check_old_syscalls(void) {
#ifdef __i386__
  /* These take a pointer to their arguments. */
  check_efault(syscall(SYS_mmap, BAD));
  check_efault(syscall(SYS_select, BAD));
#endif
}

static void check_iovecs(void) {
  int fd = open("/dev/zero", O_RDONLY);
  char buf[16];
  struct iovec iov = { buf, sizeof(buf) };

  test_assert(fd >= 0);
  check_efault(syscall(SYS_readv, fd, BAD, 1));
  check_error(syscall(SYS_readv, fd, &iov, -1), EINVAL);
  check_efault(syscall(SYS_preadv, fd, BAD, 1, 0, 0));
  check_efault(syscall(SYS_process_vm_readv, getpid(), BAD, 1, &iov, 1, 0));
  check_error(syscall(SYS_process_vm_readv, getpid(), &iov, 1025, &iov, 1, 0),
              EINVAL);
  check_efault(syscall(SYS_process_vm_writev, getpid(), &iov, 1, BAD, 1, 0));
  test_assert(0 == close(fd));
}

static void check_sockets(char* unmapped) {
  int sock_fds[2];
  int inet_fd;
  char buf[16];
  struct iovec iov = { buf, sizeof(buf) };
  struct msghdr msg;
  struct mmsghdr* msgs;
  struct sockaddr_un addr;
  socklen_t* bad_len = (socklen_t*)unmapped;
  int val;
  socklen_t val_len = sizeof(val);

  test_assert(0 == socketpair(AF_UNIX, SOCK_DGRAM, 0, sock_fds));
#ifdef SYS_socketcall
  check_efault(syscall(SYS_socketcall, SYS_RECV, BAD));
  check_efault(syscall(SYS_socketcall, SYS_RECVMSG, BAD));
#endif
  check_efault(recvmsg(sock_fds[0], NULL, 0));
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1025;
  check_error(recvmsg(sock_fds[0], &msg, 0), EMSGSIZE);
  check_efault(recvmmsg(sock_fds[0], NULL, 1, 0, NULL));
  check_efault(getpeername(sock_fds[0], (struct sockaddr*)&addr, bad_len));
  check_efault(getsockname(sock_fds[0], (struct sockaddr*)&addr, bad_len));
  check_efault(getsockopt(sock_fds[0], SOL_SOCKET, SO_TYPE, &val, bad_len));
  check_efault(getsockopt(sock_fds[0], SOL_SOCKET, SO_TYPE, BAD, &val_len));

  /* recvfrom() receives the message, then fails to read the address
     length. */
  memset(buf, 0, sizeof(buf));
  test_assert(5 == write(sock_fds[1], "hello", 5));
  check_efault(recvfrom(sock_fds[0], buf, sizeof(buf), 0,
                        (struct sockaddr*)&addr, bad_len));
  test_assert(!memcmp(buf, "hello", 5));

  /* recvmmsg() receives one message, then fails to read the second
     mmsghdr. That returns 1 (and makes the socket report EFAULT later). */
  memset(buf, 0, sizeof(buf));
  msgs = (struct mmsghdr*)unmapped - 1;
  memset(msgs, 0, sizeof(*msgs));
  msgs->msg_hdr.msg_iov = &iov;
  msgs->msg_hdr.msg_iovlen = 1;
  test_assert(5 == write(sock_fds[1], "again", 5));
  test_assert(1 == recvmmsg(sock_fds[0], msgs, 2, 0, NULL));
  test_assert(msgs->msg_len == 5);
  test_assert(!memcmp(buf, "again", 5));

  inet_fd = socket(AF_INET, SOCK_DGRAM, 0);
  test_assert(inet_fd >= 0);
  check_efault(ioctl(inet_fd, SIOCGIFCONF, BAD));
}

static void check_waits(void) {
  long ret;

  check_error(syscall(SYS_wait4, -1, BAD, 0, BAD), ECHILD);
  /* With no children, waitid() fails to clear |infop|. */
  ret = syscall(SYS_waitid, P_ALL, 0, BAD, WEXITED | WNOHANG, BAD);
  test_assert(ret == -1);
  test_assert(errno == EFAULT || errno == ECHILD);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* pages;
  char* unmapped;

  /* Make sure that the syscall buffer still handles syscalls after it gave
     up on these. */
  check_outputs();
  check_syscallbuf_used();
  check_signals();
  check_syscallbuf_used();
  check_signal_state();
  check_syscallbuf_used();
  check_iovecs();
  check_syscallbuf_used();

  /* An unmapped page right after a mapped one. Nothing may get mapped there
     before check_sockets uses it. */
  pages = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(pages != MAP_FAILED);
  unmapped = pages + page_size;
  test_assert(0 == munmap(unmapped, page_size));
  check_sockets(unmapped);
  check_syscallbuf_used();
  check_waits();
  check_old_syscalls();
  check_syscallbuf_used();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
