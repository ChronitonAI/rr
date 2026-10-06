/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrcalls.h"
#include "util.h"

/* Buffered syscalls whose memory the tracee can't access, or whose pointers
   are null, must fail as they do without rr instead of faulting in the
   syscallbuf code. Whatever the kernel wrote before failing must be
   recorded. Afterwards, the syscall buffer must still be in use. See also
   syscallbuf_efault. */

#ifdef SYS_fstat64
#define FSTAT_SYSCALL SYS_fstat64
#else
#define FSTAT_SYSCALL SYS_fstat
#endif

static size_t page_size;
static char* ro_page;
static char* none_page;
static int zero_fd;
static int sock_fds[2];

static void handler(int sig) {
  atomic_printf("FAILED: handler for signal %d ran\n", sig);
  _exit(1);
}

static void check_error(ssize_t ret, int err) {
  test_assert(ret == -1);
  test_assert(errno == err);
}

static void check_efault(ssize_t ret) { check_error(ret, EFAULT); }

/* The syscall buffer handles this syscall unless it's disabled. */
static void check_syscallbuf_used(void) {
  long ret = syscall(SYS_rrcall_check_presence,
                     RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED, 0, 0, 0, 0, 0);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));
}

static void send_hello(void) {
  test_assert(5 == write(sock_fds[1], "hello", 5));
}

static void check_bad_buffer(char* bad, int readable) {
  char buf[16];
  struct iovec iov = { bad, 5 };
  struct msghdr msg;

  send_hello();
  check_efault(recv(sock_fds[0], bad, 5, 0));
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  check_efault(recvmsg(sock_fds[0], &msg, 0));
  if (!readable) {
    check_efault(recvmsg(sock_fds[0], (struct msghdr*)bad, 0));
  }
  test_assert(5 == recv(sock_fds[0], buf, 5, 0));
  test_assert(!memcmp(buf, "hello", 5));

  /* Not fstat(): 32-bit glibc converts the kernel's struct itself. */
  check_efault(syscall(FSTAT_SYSCALL, zero_fd, bad));
  check_efault(syscall(SYS_getrandom, bad, 16, GRND_NONBLOCK));
  check_efault(readlink("/proc/self/exe", bad, 16));
  check_efault(poll((struct pollfd*)bad, 1, 0));
  if (!readable) {
    check_efault(open(bad, O_RDONLY));
  }
  check_syscallbuf_used();
}

/* The kernel receives the data, then fails to store something else. rr
   handles the syscalls differently when they can't block. */
static void check_partial_writes(int flags) {
  char buf[16];
  struct iovec iov = { buf, sizeof(buf) };
  struct msghdr* ro_msg = (struct msghdr*)ro_page;
  socklen_t* ro_addrlen = (socklen_t*)ro_page;

  memset(buf, 0, sizeof(buf));
  send_hello();
  check_efault(recvfrom(sock_fds[0], buf, sizeof(buf), flags,
                        (struct sockaddr*)(buf + 8), ro_addrlen));
  test_assert(!memcmp(buf, "hello", 5));

  memset(buf, 0, sizeof(buf));
  send_hello();
  test_assert(0 == mprotect(ro_page, page_size, PROT_READ | PROT_WRITE));
  memset(ro_msg, 0, sizeof(*ro_msg));
  ro_msg->msg_iov = &iov;
  ro_msg->msg_iovlen = 1;
  test_assert(0 == mprotect(ro_page, page_size, PROT_READ));
  check_efault(recvmsg(sock_fds[0], ro_msg, flags));
  test_assert(!memcmp(buf, "hello", 5));
  check_syscallbuf_used();
}

/* Null pointers that the syscall buffer used to dereference */
static void check_bad_args(void) {
  struct msghdr msg;
  struct iovec iov = { NULL, 5 };
  char buf[16];

  check_efault(syscall(SYS_uname, NULL));
  check_efault(socketpair(AF_UNIX, SOCK_STREAM, 0, NULL));
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  send_hello();
  check_efault(recvmsg(sock_fds[0], &msg, 0));
  test_assert(5 == recv(sock_fds[0], buf, 5, 0));
  test_assert(!memcmp(buf, "hello", 5));
  /* A private futex wake doesn't touch the futex word. */
  test_assert(0 ==
              syscall(SYS_futex, NULL, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0));
  check_syscallbuf_used();
}

int main(void) {
  struct sigaction sa;
  char buf[16];
  char st[256];
  struct iovec iov = { buf, 5 };
  struct msghdr msg;
  struct pollfd pfd = { 0, POLLIN, 0 };

  page_size = sysconf(_SC_PAGESIZE);
  ro_page = (char*)mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
  test_assert(ro_page != MAP_FAILED);
  none_page = (char*)mmap(NULL, page_size, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(none_page != MAP_FAILED);

  zero_fd = open("/dev/zero", O_RDONLY);
  test_assert(zero_fd >= 0);
  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

  /* Make each syscall once with good buffers first, so that rr patches its
     call site to use the syscall buffer. */
  send_hello();
  test_assert(5 == recv(sock_fds[0], buf, 5, 0));
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  send_hello();
  test_assert(5 == recvmsg(sock_fds[0], &msg, 0));
  test_assert(0 == syscall(FSTAT_SYSCALL, zero_fd, st));
  test_assert(16 == syscall(SYS_getrandom, buf, 16, GRND_NONBLOCK));
  test_assert(0 < readlink("/proc/self/exe", buf, sizeof(buf)));
  pfd.fd = zero_fd;
  test_assert(1 == poll(&pfd, 1, 0));
  test_assert(0 <= close(open("/dev/null", O_RDONLY)));
  check_syscallbuf_used();

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  test_assert(0 == sigaction(SIGBUS, &sa, NULL));

  check_bad_buffer(ro_page, 1);
  check_bad_buffer(none_page, 0);
  check_partial_writes(0);
  check_partial_writes(MSG_DONTWAIT);
  check_bad_args();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
