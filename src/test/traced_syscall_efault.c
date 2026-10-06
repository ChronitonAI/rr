/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Syscalls whose memory parameters the tracee can't access must fail with
   EFAULT as they do without rr, and whatever the kernel wrote before it
   failed must be recorded. rr doesn't buffer readv() and recvmmsg(), so
   these go through rr's own syscall handling. */

static size_t page_size;
static int pipe_fds[2];
static int sock_fds[2];

static void check_efault(ssize_t ret) {
  test_assert(ret == -1);
  test_assert(errno == EFAULT);
}

static char* map_page(int prot, int flags) {
  char* p = (char*)mmap(NULL, page_size, prot, flags | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  return p;
}

/* readv() into memory we can't write fails, and the data stays in the
   pipe. */
static void check_readv(char* bad) {
  char buf[16];
  struct iovec iov = { bad, 5 };

  test_assert(5 == write(pipe_fds[1], "hello", 5));
  check_efault(readv(pipe_fds[0], &iov, 1));
  iov.iov_base = buf;
  test_assert(5 == readv(pipe_fds[0], &iov, 1));
  test_assert(!memcmp(buf, "hello", 5));
}

/* recvmmsg() with a read-only mmsghdr receives the message into the buffer,
   then fails to store the message's flags. */
static void check_recvmmsg_ro_header(int flags) {
  char buf[16];
  struct iovec iov = { buf, sizeof(buf) };
  struct mmsghdr* msgs =
      (struct mmsghdr*)map_page(PROT_READ | PROT_WRITE, MAP_PRIVATE);

  memset(buf, 0, sizeof(buf));
  msgs->msg_hdr.msg_iov = &iov;
  msgs->msg_hdr.msg_iovlen = 1;
  test_assert(0 == mprotect(msgs, page_size, PROT_READ));
  test_assert(5 == write(sock_fds[1], "world", 5));
  check_efault(recvmmsg(sock_fds[0], msgs, 1, flags, NULL));
  test_assert(!memcmp(buf, "world", 5));
  test_assert(0 == munmap(msgs, page_size));
}

/* recvmmsg() receives two messages, but the second mmsghdr is read-only. It
   fails to store the second message's flags after it received the message,
   and returns 1. */
static void check_recvmmsg_ro_second_header(void) {
  char buf1[16];
  char buf2[16];
  struct iovec iov1 = { buf1, sizeof(buf1) };
  struct iovec iov2 = { buf2, sizeof(buf2) };
  char* pages = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct mmsghdr* msgs = (struct mmsghdr*)(pages + page_size) - 1;
  int err;
  socklen_t err_len = sizeof(err);

  test_assert(pages != MAP_FAILED);
  memset(buf1, 0, sizeof(buf1));
  memset(buf2, 0, sizeof(buf2));
  memset(msgs, 0, 2 * sizeof(*msgs));
  msgs[0].msg_hdr.msg_iov = &iov1;
  msgs[0].msg_hdr.msg_iovlen = 1;
  msgs[1].msg_hdr.msg_iov = &iov2;
  msgs[1].msg_hdr.msg_iovlen = 1;
  test_assert(0 == mprotect(pages + page_size, page_size, PROT_READ));
  test_assert(3 == write(sock_fds[1], "one", 3));
  test_assert(3 == write(sock_fds[1], "two", 3));
  test_assert(1 == recvmmsg(sock_fds[0], msgs, 2, 0, NULL));
  test_assert(msgs[0].msg_len == 3);
  test_assert(!memcmp(buf1, "one", 3));
  test_assert(!memcmp(buf2, "two", 3));
  /* The socket reports the error. */
  test_assert(0 ==
              getsockopt(sock_fds[0], SOL_SOCKET, SO_ERROR, &err, &err_len));
  test_assert(err == EFAULT);
  test_assert(0 == munmap(pages, 2 * page_size));
}

int main(void) {
  page_size = sysconf(_SC_PAGESIZE);
  test_assert(0 == pipe(pipe_fds));
  test_assert(0 == socketpair(AF_UNIX, SOCK_DGRAM, 0, sock_fds));

  check_readv(map_page(PROT_READ, MAP_PRIVATE));
  check_readv(map_page(PROT_NONE, MAP_PRIVATE));
  /* We can't write to shared memory that the tracee can't write either. */
  check_readv(map_page(PROT_READ, MAP_SHARED));
  check_readv(map_page(PROT_NONE, MAP_SHARED));

  check_recvmmsg_ro_header(0);
  /* rr doesn't expect this to block, which affects how it handles it. */
  check_recvmmsg_ro_header(MSG_DONTWAIT);
  check_recvmmsg_ro_second_header();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
