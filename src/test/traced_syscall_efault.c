/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Syscalls whose memory parameters the tracee can't access must fail with
   EFAULT as they do without rr, and whatever the kernel wrote before it
   failed must be recorded. rr doesn't buffer the syscalls used here, so
   they go through rr's own syscall handling. */

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

/* Two pages filled with 0xff, the first one read-only */
static char* map_ro_rw_pages(void) {
  char* p = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  memset(p, 0xff, 2 * page_size);
  test_assert(0 == mprotect(p, page_size, PROT_READ));
  return p;
}

static int is_zero(const char* p, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i) {
    if (p[i]) {
      return 0;
    }
  }
  return 1;
}

/* get_mempolicy() stores the mode, and the kernel can clear the tail of the
   nodemask before it copies the head. With a read-only head, it then fails
   after it wrote the mode and the tail. */
static void check_get_mempolicy_tail(void) {
  char* pages = map_ro_rw_pages();
  /* 1024 bits, of which the first 32 are read-only */
  char* nodemask = pages + page_size - 4;
  int mode = -1;
  long ret = syscall(SYS_get_mempolicy, &mode, nodemask, 1024, NULL, 0);

  if (ret == -1 && (errno == ENOSYS || errno == EPERM || errno == EINVAL)) {
    atomic_puts("get_mempolicy() not supported");
  } else {
    check_efault(ret);
    test_assert(mode >= 0);
    /* The head is at most 64 bytes unless there are more than 512 nodes. */
    atomic_printf("get_mempolicy() cleared the nodemask's tail: %d\n",
                  is_zero(nodemask + 64, 64));
  }
  test_assert(0 == munmap(pages, 2 * page_size));
}

/* Since Linux 6.13
   (https://github.com/torvalds/linux/commit/112cca098a7010c02a4d535a253af72e4e5bbd06),
   sched_getattr() clears the tail of a buffer larger than its struct before
   it copies the struct. With a read-only head, it then fails after it
   cleared the tail. */
static void check_sched_getattr_tail(void) {
  char* pages = map_ro_rw_pages();
  char* attr = pages + page_size - 32;

  check_efault(syscall(SYS_sched_getattr, 0, attr, 232, 0));
  /* This part of the tail stays past the struct even if it grows. */
  atomic_printf("sched_getattr() cleared the buffer's tail: %d\n",
                is_zero(attr + 128, 104));
  test_assert(0 == munmap(pages, 2 * page_size));
}

/* A page past the end of a mapped file faults, although it's mapped
   read-write. sched_getattr() stores the part of its struct that comes
   before such a page, and then fails. */
static void check_sched_getattr_past_eof(void) {
  int fd =
      open("traced_syscall_efault_file", O_RDWR | O_CREAT | O_TRUNC, 0600);
  char* pages;
  uint32_t* attr;

  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, page_size));
  pages = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                      fd, 0);
  test_assert(pages != MAP_FAILED);
  test_assert(0 == close(fd));
  test_assert(0 == unlink("traced_syscall_efault_file"));
  attr = (uint32_t*)(pages + page_size - 32);
  /* The first 48 bytes of struct sched_attr are the same in all versions. */
  check_efault(syscall(SYS_sched_getattr, 0, attr, 48, 0));
  /* attr->size */
  test_assert(attr[0] == 48);
  test_assert(0 == munmap(pages, 2 * page_size));
}

/* rt_sigpending() with a size larger than a sigset_t, and getgroups() with a
   negative size, fail with EINVAL before they store anything, so rr must not
   record the memory that their sizes cover. traced_syscall_efault.run checks
   that. */
static void check_einval_huge_size(void) {
  size_t size = 256 * page_size;
  char* p = (char*)mmap(NULL, size + page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  test_assert(p != MAP_FAILED);
  /* The sizes cover memory that the tracee can't write. */
  test_assert(0 == mprotect(p + size, page_size, PROT_NONE));
  atomic_printf("EINVAL buffer: %p\n", p);
  test_assert(-1 == syscall(SYS_rt_sigpending, p, size + page_size));
  test_assert(errno == EINVAL);
  test_assert(-1 == syscall(SYS_getgroups, -1, p));
  test_assert(errno == EINVAL);
  test_assert(0 == munmap(p, size + page_size));
}

/* readv() with a size that is larger than the memory left in the address
   space, into a buffer whose first page the tracee can't write, fails with
   EFAULT before it writes anything. rr must not record the memory after that
   page; traced_syscall_efault.run checks that. */
static void check_efault_huge_size(void) {
  char* p = (char*)mmap(NULL, 2 * page_size, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char buf[16];
  struct iovec iov = { p, SSIZE_MAX / 2 };

  test_assert(p != MAP_FAILED);
  test_assert(0 == mprotect(p + page_size, page_size, PROT_READ | PROT_WRITE));
  atomic_printf("EFAULT buffer: %p\n", p + page_size);
  test_assert(5 == write(pipe_fds[1], "hello", 5));
  check_efault(readv(pipe_fds[0], &iov, 1));
  test_assert(5 == read(pipe_fds[0], buf, sizeof(buf)));
  test_assert(0 == munmap(p, 2 * page_size));
}

#define RR_PAGE_ADDR 0x70000000

static int rr_page_writable;

static void check_rr_page(__attribute__((unused)) uint64_t env,
                          __attribute__((unused)) char* name,
                          map_properties_t* props) {
  if (props->start <= RR_PAGE_ADDR && RR_PAGE_ADDR < props->end &&
      props->flags[1] == 'w') {
    rr_page_writable = 1;
  }
}

/* rr maps a read-only page at RR_PAGE_ADDR, and memory for its own use after
   it. readv() into a buffer that starts at the end of that page fails with
   EFAULT before it writes anything, and rr must not record its own memory
   after the page. traced_syscall_efault.run checks that. */
static void check_efault_before_rr_memory(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  char buf[16];
  struct iovec iov = { (char*)RR_PAGE_ADDR + page_size - 16, 32 };

  test_assert(maps_file != NULL);
  iterate_maps(0, check_rr_page, maps_file);
  test_assert(0 == fclose(maps_file));
  if (rr_page_writable) {
    atomic_puts("Memory at RR_PAGE_ADDR is writable");
    return;
  }
  test_assert(5 == write(pipe_fds[1], "hello", 5));
  check_efault(readv(pipe_fds[0], &iov, 1));
  test_assert(5 == read(pipe_fds[0], buf, sizeof(buf)));
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

  check_get_mempolicy_tail();
  check_sched_getattr_tail();
  check_sched_getattr_past_eof();
  check_einval_huge_size();
  check_efault_huge_size();
  check_efault_before_rr_memory();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
