/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE (4 * 4096)

static char out[SIZE];

static void read_all(int fd, char* buf, size_t size) {
  size_t done = 0;
  while (done < size) {
    ssize_t n = read(fd, buf + done, size - done);
    test_assert(n > 0);
    done += n;
  }
}

int main(void) {
  int fds[2];
  char* buf;
  struct iovec iov[3];
  ssize_t n;
  size_t i;

  buf = (char*)mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(buf != MAP_FAILED);
  for (i = 0; i < SIZE; ++i) {
    buf[i] = (char)(i * 7 + 3);
  }
  test_assert(0 == pipe(fds));

  /* User memory into the pipe (fd is the write end): the kernel writes no
     user memory. */
  iov[0].iov_base = buf;
  iov[0].iov_len = SIZE / 2;
  iov[1].iov_base = buf + SIZE / 2;
  iov[1].iov_len = SIZE / 2;
  n = vmsplice(fds[1], iov, 2, 0);
  test_assert(n == SIZE);
  read_all(fds[0], out, SIZE);
  test_assert(0 == memcmp(out, buf, SIZE));

  /* The same with SPLICE_F_GIFT (whole pages). */
  iov[0].iov_base = buf;
  iov[0].iov_len = SIZE;
  n = vmsplice(fds[1], iov, 1, SPLICE_F_GIFT);
  test_assert(n == SIZE);
  memset(out, 0, SIZE);
  read_all(fds[0], out, SIZE);
  test_assert(0 == memcmp(out, buf, SIZE));

  /* The pipe into user memory (fd is the read end), scattered over three
     segments; the last is only partly filled. Replay must restore what the
     kernel wrote. */
  test_assert(1000 == write(fds[1], buf, 1000));
  memset(out, 0, SIZE);
  iov[0].iov_base = out;
  iov[0].iov_len = 300;
  iov[1].iov_base = out + 4096;
  iov[1].iov_len = 500;
  iov[2].iov_base = out + 3 * 4096;
  iov[2].iov_len = 4096;
  n = vmsplice(fds[0], iov, 3, 0);
  test_assert(n == 1000);
  test_assert(0 == memcmp(out, buf, 300));
  test_assert(0 == memcmp(out + 4096, buf + 300, 500));
  test_assert(0 == memcmp(out + 3 * 4096, buf + 800, 200));
  for (i = 0; i < 300; ++i) {
    test_assert(out[3 * 4096 + 200 + i] == 0);
  }
  atomic_printf("checksum %d %d %d\n", out[0] + out[299], out[4096 + 499],
                out[3 * 4096 + 199]);

  /* Errors: a closed fd, an empty iovec array. */
  test_assert(-1 == vmsplice(-1, iov, 1, 0) && errno == EBADF);
  test_assert(0 == vmsplice(fds[1], iov, 0, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
