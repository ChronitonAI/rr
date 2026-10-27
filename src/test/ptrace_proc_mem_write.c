/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A ptracer writes to its stopped tracee's memory through /proc/<pid>/mem
   with write(), writev(), pwrite() and pwritev(). rr makes these writes for
   the tracer. Each must write the data once, at the file position or offset,
   and write() and writev() must move the file position by the amount
   written. */

static char target[64];

static const char expected[] = "AAAABBBBCCDDEEFF";

static char a[] = "AAAA";
static char b[] = "BBBB";
static char c[] = "CC";
static char d[] = "DD";
static char e[] = "EE";
static char f[] = "FF";

/* Whether mem has the expected data and zeros after it */
static int is_expected(const char* mem) {
  size_t i;
  if (memcmp(mem, expected, sizeof(expected) - 1)) {
    return 0;
  }
  for (i = sizeof(expected) - 1; i < sizeof(target); ++i) {
    if (mem[i]) {
      return 0;
    }
  }
  return 1;
}

int main(void) {
  uint64_t addr = (uintptr_t)target;
  struct iovec iov[2];
  char buf[sizeof(target)];
  int go_pipe[2];
  char path[64];
  pid_t child;
  int status;
  int fd;
  char ch;

  test_assert(0 == pipe(go_pipe));
  child = fork();
  if (!child) {
    /* Wait until the parent has attached; if the parent dies first, the
       read() sees EOF. */
    close(go_pipe[1]);
    if (1 != read(go_pipe[0], &ch, 1)) {
      return 1;
    }
    raise(SIGSTOP);
    return is_expected(target) ? 0 : 1;
  }
  test_assert(child > 0);
  close(go_pipe[0]);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(go_pipe[1], "g", 1));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  sprintf(path, "/proc/%d/mem", child);
  fd = open(path, O_RDWR);
  test_assert(fd >= 0);

  test_assert((off_t)addr == lseek(fd, addr, SEEK_SET));
  test_assert(4 == write(fd, a, 4));
  test_assert((off_t)(addr + 4) == lseek(fd, 0, SEEK_CUR));

  iov[0].iov_base = b;
  iov[0].iov_len = 4;
  iov[1].iov_base = c;
  iov[1].iov_len = 2;
  test_assert(6 == writev(fd, iov, 2));
  test_assert((off_t)(addr + 10) == lseek(fd, 0, SEEK_CUR));

  test_assert(2 == pwrite(fd, d, 2, addr + 10));
  iov[0].iov_base = e;
  iov[0].iov_len = 2;
  iov[1].iov_base = f;
  iov[1].iov_len = 2;
  test_assert(4 == pwritev(fd, iov, 2, addr + 12));
  test_assert((off_t)(addr + 10) == lseek(fd, 0, SEEK_CUR));

  test_assert((ssize_t)sizeof(buf) == pread(fd, buf, sizeof(buf), addr));
  test_assert(is_expected(buf));
  test_assert(0 == close(fd));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
