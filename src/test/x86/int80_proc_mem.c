/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* An x86-64 ptracer writes to its stopped tracee's memory through
   /proc/<pid>/mem with i386 write(), writev(), pwrite64() and pwritev()
   (int $0x80). rr makes these writes for the tracer, and after write() and
   writev() it sets the file position with a syscall of its own: to just
   after the data written. */

#if defined(__x86_64__)

#define I386_writev 146
#define I386_pwrite64 181
#define I386_pwritev 334

struct i386_iovec {
  uint32_t base;
  uint32_t len;
};

static char target[64];

static const char expected[] = "AAAABBBBCCDDEEEEFFGG";

int main(void) {
  char* buf = int80_low_alloc(4096);
  struct i386_iovec* iov = (struct i386_iovec*)(buf + 1024);
  uint64_t addr = (uintptr_t)target;
  int go_pipe[2];
  char path[64];
  pid_t child;
  int status;
  int fd;
  long ret;
  char c;

  int80_setup();
  test_assert(0 == pipe(go_pipe));
  child = fork();
  if (!child) {
    /* Wait until the parent has attached; if the parent dies first, the
       read() sees EOF. */
    close(go_pipe[1]);
    if (1 != read(go_pipe[0], &c, 1)) {
      return 1;
    }
    raise(SIGSTOP);
    return memcmp(target, expected, sizeof(expected) - 1) == 0 ? 0 : 1;
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

  memcpy(buf, "AAAA", 4);
  ret = int80_5(I386_pwrite64, fd, LOW(buf), 4, (uint32_t)addr,
                (uint32_t)(addr >> 32));
  test_assert(ret == 4);

  test_assert((off_t)(addr + 4) == lseek(fd, addr + 4, SEEK_SET));
  memcpy(buf + 16, "BBBB", 4);
  ret = int80_3(I386_write, fd, LOW(buf + 16), 4);
  test_assert(ret == 4);
  test_assert((off_t)(addr + 8) == lseek(fd, 0, SEEK_CUR));

  memcpy(buf + 32, "CC", 2);
  memcpy(buf + 48, "DD", 2);
  iov[0].base = LOW(buf + 32);
  iov[0].len = 2;
  iov[1].base = LOW(buf + 48);
  iov[1].len = 2;
  ret = int80_3(I386_writev, fd, LOW(iov), 2);
  test_assert(ret == 4);
  test_assert((off_t)(addr + 12) == lseek(fd, 0, SEEK_CUR));

  memcpy(buf + 64, "EEEE", 4);
  ret = int80_5(I386_pwrite64, fd, LOW(buf + 64), 4, (uint32_t)(addr + 12),
                (uint32_t)((addr + 12) >> 32));
  test_assert(ret == 4);

  memcpy(buf + 80, "FF", 2);
  memcpy(buf + 96, "GG", 2);
  iov[0].base = LOW(buf + 80);
  iov[0].len = 2;
  iov[1].base = LOW(buf + 96);
  iov[1].len = 2;
  ret = int80_5(I386_pwritev, fd, LOW(iov), 2, (uint32_t)(addr + 16),
                (uint32_t)((addr + 16) >> 32));
  test_assert(ret == 4);
  test_assert((off_t)(addr + 12) == lseek(fd, 0, SEEK_CUR));

  memset(buf + 128, 0, 64);
  test_assert((ssize_t)sizeof(expected) - 1 ==
              pread(fd, buf + 128, sizeof(expected) - 1, addr));
  test_assert(0 == memcmp(buf + 128, expected, sizeof(expected) - 1));
  test_assert(0 == close(fd));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
