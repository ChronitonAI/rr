/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* `map <file>` maps <file> read-only and shared from an fd it then closes,
   so nothing in the recording can write <file>. It then opens <file>
   O_RDWR|O_NONBLOCK, which fails while anyone holds a lease on <file>.

   `write <file>` and `memfd -` run outside the recording. They create a
   writable shared mapping of <file> (and close its fd) or of a new memfd,
   print the path for `map` to use and wait to be killed. */

static void die_with_parent(void) {
  pid_t parent = getppid();
  test_assert(0 == prctl(PR_SET_PDEATHSIG, SIGKILL));
  if (getppid() != parent) {
    exit(0);
  }
}

static void wait_forever(void) {
  while (1) {
    pause();
  }
}

int main(int argc, char* argv[]) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p;
  int fd;

  test_assert(argc == 3);
  if (!strcmp(argv[1], "write")) {
    die_with_parent();
    fd = open(argv[2], O_RDWR | O_CREAT, 0600);
    test_assert(fd >= 0);
    test_assert(0 == ftruncate(fd, page_size));
    p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    test_assert(p != MAP_FAILED);
    test_assert(0 == close(fd));
    p[0] = 1;
    atomic_printf("ready %s\n", argv[2]);
    wait_forever();
  }
  if (!strcmp(argv[1], "memfd")) {
    die_with_parent();
    fd = syscall(RR_memfd_create, "mmap_shared_extern_readonly", 0);
    test_assert(fd >= 0);
    test_assert(0 == ftruncate(fd, page_size));
    p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    test_assert(p != MAP_FAILED);
    p[0] = 1;
    atomic_printf("ready /proc/%d/fd/%d\n", getpid(), fd);
    wait_forever();
  }

  test_assert(!strcmp(argv[1], "map"));
  fd = open(argv[2], O_RDONLY);
  test_assert(fd >= 0);
  p = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == close(fd));
  fd = open(argv[2], O_RDWR | O_NONBLOCK);
  test_assert(fd >= 0);
  test_assert(0 == close(fd));
  test_assert(0 == munmap(p, page_size));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
