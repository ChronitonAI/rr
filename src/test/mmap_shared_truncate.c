/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DATA_OFFSET 100
/* Large enough for replay to clear most of the mapping with madvise. */
#define MAP_PAGES 32

static const char data[] = "abcde";
static size_t page_size;

enum Truncation {
  OPEN_RDWR_TRUNC,
  OPEN_RDONLY_TRUNC,
  FTRUNCATE,
  FTRUNCATE_PARTIAL,
  TRUNCATE,
  TRUNCATE_PROC_FD,
};

static void truncate_file(int fd, enum Truncation how) {
  char path[64];
  int fd2;
  switch (how) {
    case OPEN_RDWR_TRUNC:
      fd2 = open("temp", O_RDWR | O_TRUNC);
      test_assert(fd2 >= 0);
      test_assert(0 == close(fd2));
      break;
    case OPEN_RDONLY_TRUNC:
      /* Linux truncates the file for O_RDONLY | O_TRUNC too. */
      fd2 = open("temp", O_RDONLY | O_TRUNC);
      test_assert(fd2 >= 0);
      test_assert(0 == close(fd2));
      break;
    case FTRUNCATE:
      test_assert(0 == ftruncate(fd, 0));
      break;
    case FTRUNCATE_PARTIAL:
      test_assert(0 == ftruncate(fd, DATA_OFFSET + 2));
      break;
    case TRUNCATE:
      test_assert(0 == truncate("temp", 0));
      break;
    case TRUNCATE_PROC_FD:
      /* This path names the file through this process's fd table. */
      sprintf(path, "/proc/self/fd/%d", fd);
      test_assert(0 == truncate(path, 0));
      break;
  }
}

static void check_bytes(const char* p, size_t kept) {
  size_t i;
  for (i = 0; i < sizeof(data) - 1; ++i) {
    test_assert(p[DATA_OFFSET + i] == (i < kept ? data[i] : 0));
  }
}

static void test_truncation(enum Truncation how, int in_child) {
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR, 0600);
  char* p;
  char* q;
  pid_t child;
  int status;

  test_assert(fd >= 0);
  test_assert(sizeof(data) - 1 ==
              pwrite(fd, data, sizeof(data) - 1, DATA_OFFSET));
  test_assert(sizeof(data) - 1 ==
              pwrite(fd, data, sizeof(data) - 1, page_size + DATA_OFFSET));

  p = mmap(NULL, MAP_PAGES * page_size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  q = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, page_size);
  test_assert(q != MAP_FAILED);
  check_bytes(p, sizeof(data) - 1);
  check_bytes(p + page_size, sizeof(data) - 1);
  check_bytes(q, sizeof(data) - 1);

  if (in_child) {
    /* Truncate the file in a process that doesn't map it. */
    child = fork();
    if (!child) {
      test_assert(0 == munmap(p, MAP_PAGES * page_size));
      test_assert(0 == munmap(q, page_size));
      truncate_file(fd, how);
      exit(77);
    }
    test_assert(child > 0);
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  } else {
    truncate_file(fd, how);
  }

  /* Extend the file again so the mappings can read the truncated part.
     This uses a write because when ftruncate extends a file, rr records
     zeroes for its mappings itself. */
  test_assert(1 == pwrite(fd, "", 1, 2 * page_size - 1));
  check_bytes(p, how == FTRUNCATE_PARTIAL ? 2 : 0);
  check_bytes(p + page_size, 0);
  check_bytes(q, 0);

  test_assert(0 == munmap(p, MAP_PAGES * page_size));
  test_assert(0 == munmap(q, page_size));
  test_assert(0 == close(fd));
  test_assert(0 == unlink("temp"));
}

/* Write through a mapping beyond the end of the file, then grow the file.
   Some filesystems clear what was written there and some keep it. */
static void test_growth(int use_memfd, int past_page) {
  int fd = use_memfd ? memfd_create("temp", 0)
                     : open("temp", O_CREAT | O_EXCL | O_RDWR, 0600);
  char path[64];
  char* p;
  size_t i;

  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, DATA_OFFSET));
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  memcpy(p + DATA_OFFSET, data, sizeof(data) - 1);

  if (past_page) {
    sprintf(path, "/proc/self/fd/%d", fd);
    test_assert(0 == truncate(path, 2 * page_size));
  } else {
    test_assert(0 == ftruncate(fd, DATA_OFFSET + 2));
  }

  for (i = 0; i < sizeof(data) - 1; ++i) {
    test_assert(p[DATA_OFFSET + i] == data[i] || p[DATA_OFFSET + i] == 0);
  }
  /* The length of this output depends on what was kept. */
  atomic_printf("kept '%s'\n", p + DATA_OFFSET);

  test_assert(0 == munmap(p, page_size));
  test_assert(0 == close(fd));
  if (!use_memfd) {
    test_assert(0 == unlink("temp"));
  }
}

int main(void) {
  enum Truncation how;
  page_size = sysconf(_SC_PAGESIZE);

  for (how = OPEN_RDWR_TRUNC; how <= TRUNCATE_PROC_FD; ++how) {
    test_truncation(how, 0);
    test_truncation(how, 1);
  }
  test_growth(0, 0);
  test_growth(0, 1);
  test_growth(1, 0);
  test_growth(1, 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
