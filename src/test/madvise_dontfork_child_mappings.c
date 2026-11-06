/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define MAX_HOLES 64

static char parent_maps[65536];
static char child_maps[65536];
static char* holes[MAX_HOLES];

static void read_maps(char* buf, size_t size) {
  int fd = open("/proc/self/maps", O_RDONLY);
  size_t len = 0;
  ssize_t ret;
  test_assert(fd >= 0);
  while ((ret = read(fd, buf + len, size - 1 - len)) > 0) {
    len += ret;
  }
  test_assert(ret == 0);
  test_assert(len < size - 1);
  buf[len] = 0;
  test_assert(0 == close(fd));
}

static int overlaps_any(const char* maps, unsigned long start,
                        unsigned long end) {
  const char* line = maps;
  while (*line) {
    unsigned long s, e;
    const char* eol = strchr(line, '\n');
    if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s < end && start < e) {
      return 1;
    }
    if (!eol) {
      break;
    }
    line = eol + 1;
  }
  return 0;
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  const char* line;
  int fds[2];
  size_t len = 0;
  ssize_t ret;
  int num_holes = 0;
  int i;
  pid_t child;
  int status;

  test_assert(0 == pipe(fds));
  read_maps(parent_maps, sizeof(parent_maps));

  /* Find the ranges that are mapped in a forked child but not here (under
     rr, memory that rr maps for the child). */
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    read_maps(child_maps, sizeof(child_maps));
    len = strlen(child_maps);
    test_assert((ssize_t)len == write(fds[1], child_maps, len));
    _exit(0);
  }
  test_assert(0 == close(fds[1]));
  while ((ret = read(fds[0], child_maps + len,
                     sizeof(child_maps) - 1 - len)) > 0) {
    len += ret;
  }
  test_assert(ret == 0);
  child_maps[len] = 0;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  /* Map the last page of each such range and mark it MADV_DONTFORK. A
     child forked now starts with the address space layout the first child
     had, so these pages are unmapped in it. */
  line = child_maps;
  while (*line) {
    unsigned long start, end;
    const char* eol = strchr(line, '\n');
    if (sscanf(line, "%lx-%lx", &start, &end) == 2 &&
        !overlaps_any(parent_maps, start, end)) {
      char* hole = (char*)(end - page_size);
      test_assert(num_holes < MAX_HOLES);
      test_assert(hole == mmap(hole, page_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS |
                                   MAP_FIXED_NOREPLACE,
                               -1, 0));
      test_assert(0 == madvise(hole, page_size, MADV_DONTFORK));
      holes[num_holes++] = hole;
    }
    if (!eol) {
      break;
    }
    line = eol + 1;
  }

  child = fork();
  test_assert(child >= 0);
  if (!child) {
    for (i = 0; i < num_holes; ++i) {
      test_assert(-1 == madvise(holes[i], page_size, MADV_NORMAL));
      test_assert(ENOMEM == errno);
    }
    _exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_printf("%d DONTFORK holes checked\n", num_holes);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
