/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A vfork child gets its own syscall buffer in the address space it shares
   with its parent. When the child execs, the buffer stays behind until rr
   unmaps it. Then the parent maps memory over a range that starts below
   where the child's buffer was and covers it. After that, rr must still be
   able to use the syscall buffer of the process that the child exec'd. */

#define GAP_SIZE (16 * 1024 * 1024)

static char maps[65536];
/* Written by the vfork child, which shares our memory. */
static uintptr_t child_buf_start;
static uintptr_t child_buf_end;

static void read_maps(void) {
  int fd = open("/proc/self/maps", O_RDONLY);
  size_t len = 0;
  ssize_t ret;
  test_assert(fd >= 0);
  while ((ret = read(fd, maps + len, sizeof(maps) - 1 - len)) > 0) {
    len += ret;
  }
  test_assert(ret == 0);
  test_assert(0 == close(fd));
  maps[len] = 0;
}

/* Find the mapping of our syscall buffer, if we have one. */
static int find_syscallbuf(uintptr_t* start, uintptr_t* end) {
  char name[64];
  char* line = maps;
  sprintf(name, "syscallbuf.%d-", (int)syscall(SYS_gettid));
  while (*line) {
    char* next = strchr(line, '\n');
    if (next) {
      *next = 0;
    }
    if (strstr(line, name)) {
      test_assert(2 == sscanf(line, "%" SCNxPTR "-%" SCNxPTR, start, end));
      return 1;
    }
    if (!next) {
      break;
    }
    line = next + 1;
  }
  return 0;
}

static int run_exec_child(int in_fd, int out_fd) {
  char ch;
  /* Our first syscalls set up our syscall buffer. */
  test_assert(1 == write(out_fd, "r", 1));
  test_assert(1 == read(in_fd, &ch, 1));
  test_assert(1 == write(out_fd, "d", 1));
  return 0;
}

int main(int argc, char** argv) {
  int to_child[2];
  int from_child[2];
  char in_fd[16];
  char out_fd[16];
  uintptr_t buf_start = 0;
  uintptr_t buf_end = 0;
  void* gap = NULL;
  pid_t child;
  int status;
  char ch;

  if (argc == 4) {
    return run_exec_child(atoi(argv[2]), atoi(argv[3]));
  }

  test_assert(0 == pipe(to_child));
  test_assert(0 == pipe(from_child));
  sprintf(in_fd, "%d", to_child[0]);
  sprintf(out_fd, "%d", from_child[1]);

  read_maps();
  if (find_syscallbuf(&buf_start, &buf_end)) {
    /* rr puts the next syscall buffer at the first free address after ours.
       Keep the memory there busy, so that the child's buffer goes above
       it. */
    gap = mmap((void*)buf_end, GAP_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    test_assert(gap != MAP_FAILED);
  }

  if (0 == (child = vfork())) {
    /* Our first syscalls set up our syscall buffer. */
    read_maps();
    find_syscallbuf(&child_buf_start, &child_buf_end);
    execl("/proc/self/exe", "/proc/self/exe", "child", in_fd, out_fd, NULL);
    _exit(1);
  }
  /* The exec'd child has set up its syscall buffer. */
  test_assert(1 == read(from_child[0], &ch, 1));

  if (gap == (void*)buf_end && child_buf_start == buf_end + GAP_SIZE) {
    /* Map over the gap and where the child's syscall buffer was. */
    test_assert(0 == munmap(gap, GAP_SIZE));
    test_assert(gap == mmap(gap, child_buf_end - buf_end,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    atomic_puts("Mapped over the child's syscall buffer");
  }

  test_assert(1 == write(to_child[1], "g", 1));
  test_assert(1 == read(from_child[0], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
