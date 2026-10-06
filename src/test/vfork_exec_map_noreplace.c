/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A vfork child gets its own syscall buffer in the address space it shares
   with its parent. When the child execs, rr unmaps the buffer before the
   parent runs again. Then the parent maps memory where the buffer was, with
   MAP_FIXED_NOREPLACE, which fails if anything is still mapped there. */

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

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
static void find_syscallbuf(uintptr_t* start, uintptr_t* end) {
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
      return;
    }
    if (!next) {
      break;
    }
    line = next + 1;
  }
}

int main(int argc, __attribute__((unused)) char** argv) {
  pid_t child;
  int status;

  if (argc > 1) {
    return 0;
  }

  if (0 == (child = vfork())) {
    /* Our first syscalls set up our syscall buffer. */
    read_maps();
    find_syscallbuf(&child_buf_start, &child_buf_end);
    execl("/proc/self/exe", "/proc/self/exe", "exit", NULL);
    _exit(1);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  if (child_buf_end) {
    void* p = mmap((void*)child_buf_start, child_buf_end - child_buf_start,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    test_assert(p == (void*)child_buf_start);
    atomic_puts("Mapped where the child's syscall buffer was");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
