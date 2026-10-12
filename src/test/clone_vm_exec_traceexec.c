/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A CLONE_VM child gets its own syscall buffer in the address space it
   shares with its parent. Its parent traces it with PTRACE_O_TRACEEXEC, so
   it stops at the exec event, before its execve() returns. Meanwhile the
   parent tries to map memory where the child's syscall buffer was, with
   MAP_FIXED_NOREPLACE. Then a second child gets killed at the exec event,
   and the parent tries to mprotect() its syscall buffer. Whether these work
   depends on when rr unmaps the buffers, but replay must get the same
   results as the recording. (We use pkey_mprotect(), which rr doesn't
   buffer, so that replay executes it, as an mprotect(), and checks that it
   gets the recorded result. So we skip that where the kernel doesn't have
   pkey_mprotect(), since mprotect() wouldn't fail with ENOSYS.) */

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef SYS_pkey_mprotect
#if defined(__x86_64__)
#define SYS_pkey_mprotect 329
#elif defined(__i386__)
#define SYS_pkey_mprotect 380
#elif defined(__aarch64__)
#define SYS_pkey_mprotect 288
#endif
#endif
#ifndef SYS_pkey_free
#if defined(__x86_64__)
#define SYS_pkey_free 331
#elif defined(__i386__)
#define SYS_pkey_free 382
#elif defined(__aarch64__)
#define SYS_pkey_free 290
#endif
#endif

static char maps[65536];
/* Written by the child, which shares our memory. */
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

static int child_main(__attribute__((unused)) void* arg) {
  test_assert(0 == ptrace(PTRACE_TRACEME, 0, 0, 0));
  read_maps();
  find_syscallbuf(&child_buf_start, &child_buf_end);
  raise(SIGSTOP);
  execl("/proc/self/exe", "/proc/self/exe", "exit", NULL);
  _exit(1);
}

static pid_t start_child_until_exec(void) {
  static char stack[65536];
  pid_t child;
  int status;

  child_buf_start = 0;
  child_buf_end = 0;
  child = clone(child_main, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 ==
              ptrace(PTRACE_SETOPTIONS, child, 0, (void*)PTRACE_O_TRACEEXEC));
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  return child;
}

int main(int argc, __attribute__((unused)) char** argv) {
  pid_t child;
  int status;

  if (argc > 1) {
    return 0;
  }

  child = start_child_until_exec();
  if (child_buf_end) {
    void* p = mmap((void*)child_buf_start, child_buf_end - child_buf_start,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    test_assert(p == (void*)child_buf_start ||
                (p == MAP_FAILED && errno == EEXIST));
    atomic_printf("Mapping where the child's syscall buffer was %s\n",
                  p == MAP_FAILED ? "failed" : "worked");
  }

  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  child = start_child_until_exec();
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  /* rr emulates pkey_free(), which fails with EINVAL for this pkey where
     the kernel has the pkey syscalls. */
  if (child_buf_end && syscall(SYS_pkey_free, -1) == -1 && errno == EINVAL) {
    int ret = syscall(SYS_pkey_mprotect, child_buf_start,
                      child_buf_end - child_buf_start, PROT_READ, -1);
    test_assert(ret == 0 || errno == ENOMEM);
    atomic_printf("mprotect of the killed child's syscall buffer %s\n",
                  ret ? "failed" : "worked");
  } else if (child_buf_end) {
    atomic_puts("No pkey_mprotect(), skipping the mprotect() check");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
