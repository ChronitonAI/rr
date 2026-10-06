/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A CLONE_VM child gets its own syscall buffer in the address space it
   shares with its parent, and then a thread of the parent gets one. The
   child execs while its parent ptraces it with PTRACE_O_TRACEEXEC. While the
   child is stopped at the exec event, the parent maps memory over a range
   that starts below where the child's syscall buffer was and covers it.
   After that, rr must still be able to use the thread's syscall buffer. */

#define GAP_SIZE (16 * 1024 * 1024)

static char maps[65536];
/* Written by the child, which shares our memory. */
static uintptr_t child_buf_start;
static uintptr_t child_buf_end;
static int to_thread[2];
static int from_thread[2];

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

static int child_main(__attribute__((unused)) void* arg) {
  /* We share our parent's TLS, where libc may keep our parent's tid, so we
     stop ourselves with the tid that the kernel gives us, which is also our
     tgid. */
  pid_t tid = sys_gettid();
  test_assert(0 == ptrace(PTRACE_TRACEME, 0, 0, 0));
  /* Our first syscalls set up our syscall buffer. */
  read_maps();
  find_syscallbuf(&child_buf_start, &child_buf_end);
  test_assert(0 == tgkill(tid, tid, SIGSTOP));
  execl("/proc/self/exe", "/proc/self/exe", "exit", NULL);
  _exit(1);
}

static void* thread_main(__attribute__((unused)) void* arg) {
  char ch;
  /* Our first syscall sets up our syscall buffer. */
  test_assert(1 == write(from_thread[1], "r", 1));
  test_assert(1 == read(to_thread[0], &ch, 1));
  test_assert(1 == write(from_thread[1], "d", 1));
  return NULL;
}

int main(int argc, __attribute__((unused)) char** argv) {
  static char stack[65536];
  uintptr_t buf_start = 0;
  uintptr_t buf_end = 0;
  void* gap = NULL;
  pthread_t thread;
  pid_t child;
  int status;
  char ch;

  if (argc > 1) {
    return 0;
  }

  test_assert(0 == pipe(to_thread));
  test_assert(0 == pipe(from_thread));

  read_maps();
  if (find_syscallbuf(&buf_start, &buf_end)) {
    /* rr puts the next syscall buffer at the first free address after ours.
       Keep the memory there busy, so that the child's buffer goes above
       it. */
    gap = mmap((void*)buf_end, GAP_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
    test_assert(gap != MAP_FAILED);
  }

  child = clone(child_main, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
  test_assert(1 == read(from_thread[0], &ch, 1));

  test_assert(0 ==
              ptrace(PTRACE_SETOPTIONS, child, 0, (void*)PTRACE_O_TRACEEXEC));
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));

  if (gap == (void*)buf_end && child_buf_start == buf_end + GAP_SIZE) {
    /* Map over the gap and where the child's syscall buffer was. */
    test_assert(0 == munmap(gap, GAP_SIZE));
    test_assert(gap == mmap(gap, child_buf_end - buf_end,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    atomic_puts("Mapped over the child's syscall buffer");
  }

  test_assert(1 == write(to_thread[1], "g", 1));
  test_assert(1 == read(from_thread[0], &ch, 1));
  test_assert(0 == pthread_join(thread, NULL));

  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
