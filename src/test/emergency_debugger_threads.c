/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static int pipe_fds[2];
static pid_t reader_tid;

/* On x86-32 with the syscall buffer, read() runs rr's syscall hook on a
   stack of its own, and gdb ends a backtrace where a frame's caller is on a
   stack below it. So make the syscall directly, and the backtrace shows
   blocked_reader() wherever the thread's stack is. */
static long read_byte(int fd, char* ch) {
#ifdef __i386__
  long ret;
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "0"(SYS_read), "b"(fd), "c"(ch), "d"(1)
                       : "memory");
  return ret;
#else
  return read(fd, ch, 1);
#endif
}

static void* blocked_reader(__attribute__((unused)) void* p) {
  char ch;
  __atomic_store_n(&reader_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(1 == read_byte(pipe_fds[0], &ch));
  return NULL;
}

static void __attribute__((noinline)) fail_here(void) { rr_fail_assertion(); }

int main(void) {
  test_assert(0 == pipe(pipe_fds));
  pid_t parent = getpid();
  pid_t child = fork();
  if (!child) {
    pthread_t thread;
    pid_t reader;
    test_assert(0 == pthread_create(&thread, NULL, blocked_reader, NULL));
    while (!(reader = __atomic_load_n(&reader_tid, __ATOMIC_SEQ_CST))) {
      sched_yield();
    }
    /* Wait until our parent is blocked in waitpid() and our other thread in
       read(), so that rr has resumed them into those syscalls and they
       aren't stopped when rr fails. */
    while (get_task_state(parent) != 'S' ||
           get_task_state(reader) != 'S') {
      sched_yield();
    }
    /* While rr records us, this doesn't return. */
    fail_here();
    return 77;
  }
  test_assert(child > 0);
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
