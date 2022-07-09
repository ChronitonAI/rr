/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Buffered syscalls with arguments in pages the program can't access. The
   syscallbuf copies arguments itself, so under rr the copy can raise
   SIGSEGV in syscallbuf code, and the handler makes the page accessible
   and returns. Then the handler's own syscalls and the buffered syscall
   must work as they do without rr: a read() into a read-only page returns
   EFAULT or the first byte, and a recvfrom() whose (unused) addrlen can't
   be read blocks until data arrives. */

static char* page;
static size_t page_size;
static int segv_count;
static int sockfds[2];
static pid_t main_tid;

static void handler(__attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si,
                    __attribute__((unused)) void* p) {
  __atomic_fetch_add(&segv_count, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == mprotect(page, page_size, PROT_READ | PROT_WRITE));
}

static ssize_t do_recvfrom(char* buf, size_t len, socklen_t* addrlen) {
#if defined(__i386__)
  /* glibc's recvfrom() uses socketcall, which the syscallbuf doesn't
     buffer. */
  return syscall(SYS_recvfrom, sockfds[0], buf, len, 0, NULL, addrlen);
#else
  return recvfrom(sockfds[0], buf, len, 0, NULL, addrlen);
#endif
}

static void* sender_thread(__attribute__((unused)) void* p) {
  pid_t tid = __atomic_load_n(&main_tid, __ATOMIC_SEQ_CST);
  test_assert(tid > 1);
  wait_for_task_asleep_in_syscall(tid, SYS_recvfrom, sockfds[0]);
  test_assert(1 == write(sockfds[1], "x", 1));
  return NULL;
}

static void check_read(void) {
  int pipefds[2];
  ssize_t ret;
  char ch;

  test_assert(0 == pipe(pipefds));
  /* Let rr patch the read() site. */
  test_assert(1 == write(pipefds[1], "a", 1));
  test_assert(1 == read(pipefds[0], page, 1));

  test_assert(2 == write(pipefds[1], "cd", 2));
  test_assert(0 == mprotect(page, page_size, PROT_READ));
  /* A traced syscall flushes the syscallbuf, so the read() gets the first
     record. The same goes for the recvfrom() below. */
  syscall(SYS_getsid, 0);
  ret = read(pipefds[0], page, 1);
  if (ret < 0) {
    test_assert(errno == EFAULT);
    test_assert(0 == __atomic_load_n(&segv_count, __ATOMIC_SEQ_CST));
    test_assert(0 == mprotect(page, page_size, PROT_READ | PROT_WRITE));
    test_assert(1 == read(pipefds[0], page, 1));
  } else {
    test_assert(1 == ret);
    test_assert(__atomic_load_n(&segv_count, __ATOMIC_SEQ_CST) <= 1);
  }
  test_assert(page[0] == 'c');
  test_assert(1 == read(pipefds[0], &ch, 1));
  test_assert(ch == 'd');
  test_assert(0 == close(pipefds[0]));
  test_assert(0 == close(pipefds[1]));
}

static void check_recvfrom(void) {
  socklen_t* addrlen = (socklen_t*)page;
  char buf[16];
  pthread_t thread;

  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds));
  /* Let rr patch the recvfrom() site. */
  test_assert(1 == write(sockfds[1], "a", 1));
  *addrlen = 0;
  test_assert(1 == do_recvfrom(buf, sizeof(buf), addrlen));

  __atomic_store_n(&segv_count, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&main_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, sender_thread, NULL));
  test_assert(0 == mprotect(page, page_size, PROT_NONE));
  syscall(SYS_getsid, 0);
  /* Without a source address buffer, the kernel doesn't access addrlen. */
  test_assert(1 == do_recvfrom(buf, sizeof(buf), addrlen));
  test_assert(__atomic_load_n(&segv_count, __ATOMIC_SEQ_CST) <= 1);
  test_assert(buf[0] == 'x');
  test_assert(0 == pthread_join(thread, NULL));
}

int main(void) {
  struct sigaction sa;

  page_size = sysconf(_SC_PAGESIZE);
  page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

  check_read();
  check_recvfrom();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
