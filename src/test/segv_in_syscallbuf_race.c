/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This is a race test: the race it tests only happens in some recordings.
 *
 * As in segv_in_syscallbuf, a buffered read() into a read-only page raises
 * SIGSEGV in syscallbuf code under rr, after the read() has taken 'c' from
 * the pipe. The handler makes the page writable and then keeps opening a
 * file that rr refuses to open, so rr closes each new fd with a remote
 * syscall. Every open() goes through the syscallbuf code, which sees the
 * syscallbuf locked and makes it a traced syscall. An interval timer
 * interrupts the handler, sometimes while it runs that syscallbuf code.
 * Each open() must still succeed or fail with ENOENT (rr's refusal), and
 * the read() must return the 'c'.
 */

#define ROUNDS 10
#define OPENS_PER_ROUND 2000

static const char file_name[] = "rr-test-blacklist-file_name";
static char* page;
static size_t page_size;

static void set_timer(int usec) {
  struct itimerval timer = { { 0, usec }, { 0, usec } };
  test_assert(0 == setitimer(ITIMER_VIRTUAL, &timer, NULL));
}

static void vtalrm_handler(__attribute__((unused)) int sig) {}

static void segv_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si,
                         __attribute__((unused)) void* p) {
  int i;

  test_assert(0 == mprotect(page, page_size, PROT_READ | PROT_WRITE));
  set_timer(100);
  for (i = 0; i < OPENS_PER_ROUND; ++i) {
    int fd = open(file_name, O_RDONLY | O_CREAT, 0600);
    if (fd >= 0) {
      test_assert(0 == close(fd));
    } else {
      test_assert(errno == ENOENT);
    }
  }
  set_timer(0);
}

int main(void) {
  struct sigaction sa;
  int pipefds[2];
  int i;

  page_size = sysconf(_SC_PAGESIZE);
  page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = segv_handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = vtalrm_handler;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGVTALRM, &sa, NULL));

  test_assert(0 == pipe(pipefds));
  /* Let rr patch the read() site. */
  test_assert(1 == write(pipefds[1], "a", 1));
  test_assert(1 == read(pipefds[0], page, 1));

  for (i = 0; i < ROUNDS; ++i) {
    ssize_t ret;
    char ch;

    test_assert(2 == write(pipefds[1], "cd", 2));
    test_assert(0 == mprotect(page, page_size, PROT_READ));
    /* A traced syscall flushes the syscallbuf, so the read() gets the first
       record. */
    syscall(SYS_getsid, 0);
    ret = read(pipefds[0], page, 1);
    if (ret < 0) {
      test_assert(errno == EFAULT);
      test_assert(0 == mprotect(page, page_size, PROT_READ | PROT_WRITE));
      test_assert(1 == read(pipefds[0], page, 1));
    } else {
      test_assert(1 == ret);
    }
    test_assert(page[0] == 'c');
    test_assert(1 == read(pipefds[0], &ch, 1));
    test_assert(ch == 'd');
  }
  unlink(file_name);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
