/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrcalls.h"
#include "util.h"

/* A buffered read() into memory that the tracee can't write must fail with
   EFAULT as it does without rr (and leave the data in a pipe), instead of
   faulting in the syscallbuf code. A buffer that the kernel only partly
   fills must work even if the rest of it is inaccessible or past the end of
   a mapped file. The tracee's SIGSEGV and SIGBUS handlers must not run, and
   those signals' dispositions and blocked-ness must not change. */

static size_t page_size;
static char* ro_page;
static char* none_page;
static char* shared_ro_page;
/* A writable page followed by a read-only one */
static char* rw_ro_pages;
/* Two pages of a file that ends in the first one */
static char* private_file_pages;
static char* shared_file_pages;
static int zero_fd;
static int pipe_fds[2];

static void handler(int sig) {
  atomic_printf("FAILED: handler for signal %d ran\n", sig);
  _exit(1);
}

static void check_efault(ssize_t ret) {
  test_assert(ret == -1);
  test_assert(errno == EFAULT);
}

/* The syscall buffer handles this syscall unless it's disabled. */
static void check_syscallbuf_used(void) {
  long ret = syscall(SYS_rrcall_check_presence,
                     RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED, 0, 0, 0, 0, 0);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));
}

/* The kernel only writes to the first page of |p|. */
static void check_short_read(char* p) {
  test_assert(10 == write(pipe_fds[1], "0123456789", 10));
  test_assert(10 == read(pipe_fds[0], p + page_size - 16, 32));
  test_assert(!memcmp(p + page_size - 16, "0123456789", 10));
}

static void check_buffers(void) {
  char buf[16];

  check_efault(read(zero_fd, ro_page, 16));
  check_efault(read(zero_fd, none_page, 16));
  check_efault(read(zero_fd, shared_ro_page, 16));

  /* The data stays in the pipe. */
  test_assert(5 == write(pipe_fds[1], "hello", 5));
  check_efault(read(pipe_fds[0], ro_page, 5));
  check_efault(read(pipe_fds[0], none_page, 5));
  check_efault(read(pipe_fds[0], shared_ro_page, 5));
  test_assert(5 == read(pipe_fds[0], buf, 5));
  test_assert(!memcmp(buf, "hello", 5));

  check_short_read(rw_ro_pages);
  check_short_read(private_file_pages);
  check_short_read(shared_file_pages);

  check_syscallbuf_used();
  test_assert(16 == read(zero_fd, buf, sizeof(buf)));
}

static void check_handlers(sighandler_t expected) {
  struct sigaction sa;
  test_assert(0 == sigaction(SIGSEGV, NULL, &sa));
  test_assert(sa.sa_handler == expected);
  test_assert(0 == sigaction(SIGBUS, NULL, &sa));
  test_assert(sa.sa_handler == expected);
}

static char* map_file(const char* name, int flags) {
  static const char data[100];
  int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
  char* p;
  test_assert(fd >= 0);
  test_assert(100 == write(fd, data, sizeof(data)));
  p = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, flags, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == close(fd));
  return p;
}

int main(void) {
  struct sigaction sa;
  sigset_t mask;
  char buf[16];

  page_size = sysconf(_SC_PAGESIZE);
  ro_page = (char*)mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
  test_assert(ro_page != MAP_FAILED);
  none_page = (char*)mmap(NULL, page_size, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(none_page != MAP_FAILED);
  shared_ro_page = (char*)mmap(NULL, page_size, PROT_READ,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(shared_ro_page != MAP_FAILED);
  rw_ro_pages = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(rw_ro_pages != MAP_FAILED);
  test_assert(0 == mprotect(rw_ro_pages + page_size, page_size, PROT_READ));
  private_file_pages = map_file("syscallbuf_efault_private", MAP_PRIVATE);
  shared_file_pages = map_file("syscallbuf_efault_shared", MAP_SHARED);

  zero_fd = open("/dev/zero", O_RDONLY);
  test_assert(zero_fd >= 0);
  test_assert(0 == pipe(pipe_fds));

  /* Read once with a good buffer first, so that rr patches read()'s call site
     to use the syscall buffer. */
  test_assert(16 == read(zero_fd, buf, sizeof(buf)));
  test_assert(16 == read(zero_fd, buf, sizeof(buf)));

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  test_assert(0 == sigaction(SIGBUS, &sa, NULL));
  check_buffers();
  check_handlers(handler);

  /* The kernel resets a blocked or ignored signal's disposition when it
     forces one on the tracee. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGSEGV);
  sigaddset(&mask, SIGBUS);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  check_buffers();
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &mask));
  test_assert(sigismember(&mask, SIGSEGV));
  test_assert(sigismember(&mask, SIGBUS));
  check_handlers(handler);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &mask, NULL));

  test_assert(SIG_ERR != signal(SIGSEGV, SIG_IGN));
  test_assert(SIG_ERR != signal(SIGBUS, SIG_IGN));
  check_buffers();
  check_handlers(SIG_IGN);

  test_assert(0 == unlink("syscallbuf_efault_private"));
  test_assert(0 == unlink("syscallbuf_efault_shared"));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
