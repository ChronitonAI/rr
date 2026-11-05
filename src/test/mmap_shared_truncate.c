/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <setjmp.h>

#define DATA_OFFSET 100
#define MAP_PAGES 4

static const char data[] = "abcde";
static size_t page_size;

static sigjmp_buf fault_jmp;
static void* fault_addr;

enum Truncation {
  OPEN_RDWR_TRUNC,
  OPEN_RDONLY_TRUNC,
  FTRUNCATE,
  FTRUNCATE_PARTIAL,
  FTRUNCATE_SYSCALL,
  TRUNCATE,
  TRUNCATE_PROC_FD,
  TRUNCATION_COUNT
};

enum Growth {
  WRITE_IN_MAPPING,
  WRITE_PAST_MAPPINGS,
  FTRUNCATE64_PAST_4G,
  TRUNCATE_PATH,
  FALLOCATE_PAST_4G,
  SENDFILE,
  SPLICE,
  GROWTH_COUNT
};

static void handle_sigbus(__attribute__((unused)) int sig, siginfo_t* si,
                          __attribute__((unused)) void* context) {
  test_assert(si->si_code == BUS_ADRERR);
  __atomic_store_n(&fault_addr, si->si_addr, __ATOMIC_SEQ_CST);
  siglongjmp(fault_jmp, 1);
}

/* Returns whether reading `p` raises SIGBUS. */
static int read_faults(const char* p) {
  __atomic_store_n(&fault_addr, NULL, __ATOMIC_SEQ_CST);
  if (sigsetjmp(fault_jmp, 1)) {
    test_assert(__atomic_load_n(&fault_addr, __ATOMIC_SEQ_CST) == p);
    return 1;
  }
  (void)__atomic_load_n(p, __ATOMIC_SEQ_CST);
  return 0;
}

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
      /* 32-bit glibc calls ftruncate64. */
      test_assert(0 == ftruncate(fd, 0));
      break;
    case FTRUNCATE_PARTIAL:
      test_assert(0 == ftruncate(fd, DATA_OFFSET + 2));
      break;
    case FTRUNCATE_SYSCALL:
      test_assert(0 == syscall(RR_ftruncate, fd, 0L));
      break;
    case TRUNCATE:
      test_assert(0 == truncate("temp", 0));
      break;
    case TRUNCATE_PROC_FD:
      /* This path names the file through this process's fd table. */
      sprintf(path, "/proc/self/fd/%d", fd);
      test_assert(0 == truncate(path, 0));
      break;
    default:
      test_assert(0);
  }
}

/* Grows the file and returns its new size. Growth by a write leaves 'x'
   in the last byte. */
static uint64_t grow_file(int fd, enum Growth how, int* wrote_x) {
  int src_fd;
  int pipe_fds[2];
  off_t src_offset = 0;
  loff_t offset = 2 * page_size - 1;

  *wrote_x = 0;
  switch (how) {
    case WRITE_IN_MAPPING:
      test_assert(1 == pwrite(fd, "x", 1, 2 * page_size - 1));
      *wrote_x = 1;
      return 2 * page_size;
    case WRITE_PAST_MAPPINGS:
      test_assert(1 == pwrite(fd, "x", 1, MAP_PAGES * page_size));
      *wrote_x = 1;
      return MAP_PAGES * page_size + 1;
    case FTRUNCATE64_PAST_4G:
      test_assert(0 == ftruncate64(fd, (1LL << 32) + DATA_OFFSET));
      return (1ULL << 32) + DATA_OFFSET;
    case TRUNCATE_PATH:
      test_assert(0 == truncate("temp", 2 * page_size));
      return 2 * page_size;
    case FALLOCATE_PAST_4G:
      if (fallocate64(fd, 0, 1LL << 32, page_size)) {
        /* The file system doesn't support it. */
        test_assert(errno == EOPNOTSUPP);
        test_assert(0 == ftruncate64(fd, (1LL << 32) + page_size));
      }
      return (1ULL << 32) + page_size;
    case SENDFILE:
      /* sendfile writes at fd's file position. */
      src_fd = open("temp2", O_CREAT | O_EXCL | O_RDWR, 0600);
      test_assert(src_fd >= 0);
      test_assert(1 == write(src_fd, "x", 1));
      test_assert(2 * page_size - 1 ==
                  (size_t)lseek(fd, 2 * page_size - 1, SEEK_SET));
      test_assert(1 == sendfile(fd, src_fd, &src_offset, 1));
      test_assert(0 == close(src_fd));
      test_assert(0 == unlink("temp2"));
      *wrote_x = 1;
      return 2 * page_size;
    case SPLICE:
      /* splice writes at the offset it is given. */
      test_assert(0 == pipe(pipe_fds));
      test_assert(1 == write(pipe_fds[1], "x", 1));
      test_assert(1 == splice(pipe_fds[0], NULL, fd, &offset, 1, 0));
      test_assert(0 == close(pipe_fds[0]));
      test_assert(0 == close(pipe_fds[1]));
      *wrote_x = 1;
      return 2 * page_size;
    default:
      test_assert(0);
      return 0;
  }
}

static void check_bytes(const char* p, size_t kept) {
  size_t i;
  for (i = 0; i < sizeof(data) - 1; ++i) {
    test_assert(__atomic_load_n(p + DATA_OFFSET + i, __ATOMIC_SEQ_CST) ==
                (i < kept ? data[i] : 0));
  }
}

static void test_truncation(enum Truncation how, int in_child,
                            enum Growth growth) {
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR, 0600);
  char* p;
  char* q;
  pid_t child;
  int status;
  size_t kept = how == FTRUNCATE_PARTIAL ? 2 : 0;
  uint64_t size;
  int wrote_x;
  size_t i;

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

  /* Reading the mappings past the end of the file raises SIGBUS. */
  test_assert(read_faults(p + DATA_OFFSET) == !kept);
  if (kept) {
    check_bytes(p, kept);
  }
  test_assert(read_faults(p + page_size + DATA_OFFSET));
  test_assert(read_faults(q + DATA_OFFSET));

  /* The mappings read zeroes where the file grows again. */
  size = grow_file(fd, growth, &wrote_x);
  check_bytes(p, kept);
  check_bytes(p + page_size, 0);
  check_bytes(q, 0);
  if (wrote_x && size <= 2 * page_size) {
    test_assert(__atomic_load_n(p + size - 1, __ATOMIC_SEQ_CST) == 'x');
    test_assert(__atomic_load_n(q + size - 1 - page_size, __ATOMIC_SEQ_CST) ==
                'x');
  }
  for (i = 2; i < MAP_PAGES; ++i) {
    test_assert(read_faults(p + i * page_size) == (size <= i * page_size));
  }

  test_assert(0 == munmap(p, MAP_PAGES * page_size));
  test_assert(0 == munmap(q, page_size));
  test_assert(0 == close(fd));
  test_assert(0 == unlink("temp"));
}

int main(void) {
  struct sigaction sa;
  int how;
  int growth;

  page_size = sysconf(_SC_PAGESIZE);

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigbus;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGBUS, &sa, NULL));

  for (how = 0; how < TRUNCATION_COUNT; ++how) {
    for (growth = 0; growth < GROWTH_COUNT; ++growth) {
      test_truncation(how, 0, growth);
      test_truncation(how, 1, growth);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
