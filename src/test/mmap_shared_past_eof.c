/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A MAP_SHARED mapping can write bytes past the end of the file in its
   last page. When the file's size changes, some file systems keep those
   bytes and others clear them, and writeback clears them on some. Each
   case writes 'J' there (or doesn't, or does and calls fsync()), changes
   the file, and prints what the mapping then reads past the old end, so
   a replay that reads other bytes produces other output. */

#define OLD_SIZE 100
#define TMPFS_MAGIC_NUMBER 0x01021994

enum Op {
  FTRUNCATE_IN_PAGE,
  FTRUNCATE_TO_PAGE_END,
  FTRUNCATE_PAST_PAGE,
  FTRUNCATE_SAME_SIZE,
  TRUNCATE_IN_PAGE,
  FALLOCATE_IN_PAGE,
  FALLOCATE_PAST_PAGE,
  FALLOCATE_KEEP_SIZE,
  PWRITE_AT_EOF,
  PWRITE_IN_PAGE,
  PWRITE_PAST_PAGE,
  WRITE_IN_PAGE,
  WRITEV_PAST_PAGE,
  PWRITEV_IN_PAGE,
  PWRITEV2_IN_PAGE,
  APPEND,
  SENDFILE_IN_PAGE,
  SPLICE_PAST_PAGE,
  OP_COUNT
};

static const char* const op_names[OP_COUNT] = {
  "ftruncate in page", "ftruncate to page end", "ftruncate past page",
  "ftruncate same size", "truncate in page", "fallocate in page",
  "fallocate past page", "fallocate keep size", "pwrite at eof",
  "pwrite in page", "pwrite past page", "write in page", "writev past page",
  "pwritev in page", "pwritev2 in page", "append", "sendfile in page",
  "splice past page"
};

enum Backing { MEMFD, CWD_FILE, DEV_SHM_FILE, BACKING_COUNT };

static const char* const backing_names[BACKING_COUNT] = { "memfd", "file",
                                                          "/dev/shm file" };

enum Junk { NO_JUNK, JUNK, JUNK_FSYNC, JUNK_COUNT };

static const char* const junk_names[JUNK_COUNT] = { "", ", junk",
                                                    ", junk, fsync" };

static size_t page_size;

/* Opens a new file of the given kind and stores its name, or returns -1. */
static int open_backing(enum Backing backing, char* name, size_t name_size) {
  struct statfs sfs;
  int fd;

  switch (backing) {
    case MEMFD:
      fd = memfd_create("mmap_shared_past_eof", 0);
      test_assert(fd >= 0);
      snprintf(name, name_size, "/proc/self/fd/%d", fd);
      return fd;
    case CWD_FILE:
      snprintf(name, name_size, "temp");
      fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
      test_assert(fd >= 0);
      return fd;
    case DEV_SHM_FILE:
      if (statfs("/dev/shm", &sfs) < 0 ||
          sfs.f_type != TMPFS_MAGIC_NUMBER) {
        return -1;
      }
      snprintf(name, name_size, "/dev/shm/rr-test-past-eof-XXXXXX");
      return mkstemp(name);
    default:
      test_assert(0);
      return -1;
  }
}

/* Changes the file. Returns 0 if the file system doesn't support it. */
static int do_op(int fd, const char* name, enum Op op) {
  struct iovec iov = { (void*)"w", 1 };
  loff_t off;
  off_t src_offset = 0;
  int pipe_fds[2];
  int fd2;
  int ret;

  switch (op) {
    case FTRUNCATE_IN_PAGE:
      test_assert(0 == ftruncate(fd, OLD_SIZE + 2));
      break;
    case FTRUNCATE_TO_PAGE_END:
      test_assert(0 == ftruncate(fd, page_size));
      break;
    case FTRUNCATE_PAST_PAGE:
      test_assert(0 == ftruncate(fd, 2 * page_size));
      break;
    case FTRUNCATE_SAME_SIZE:
      test_assert(0 == ftruncate(fd, OLD_SIZE));
      break;
    case TRUNCATE_IN_PAGE:
      test_assert(0 == truncate(name, OLD_SIZE + 2));
      break;
    case FALLOCATE_IN_PAGE:
    case FALLOCATE_PAST_PAGE:
    case FALLOCATE_KEEP_SIZE:
      ret = fallocate(fd, op == FALLOCATE_KEEP_SIZE ? FALLOC_FL_KEEP_SIZE : 0,
                      0,
                      op == FALLOCATE_IN_PAGE ? OLD_SIZE + 2 : 2 * page_size);
      if (ret < 0) {
        test_assert(errno == EOPNOTSUPP);
        return 0;
      }
      test_assert(ret == 0);
      break;
    case PWRITE_AT_EOF:
      test_assert(1 == pwrite(fd, "w", 1, OLD_SIZE));
      break;
    case PWRITE_IN_PAGE:
      test_assert(1 == pwrite(fd, "w", 1, 2 * OLD_SIZE));
      break;
    case PWRITE_PAST_PAGE:
      test_assert(1 == pwrite(fd, "w", 1, page_size + 10));
      break;
    case WRITE_IN_PAGE:
      test_assert(2 * OLD_SIZE == lseek(fd, 2 * OLD_SIZE, SEEK_SET));
      test_assert(1 == write(fd, "w", 1));
      break;
    case WRITEV_PAST_PAGE:
      test_assert((off_t)page_size + 10 ==
                  lseek(fd, page_size + 10, SEEK_SET));
      test_assert(1 == writev(fd, &iov, 1));
      break;
    case PWRITEV_IN_PAGE:
      test_assert(1 == pwritev(fd, &iov, 1, 2 * OLD_SIZE));
      break;
    case PWRITEV2_IN_PAGE:
      test_assert(1 == pwritev2(fd, &iov, 1, 2 * OLD_SIZE, 0));
      break;
    case APPEND:
      fd2 = open(name, O_WRONLY | O_APPEND);
      test_assert(fd2 >= 0);
      test_assert(1 == write(fd2, "w", 1));
      test_assert(0 == close(fd2));
      break;
    case SENDFILE_IN_PAGE:
      fd2 = memfd_create("src", 0);
      test_assert(fd2 >= 0);
      test_assert(1 == write(fd2, "w", 1));
      test_assert(2 * OLD_SIZE == lseek(fd, 2 * OLD_SIZE, SEEK_SET));
      test_assert(1 == sendfile(fd, fd2, &src_offset, 1));
      test_assert(0 == close(fd2));
      break;
    case SPLICE_PAST_PAGE:
      test_assert(0 == pipe(pipe_fds));
      test_assert(1 == write(pipe_fds[1], "w", 1));
      off = page_size + 10;
      test_assert(1 == splice(pipe_fds[0], NULL, fd, &off, 1, 0));
      test_assert(0 == close(pipe_fds[0]));
      test_assert(0 == close(pipe_fds[1]));
      break;
    default:
      test_assert(0);
  }
  return 1;
}

/* Prints the bytes from OLD_SIZE / 2 to the end of the first page as runs
   of 'a' (the file's data), 'J' (written through the mapping), 'w'
   (written by the op), '0' (zero). */
static void print_page(const char* label, const char* p, off_t size) {
  char line[512];
  size_t len;
  size_t i;
  size_t run_start = OLD_SIZE / 2;
  char prev = 0;

  len = snprintf(line, sizeof(line), "%s: size %lld:", label,
                 (long long)size);
  for (i = OLD_SIZE / 2; i <= page_size; ++i) {
    char c = i < page_size ? __atomic_load_n(p + i, __ATOMIC_SEQ_CST) : '$';
    char cls = c ? c : '0';
    test_assert(cls == 'a' || cls == 'J' || cls == 'w' || cls == '0' ||
                cls == '$');
    test_assert((cls == 'a') == (i < OLD_SIZE));
    if (i > OLD_SIZE / 2 && cls != prev) {
      len += snprintf(line + len, sizeof(line) - len, " [%zu,%zu)%c",
                      run_start, i, prev);
      test_assert(len < sizeof(line));
      run_start = i;
    }
    prev = cls;
  }
  atomic_puts(line);
}

static void test_case(enum Backing backing, enum Op op, enum Junk junk,
                      int in_child) {
  char name[64];
  char label[128];
  char data[OLD_SIZE];
  struct stat st;
  char* p;
  pid_t child;
  int status;
  int supported;
  size_t i;
  int fd = open_backing(backing, name, sizeof(name));

  if (fd < 0) {
    if (op == 0 && junk == NO_JUNK && !in_child) {
      atomic_printf("%s: not available\n", backing_names[backing]);
    }
    return;
  }

  memset(data, 'a', sizeof(data));
  test_assert(OLD_SIZE == write(fd, data, OLD_SIZE));
  p = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  if (junk != NO_JUNK) {
    for (i = OLD_SIZE; i < page_size; ++i) {
      __atomic_store_n(p + i, 'J', __ATOMIC_SEQ_CST);
    }
  }
  if (junk == JUNK_FSYNC) {
    test_assert(0 == fsync(fd));
  }

  if (in_child) {
    /* Change the file in a process that doesn't map it. */
    child = fork();
    test_assert(child >= 0);
    if (!child) {
      test_assert(0 == munmap(p, 2 * page_size));
      exit(do_op(fd, name, op) ? 77 : 78);
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status));
    test_assert(WEXITSTATUS(status) == 77 || WEXITSTATUS(status) == 78);
    supported = WEXITSTATUS(status) == 77;
  } else {
    supported = do_op(fd, name, op);
  }

  snprintf(label, sizeof(label), "%s, %s%s%s", backing_names[backing],
           op_names[op], junk_names[junk], in_child ? ", in child" : "");
  if (supported) {
    test_assert(0 == fstat(fd, &st));
    print_page(label, p, st.st_size);
  } else {
    atomic_printf("%s: not supported\n", label);
  }

  test_assert(0 == munmap(p, 2 * page_size));
  test_assert(0 == close(fd));
  if (backing != MEMFD) {
    test_assert(0 == unlink(name));
  }
}

int main(void) {
  int backing;
  int op;
  int junk;
  int in_child;

  page_size = sysconf(_SC_PAGESIZE);

  for (backing = 0; backing < BACKING_COUNT; ++backing) {
    for (op = 0; op < OP_COUNT; ++op) {
      for (junk = 0; junk < JUNK_COUNT; ++junk) {
        for (in_child = 0; in_child < 2; ++in_child) {
          test_case(backing, op, junk, in_child);
        }
      }
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
