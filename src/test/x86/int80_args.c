/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* i386 syscalls with memory parameters, made by an x86-64 process with
   int $0x80. */

#if defined(__x86_64__)

#include <linux/net.h>

struct iovec32 {
  uint32_t base;
  uint32_t len;
};

struct msghdr32 {
  uint32_t name, namelen, iov, iovlen, control, controllen, flags;
};

struct pollfd32 {
  int fd;
  short events, revents;
};

static void fill(unsigned char* p, int n, int seed) {
  int i;
  for (i = 0; i < n; ++i) {
    p[i] = (unsigned char)(seed + i * 7);
  }
}

static void check_filled(const unsigned char* p, int n, int seed) {
  int i;
  for (i = 0; i < n; ++i) {
    test_assert(p[i] == (unsigned char)(seed + i * 7));
  }
}

static void test_read(int fds[2]) {
  unsigned char* buf = int80_low_alloc(4096);
  unsigned char src[300];
  long ret;
  fill(src, sizeof(src), 1);
  test_assert(sizeof(src) == write(fds[1], src, sizeof(src)));
  memset(buf, 0xee, 512);
  ret = int80_3(I386_read, fds[0], LOW(buf), 512);
  test_assert(ret == sizeof(src));
  check_filled(buf, sizeof(src), 1);
  test_assert(buf[sizeof(src)] == 0xee);
  munmap(buf, 4096);
}

static void test_readv(int fds[2]) {
  unsigned char* buf = int80_low_alloc(4096);
  struct iovec32* iov = (struct iovec32*)(buf + 2048);
  unsigned char src[90];
  long ret;
  fill(src, sizeof(src), 2);
  test_assert(sizeof(src) == write(fds[1], src, sizeof(src)));
  memset(buf, 0xee, 2048);
  iov[0].base = LOW(buf);
  iov[0].len = 30;
  iov[1].base = LOW(buf + 64);
  iov[1].len = 100;
  ret = int80_3(I386_readv, fds[0], LOW(iov), 2);
  test_assert(ret == sizeof(src));
  check_filled(buf, 30, 2);
  test_assert(buf[30] == 0xee);
  check_filled(buf + 64, 60, 2 + 30 * 7);
  test_assert(buf[64 + 60] == 0xee);
  munmap(buf, 4096);
}

static void test_poll_and_ioctl(int fds[2]) {
  unsigned char* buf = int80_low_alloc(4096);
  struct pollfd32* pfd = (struct pollfd32*)buf;
  int* avail = (int*)(buf + 64);
  long ret;
  test_assert(10 == write(fds[1], "0123456789", 10));
  pfd->fd = fds[0];
  pfd->events = POLLIN;
  pfd->revents = 0;
  ret = int80_3(I386_poll, LOW(pfd), 1, 1000);
  test_assert(ret == 1);
  test_assert(pfd->revents == POLLIN);
  *avail = -1;
  ret = int80_3(I386_ioctl, fds[0], FIONREAD, LOW(avail));
  test_assert(ret == 0);
  test_assert(*avail == 10);
  test_assert(10 == read(fds[0], buf + 128, 10));
  munmap(buf, 4096);
}

static void test_recv(void) {
  unsigned char* buf = int80_low_alloc(4096);
  uint32_t* args = (uint32_t*)(buf + 1024);
  struct msghdr32* msg = (struct msghdr32*)(buf + 2048);
  struct iovec32* iov = (struct iovec32*)(buf + 3072);
  unsigned char src[50];
  int sv[2];
  long ret;
  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
  fill(src, sizeof(src), 3);
  test_assert(sizeof(src) == write(sv[0], src, sizeof(src)));
  /* socketcall(SYS_RECV), whose arguments are in memory */
  memset(buf, 0xee, 1024);
  args[0] = sv[1];
  args[1] = LOW(buf);
  args[2] = 20;
  args[3] = 0;
  ret = int80_2(I386_socketcall, SYS_RECV, LOW(args));
  test_assert(ret == 20);
  check_filled(buf, 20, 3);
  test_assert(buf[20] == 0xee);
  /* recvmsg with 32-bit pointers in the msghdr and the iovecs */
  iov[0].base = LOW(buf + 100);
  iov[0].len = 10;
  iov[1].base = LOW(buf + 200);
  iov[1].len = 100;
  memset(msg, 0, sizeof(*msg));
  msg->iov = LOW(iov);
  msg->iovlen = 2;
  ret = int80_3(I386_recvmsg, sv[1], LOW(msg), 0);
  test_assert(ret == 30);
  check_filled(buf + 100, 10, 3 + 20 * 7);
  test_assert(buf[110] == 0xee);
  check_filled(buf + 200, 20, 3 + 30 * 7);
  test_assert(buf[220] == 0xee);
  close(sv[0]);
  close(sv[1]);
  munmap(buf, 4096);
}

static int blocked_fds[2];
static pid_t main_tid;

static void* writer_thread(__attribute__((unused)) void* p) {
  unsigned char src[100];
  int80_wait_for_blocked_syscall(main_tid, I386_read);
  fill(src, sizeof(src), 4);
  test_assert(sizeof(src) == write(blocked_fds[1], src, sizeof(src)));
  return NULL;
}

/* A read that blocks */
static void test_blocking_read(void) {
  unsigned char* buf = int80_low_alloc(4096);
  pthread_t thread;
  long ret;
  test_assert(0 == pipe(blocked_fds));
  main_tid = sys_gettid();
  pthread_create(&thread, NULL, writer_thread, NULL);
  memset(buf, 0xee, 256);
  ret = int80_3(I386_read, blocked_fds[0], LOW(buf), 256);
  test_assert(ret == 100);
  check_filled(buf, 100, 4);
  test_assert(buf[100] == 0xee);
  pthread_join(thread, NULL);
  close(blocked_fds[0]);
  close(blocked_fds[1]);
  munmap(buf, 4096);
}

static volatile pid_t reader_tid;
static unsigned char* reader_buf;

static void* reader_thread(__attribute__((unused)) void* p) {
  long ret;
  reader_tid = sys_gettid();
  ret = int80_3(I386_read, blocked_fds[0], LOW(reader_buf), 256);
  test_assert(ret == 100);
  return NULL;
}

/* A read that blocks in a thread that isn't the main thread. rr's scratch
   memory for that thread is above 4GB, where an i386 syscall can't use it. */
static void test_blocking_read_in_thread(void) {
  unsigned char src[100];
  pthread_t thread;
  reader_buf = int80_low_alloc(4096);
  memset(reader_buf, 0xee, 256);
  test_assert(0 == pipe(blocked_fds));
  pthread_create(&thread, NULL, reader_thread, NULL);
  while (!reader_tid) {
    sched_yield();
  }
  int80_wait_for_blocked_syscall(reader_tid, I386_read);
  fill(src, sizeof(src), 5);
  test_assert(sizeof(src) == write(blocked_fds[1], src, sizeof(src)));
  pthread_join(thread, NULL);
  check_filled(reader_buf, 100, 5);
  test_assert(reader_buf[100] == 0xee);
  close(blocked_fds[0]);
  close(blocked_fds[1]);
  munmap(reader_buf, 4096);
}

/* struct ifreq of i386, with ifr_data in its union */
struct i386_ifreq {
  char name[IFNAMSIZ];
  uint32_t data;
  char padding[12];
};

/* ETHTOOL_GSTRINGS, which rr emulates with other SIOCETHTOOL ioctls, of the
   names of lo's features. Compared with the program's own ioctl. */
static void test_ethtool_gstrings(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr;
  struct {
    struct ethtool_sset_info hdr;
    uint32_t count;
  } info;
  struct ethtool_gstrings* native;
  struct ethtool_gstrings* gs;
  struct i386_ifreq* ifr32;
  size_t size;
  long ret;

  test_assert(fd >= 0);
  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, "lo");
  memset(&info, 0, sizeof(info));
  info.hdr.cmd = ETHTOOL_GSSET_INFO;
  info.hdr.sset_mask = 1 << ETH_SS_FEATURES;
  ifr.ifr_data = (void*)&info;
  if (ioctl(fd, SIOCETHTOOL, &ifr) < 0 || !info.hdr.sset_mask) {
    atomic_puts("No ETH_SS_FEATURES strings for lo, skipping");
    close(fd);
    return;
  }
  size = sizeof(*native) + info.count * ETH_GSTRING_LEN;
  native = calloc(1, size);
  native->cmd = ETHTOOL_GSTRINGS;
  native->string_set = ETH_SS_FEATURES;
  native->len = info.count;
  ifr.ifr_data = (void*)native;
  test_assert(0 == ioctl(fd, SIOCETHTOOL, &ifr));

  gs = int80_low_alloc(size);
  memset(gs, 0xee, size);
  gs->cmd = ETHTOOL_GSTRINGS;
  gs->string_set = ETH_SS_FEATURES;
  gs->len = info.count;
  ifr32 = int80_low_alloc(4096);
  memset(ifr32, 0xff, 4096);
  memset(ifr32, 0, sizeof(*ifr32));
  strcpy(ifr32->name, "lo");
  ifr32->data = (uint32_t)LOW(gs);
  ret = int80_3(I386_ioctl, fd, SIOCETHTOOL, LOW(ifr32));
  test_assert(ret == 0);
  test_assert(gs->len == native->len);
  test_assert(0 == memcmp(gs->data, native->data, gs->len * ETH_GSTRING_LEN));

  free(native);
  munmap(gs, size);
  munmap(ifr32, 4096);
  close(fd);
}

/* Files that rr monitors: /proc/stat (rr emulates reading it), /proc/self/mem
   and a file that is also mapped shared (rr notes writes to them). */
static void test_monitored_files(void) {
  unsigned char* buf = int80_low_alloc(4096);
  volatile uint32_t* target = (volatile uint32_t*)(buf + 3072);
  uint32_t* value = (uint32_t*)(buf + 3076);
  char tmpl[] = "int80_args-XXXXXX";
  char* shared;
  long ret;
  int fd;

  fd = open("/proc/stat", O_RDONLY);
  test_assert(fd >= 0);
  ret = int80_3(I386_read, fd, LOW(buf), 100);
  test_assert(ret == 100);
  test_assert(memcmp(buf, "cpu", 3) == 0);
  close(fd);

  fd = open("/proc/self/mem", O_RDWR);
  test_assert(fd >= 0);
  *target = 1;
  *value = 0x12345678;
  test_assert((off_t)(uintptr_t)target ==
              lseek(fd, (off_t)(uintptr_t)target, SEEK_SET));
  ret = int80_3(I386_write, fd, LOW(value), 4);
  test_assert(ret == 4);
  test_assert(*target == 0x12345678);
  close(fd);

  fd = mkstemp(tmpl);
  test_assert(fd >= 0);
  test_assert(0 == unlink(tmpl));
  test_assert(0 == ftruncate(fd, 4096));
  shared = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(shared != MAP_FAILED);
  strcpy((char*)buf, "written");
  ret = int80_3(I386_write, fd, LOW(buf), 8);
  test_assert(ret == 8);
  test_assert(strcmp(shared, "written") == 0);
  munmap(shared, 4096);
  close(fd);

  munmap(buf, 4096);
}

struct i386_dirent {
  uint32_t d_ino;
  uint32_t d_off;
  uint16_t d_reclen;
  char d_name[];
};

struct dirent64_ {
  uint64_t d_ino;
  int64_t d_off;
  uint16_t d_reclen;
  uint8_t d_type;
  char d_name[];
};

/* Lists /proc/self/fd with getdents64 (the program's view, which rr filters)
   into fds, without the fd of the directory itself; returns the count. */
static int list_fds_native(int* fds, int max) {
  char buf[4096];
  int n = 0;
  int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  test_assert(dir >= 0);
  while (1) {
    long bytes = syscall(SYS_getdents64, dir, buf, sizeof(buf));
    long off = 0;
    test_assert(bytes >= 0);
    if (!bytes) {
      break;
    }
    while (off < bytes) {
      struct dirent64_* d = (struct dirent64_*)(buf + off);
      if (d->d_name[0] != '.' && atoi(d->d_name) != dir) {
        test_assert(n < max);
        fds[n++] = atoi(d->d_name);
      }
      off += d->d_reclen;
    }
  }
  close(dir);
  return n;
}

/* The same with the i386 getdents64() or getdents(), reading size bytes at
   a time. dir itself is left out. */
static int list_fds_i386(int* fds, int max, int dir, long nr, size_t size) {
  unsigned char* buf = int80_low_alloc(4096);
  int n = 0;
  while (1) {
    long bytes = int80_3(nr, dir, LOW(buf), size);
    long off = 0;
    test_assert(bytes >= 0);
    if (!bytes) {
      break;
    }
    while (off < bytes) {
      const char* name;
      int reclen;
      if (nr == I386_getdents64) {
        struct dirent64_* d = (struct dirent64_*)(buf + off);
        name = d->d_name;
        reclen = d->d_reclen;
      } else {
        struct i386_dirent* d = (struct i386_dirent*)(buf + off);
        name = d->d_name;
        reclen = d->d_reclen;
      }
      test_assert(reclen > 0);
      if (name[0] != '.' && atoi(name) != dir) {
        test_assert(n < max);
        fds[n++] = atoi(name);
      }
      off += reclen;
    }
  }
  munmap(buf, 4096);
  return n;
}

/* rr hides its own fds from /proc/self/fd. */
static void test_proc_fd(void) {
  int expected[256];
  int got[256];
  int n_expected = list_fds_native(expected, 256);
  int n;
  int dir;
  int i;

  /* All entries at once, with getdents() */
  dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  test_assert(dir >= 0);
  n = list_fds_i386(got, 256, dir, I386_getdents, 4096);
  test_assert(n == n_expected);
  for (i = 0; i < n; ++i) {
    test_assert(got[i] == expected[i]);
  }
  close(dir);

  /* One entry at a time, with getdents64(): when rr hides an entry, it has to
     get the next one itself. */
  dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  test_assert(dir >= 0);
  n = list_fds_i386(got, 256, dir, I386_getdents64,
                    sizeof(struct dirent64_) + 8);
  test_assert(n == n_expected);
  for (i = 0; i < n; ++i) {
    test_assert(got[i] == expected[i]);
  }
  close(dir);
}

int main(void) {
  int fds[2];
  int80_setup();
  test_assert(0 == pipe(fds));
  test_read(fds);
  test_readv(fds);
  test_poll_and_ioctl(fds);
  test_recv();
  test_blocking_read();
  test_blocking_read_in_thread();
  test_ethtool_gstrings();
  test_monitored_files();
  test_proc_fd();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
