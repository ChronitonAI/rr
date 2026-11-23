/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef SIOCGSTAMP_NEW
#define SIOCGSTAMP_NEW _IOR(0x89, 0x06, long long[2])
#endif
#ifndef SIOCGSTAMPNS_NEW
#define SIOCGSTAMPNS_NEW _IOR(0x89, 0x07, long long[2])
#endif

/* What SIOCGSTAMP_NEW (seconds, microseconds) and SIOCGSTAMPNS_NEW
   (seconds, nanoseconds) write on every architecture. */
struct stamp64 {
  int64_t sec;
  int64_t frac;
};

int main(void) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  char buf[4];
  /* Kernels without the _NEW codes
     (https://github.com/torvalds/linux/commit/0768e17073dc527ccd18ed5f96ce85f9985e9115)
     fail them with ENOTTY like any unknown socket ioctl, which may first
     read a struct ifreq from the argument. */
  union {
    struct stamp64 stamp;
    struct ifreq ifr;
  } probe;
  int has_new;
  struct timeval* tv;
  struct timespec* ts;
  struct stamp64* tv64;
  struct stamp64* ts64;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  test_assert(fd >= 0);

  /* No datagram has arrived yet, so there is no timestamp. */
  memset(&probe, 0, sizeof(probe));
  test_assert(-1 == ioctl(fd, SIOCGSTAMP_NEW, &probe));
  test_assert(errno == ENOENT || errno == ENOTTY);
  has_new = errno == ENOENT;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  test_assert(0 == bind(fd, (struct sockaddr*)&addr, sizeof(addr)));
  test_assert(0 == getsockname(fd, (struct sockaddr*)&addr, &addr_len));
  test_assert(1 == sendto(fd, "x", 1, 0, (struct sockaddr*)&addr,
                          sizeof(addr)));
  test_assert(1 == recv(fd, buf, sizeof(buf), 0));

  ALLOCATE_GUARD(tv, 'a');
  test_assert(0 == ioctl(fd, SIOCGSTAMP, tv));
  VERIFY_GUARD(tv);

  ALLOCATE_GUARD(ts, 'b');
  test_assert(0 == ioctl(fd, SIOCGSTAMPNS, ts));
  VERIFY_GUARD(ts);

  /* Both describe the timestamp of the datagram received above. */
  test_assert(tv->tv_sec > 0);
  test_assert(ts->tv_sec == tv->tv_sec);
  test_assert(ts->tv_nsec / 1000 == tv->tv_usec);

  if (!has_new) {
    atomic_puts("SIOCGSTAMP_NEW not supported, skipping the _NEW codes");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ALLOCATE_GUARD(tv64, 'c');
  test_assert(0 == ioctl(fd, SIOCGSTAMP_NEW, tv64));
  VERIFY_GUARD(tv64);

  ALLOCATE_GUARD(ts64, 'd');
  test_assert(0 == ioctl(fd, SIOCGSTAMPNS_NEW, ts64));
  VERIFY_GUARD(ts64);

  /* The _NEW codes describe the same timestamp. */
  test_assert(tv64->sec == tv->tv_sec);
  test_assert(tv64->frac == tv->tv_usec);
  test_assert(ts64->sec == ts->tv_sec);
  test_assert(ts64->frac == ts->tv_nsec);
  atomic_printf("stamp=%lld.%09lld\n", (long long)ts64->sec,
                (long long)ts64->frac);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
