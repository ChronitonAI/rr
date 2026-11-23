/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/net.h>

/* When recvmmsg with a timeout receives a message, the kernel writes the
   time remaining back to the timeout. Each call below receives a datagram
   that is already queued, so the remaining time is a little less than the
   timeout. Without MSG_DONTWAIT rr may give the kernel scratch memory for
   the timeout.
   When the kernel can't read the timeout, the call fails with EFAULT before
   it receives anything; when it can't write it, the call fails with EFAULT
   after it received the datagram. */

#define TIMEOUT_SEC 5

/* The kernel's struct for recvmmsg_time64. */
struct kernel_timespec64 {
  int64_t tv_sec;
  int64_t tv_nsec;
};

/* The kernel's struct for recvmmsg and socketcall(SYS_RECVMMSG). */
struct kernel_timespec {
  long tv_sec;
  long tv_nsec;
};

enum Call { RECVMMSG, RECVMMSG_TIME64, SOCKETCALL };

static const char* const call_names[] = { "recvmmsg", "recvmmsg_time64",
                                          "socketcall(SYS_RECVMMSG)" };

enum BadTimeout { UNMAPPED, NO_ACCESS, READ_ONLY };

static const char* const bad_timeout_names[] = { "unmapped", "PROT_NONE",
                                                 "read-only" };

static const char msg[] = "datagram";

static int sockfds[2];

static void init_mmsg(struct mmsghdr* mmsg, struct iovec* iov, char* buf) {
  memset(buf, 0, sizeof(msg));
  iov->iov_base = buf;
  iov->iov_len = sizeof(msg);
  memset(mmsg, 0, sizeof(*mmsg));
  mmsg->msg_hdr.msg_iov = iov;
  mmsg->msg_hdr.msg_iovlen = 1;
}

static void init_timeout(enum Call call, void* timeout) {
  if (call == RECVMMSG_TIME64) {
    struct kernel_timespec64 ts = { TIMEOUT_SEC, 0 };
    memcpy(timeout, &ts, sizeof(ts));
  } else {
    struct kernel_timespec ts = { TIMEOUT_SEC, 0 };
    memcpy(timeout, &ts, sizeof(ts));
  }
}

static void read_timeout(enum Call call, const void* timeout, int64_t* sec,
                         int64_t* nsec) {
  if (call == RECVMMSG_TIME64) {
    struct kernel_timespec64 ts;
    memcpy(&ts, timeout, sizeof(ts));
    *sec = ts.tv_sec;
    *nsec = ts.tv_nsec;
  } else {
    struct kernel_timespec ts;
    memcpy(&ts, timeout, sizeof(ts));
    *sec = ts.tv_sec;
    *nsec = ts.tv_nsec;
  }
}

/* Receives up to one message with |call| and |flags|. */
static int call_recvmmsg(enum Call call, struct mmsghdr* mmsg, int flags,
                         void* timeout) {
  switch (call) {
    case RECVMMSG:
      return syscall(RR_recvmmsg, sockfds[1], mmsg, 1, flags, timeout);
    case RECVMMSG_TIME64:
      return syscall(RR_recvmmsg_time64, sockfds[1], mmsg, 1, flags, timeout);
    case SOCKETCALL: {
      unsigned long args[5] = { sockfds[1], (uintptr_t)mmsg, 1, flags,
                                (uintptr_t)timeout };
      return syscall(RR_socketcall, SYS_RECVMMSG, args);
    }
  }
  test_assert(0);
  return -1;
}

/* Receives a datagram with |call|, |flags| and a timeout of TIMEOUT_SEC,
   and checks the remaining time. Returns 0 if |call| is unavailable. */
static int receive(enum Call call, int flags) {
  char buf[sizeof(msg)];
  struct iovec iov;
  struct mmsghdr mmsg;
  struct kernel_timespec64 timeout;
  int64_t sec;
  int64_t nsec;
  int ret;

  init_mmsg(&mmsg, &iov, buf);
  init_timeout(call, &timeout);
  test_assert(sizeof(msg) == send(sockfds[0], msg, sizeof(msg), 0));

  ret = call_recvmmsg(call, &mmsg, flags, &timeout);
  if (ret == -1 && errno == ENOSYS) {
    atomic_printf("%s is unavailable\n", call_names[call]);
    test_assert(sizeof(msg) == recv(sockfds[1], buf, sizeof(buf), 0));
    return 0;
  }
  read_timeout(call, &timeout, &sec, &nsec);
  atomic_printf("%s with flags %#x returned %d, remaining time %lld.%09lld\n",
                call_names[call], flags, ret, (long long)sec, (long long)nsec);
  test_assert(ret == 1);
  test_assert(mmsg.msg_len == sizeof(msg));
  test_assert(memcmp(buf, msg, sizeof(msg)) == 0);
  test_assert(sec >= 0 && sec < TIMEOUT_SEC);
  test_assert(nsec >= 0 && nsec < 1000000000);
  return 1;
}

/* Calls |call| with |flags| for a queued datagram, with the timeout in a page
   that |bad| says the kernel can't read or can't write. */
static void receive_bad_timeout(enum Call call, int flags,
                                enum BadTimeout bad) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char buf[sizeof(msg)];
  struct iovec iov;
  struct mmsghdr mmsg;
  void* timeout;
  int64_t sec;
  int64_t nsec;
  int ret;
  int err;

  init_mmsg(&mmsg, &iov, buf);
  timeout = mmap(NULL, page_size,
                 bad == NO_ACCESS ? PROT_NONE : PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(timeout != MAP_FAILED);
  if (bad == READ_ONLY) {
    init_timeout(call, timeout);
    test_assert(0 == mprotect(timeout, page_size, PROT_READ));
  }
  test_assert(sizeof(msg) == send(sockfds[0], msg, sizeof(msg), 0));
  if (bad == UNMAPPED) {
    test_assert(0 == munmap(timeout, page_size));
  }

  ret = call_recvmmsg(call, &mmsg, flags, timeout);
  err = errno;
  atomic_printf("%s with flags %#x and the timeout in %s memory returned %d, "
                "errno %d\n",
                call_names[call], flags, bad_timeout_names[bad], ret, err);
  test_assert(ret == -1 && err == EFAULT);

  ret = recv(sockfds[1], buf, sizeof(buf), MSG_DONTWAIT);
  if (bad == READ_ONLY) {
    /* The kernel received the datagram and left the timeout unchanged. */
    test_assert(ret == -1 && errno == EAGAIN);
    read_timeout(call, timeout, &sec, &nsec);
    test_assert(sec == TIMEOUT_SEC && nsec == 0);
  } else {
    /* The kernel didn't receive the datagram. */
    test_assert(ret == sizeof(msg));
    test_assert(memcmp(buf, msg, sizeof(msg)) == 0);
  }
  if (bad != UNMAPPED) {
    test_assert(0 == munmap(timeout, page_size));
  }
}

static void test_call(enum Call call) {
  int flags[] = { 0, MSG_DONTWAIT };
  size_t i;
  int bad;

  for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
    if (!receive(call, flags[i])) {
      return;
    }
  }
  for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
    for (bad = UNMAPPED; bad <= READ_ONLY; ++bad) {
      receive_bad_timeout(call, flags[i], bad);
    }
  }
}

int main(void) {
  test_assert(0 == socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfds));

  test_call(RECVMMSG);
  if (RR_recvmmsg_time64 >= 0) {
    test_call(RECVMMSG_TIME64);
  }
  if (RR_socketcall >= 0) {
    test_call(SOCKETCALL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
