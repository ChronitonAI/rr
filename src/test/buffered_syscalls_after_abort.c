/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread blocks in a buffered recvmsg(), which rr aborts and
   performs as a traced syscall. The syscallbuf record of the aborted
   recvmsg() holds a copy of the msghdr, with pointers into the syscallbuf.
   Then the main thread makes many buffered writes and reads of different
   sizes, whose records overlay those bytes. Each of them must run exactly
   once. */

#define NUM_ROUNDS 10
#define NUM_IOVECS 8
#define NUM_ITERATIONS 2000

static int sockfds[2];
static int ackfds[2];
static volatile pid_t main_tid;

static char task_state(pid_t tid) {
  char path[100];
  char buf[1000];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/stat", tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  /* The state follows the command name in parentheses. */
  p = strrchr(buf, ')');
  test_assert(p && p[1] == ' ');
  return p[2];
}

static void* sender_thread(__attribute__((unused)) void* p) {
  char ch;
  int i;

  for (i = 0; i < NUM_ROUNDS; ++i) {
    /* Wait until the main thread is blocked in its recvmsg(). */
    while (task_state(main_tid) != 'S') {
      sched_yield();
    }
    test_assert(1 == write(sockfds[1], "x", 1));
    test_assert(1 == read(ackfds[0], &ch, 1));
  }
  return NULL;
}

int main(void) {
  char data[16];
  char buf[64];
  char bufs[NUM_IOVECS][8];
  struct iovec iov[NUM_IOVECS];
  struct msghdr msg;
  int pipefds[2];
  pthread_t thread;
  int i;
  int j;

  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds));
  test_assert(0 == pipe(ackfds));
  test_assert(0 == pipe2(pipefds, O_NONBLOCK));
  memset(data, 'y', sizeof(data));
  main_tid = sys_gettid();

  test_assert(0 == pthread_create(&thread, NULL, sender_thread, NULL));
  for (i = 0; i < NUM_ROUNDS; ++i) {
    memset(&msg, 0, sizeof(msg));
    for (j = 0; j < NUM_IOVECS; ++j) {
      iov[j].iov_base = bufs[j];
      iov[j].iov_len = sizeof(bufs[j]);
    }
    msg.msg_iov = iov;
    msg.msg_iovlen = NUM_IOVECS;
    test_assert(1 == recvmsg(sockfds[0], &msg, 0));
    test_assert(bufs[0][0] == 'x');

    for (j = 0; j < NUM_ITERATIONS; ++j) {
      ssize_t len = j % (int)sizeof(data) + 1;
      test_assert(len == write(pipefds[1], data, len));
      test_assert(len == read(pipefds[0], buf, sizeof(buf)));
    }
    test_assert(1 == write(ackfds[1], "a", 1));
  }
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
