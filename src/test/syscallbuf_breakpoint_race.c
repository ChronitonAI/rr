/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* A signal that arrives while a thread is in syscallbuf code is stashed. rr
 * then blocks all of the thread's signals and, when it resumes the thread to
 * run tracee code, sets breakpoints at the syscallbuf's syscall entries and
 * final exit, where it can deliver the signal. Those breakpoints are shared by
 * the address space, so another thread's stop must leave them in place while
 * the first thread runs.
 *
 * In each iteration both threads ask rr for a time-slice signal after a number
 * of ticks that puts it in the syscallbuf's loop over the iovecs of a
 * recvmsg():
 * - Thread B's recvmsg() is buffered and blocks. rr continues B's desched'd
 *   recvmsg(), setting no breakpoints since B is in a syscall, with the
 *   signal still stashed and the desched event rearmed. So as soon as B runs,
 *   its recvmsg() is interrupted and B stops.
 * - The main thread's recvmsg() asks for more data than the syscall buffer
 *   holds, so after the loop the syscallbuf code makes it a traced syscall.
 *   rr resumes the main thread with the breakpoints set, and the main thread
 *   stops next at the breakpoint at the traced syscall entry, where rr
 *   delivers the signal.
 * The threads' scheduling settings make rr handle B's stop while the main
 * thread runs towards that breakpoint:
 * - B's nice value is lower than the main thread's, and rr's scheduler uses
 *   nice values as priorities. So rr switches to B (whose previous recvmsg()
 *   the main thread has just completed) at the exit of the main thread's
 *   SYS_rrcall_arm_time_slice, and back to the main thread when B blocks.
 *   Since B is then in a syscall as far as rr knows, rr handles a stop of B
 *   while it waits for the main thread to stop.
 * - Both threads are SCHED_BATCH, so waking either doesn't preempt the task
 *   that's running, and the kernel runs rr and B before the main thread when
 *   it can. So the main thread runs to its signal while B is blocked, and once
 *   rr has resumed it with the breakpoints set, B and rr run before it does.
 * - The main thread leads the thread group, so when its stop and B's are both
 *   pending, waitid() reports the main thread's first.
 * The kernel can still schedule them in another order, for example when other
 * tasks run on the same CPU, so the test does many iterations.
 *
 * After each recvmsg() the main thread checks that its signal mask is the one
 * it set.
 */

#define ITERATIONS 100
#define NUM_IOVS 512
/* The syscallbuf's loop takes about a tick per iovec, and starts a few dozen
   ticks after SYS_rrcall_arm_time_slice returns. */
#define MAIN_TICKS (NUM_IOVS / 2 + 64)
/* For a buffered recvmsg() the syscallbuf loops over the iovecs twice before
   the syscall. */
#define B_TICKS (NUM_IOVS + 64)

static int main_sockets[2];
static int b_sockets[2];
static char main_buf[8192];
static struct iovec main_iovs[NUM_IOVS];
static char b_bytes[NUM_IOVS];
static struct iovec b_iovs[NUM_IOVS];
static volatile int done;

static void arm_time_slice(long ticks) {
  test_assert(0 == syscall(SYS_rrcall_arm_time_slice, ticks, 0L, 0L, 0L, 0L,
                           0L));
}

static void set_batch_policy(void) {
  struct sched_param param = { 0 };
  test_assert(0 == sched_setscheduler(0, SCHED_BATCH, &param));
}

/* The libc wrapper may use socketcall, which the syscallbuf doesn't buffer. */
static long sys_recvmsg(int fd, struct msghdr* msg, int flags) {
  return syscall(SYS_recvmsg, fd, msg, flags);
}

/* NUM_IOVS * sizeof(main_buf) is more than the syscall buffer holds. */
static void main_receive(void) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = main_iovs;
  msg.msg_iovlen = NUM_IOVS;
  test_assert(-1 == sys_recvmsg(main_sockets[0], &msg, MSG_DONTWAIT));
  test_assert(errno == EAGAIN);
}

static void b_receive(void) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = b_iovs;
  msg.msg_iovlen = NUM_IOVS;
  /* This can receive the bytes of more than one iteration. */
  test_assert(sys_recvmsg(b_sockets[0], &msg, 0) >= 1);
}

static void check_mask(const sigset_t* expected) {
  sigset_t cur;
  int i;
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &cur));
  for (i = 1; i < 32; ++i) {
    test_assert(sigismember(&cur, i) == sigismember(expected, i));
  }
}

static void* do_thread(__attribute__((unused)) void* p) {
  set_batch_policy();
  while (1) {
    b_receive();
    if (done) {
      break;
    }
    arm_time_slice(B_TICKS);
  }
  return NULL;
}

int main(void) {
  pthread_t thread;
  sigset_t mask;
  int i;

  if (!running_under_rr()) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, main_sockets));
  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, b_sockets));
  for (i = 0; i < NUM_IOVS; ++i) {
    main_iovs[i].iov_base = main_buf;
    main_iovs[i].iov_len = sizeof(main_buf);
    b_iovs[i].iov_base = &b_bytes[i];
    b_iovs[i].iov_len = 1;
  }
  /* A mask of our own, which rr's all-blocked mask can't be mistaken for. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR2);
  test_assert(0 == pthread_sigmask(SIG_SETMASK, &mask, NULL));
  /* Let rr patch the syscall() wrapper before the iterations start. */
  main_receive();

  test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 10));
  set_batch_policy();
  for (i = 0; i < ITERATIONS; ++i) {
    test_assert(1 == write(b_sockets[1], "x", 1));
    arm_time_slice(MAIN_TICKS);
    main_receive();
    check_mask(&mask);
  }
  done = 1;
  test_assert(1 == write(b_sockets[1], "x", 1));
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
