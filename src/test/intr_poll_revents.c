/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* When a signal interrupts poll(), the kernel writes the revents of every
   pollfd, whether poll() then fails with EINTR or is restarted. Each child
   below polls a pipe without data, in a pollfd array whose revents are all
   STALE_REVENTS, until its parent sends it a signal that runs a handler,
   with or without SA_RESTART, or stops and continues it and then sends that
   signal. poll() fails with EINTR, and both the handler and the child find
   every revents 0. The array is in memory the parent shares with the child,
   so in the stop case the parent checks that every revents is 0 while the
   child is stopped and sets them back to STALE_REVENTS before it continues
   the child. rr may give the kernel scratch memory for the small array, but
   not for the big one, which is larger than its 2 MiB scratch buffer. */

#define SMALL_NFDS 4
#define BIG_NFDS 300000

#define STALE_REVENTS 0x5a5a

enum interruption { HANDLER, HANDLER_WITH_SA_RESTART, STOP_THEN_HANDLER };

static const char* const interruption_names[] = {
  "handler", "handler with SA_RESTART", "stop, then handler"
};

static struct pollfd* poll_fds;
static unsigned int poll_nfds;
static int handler_calls;
/* The number of revents that weren't 0 when the handler ran. */
static unsigned int handler_unwritten;

static unsigned int count_unwritten(const struct pollfd* fds,
                                    unsigned int nfds) {
  unsigned int count = 0;
  unsigned int i;
  for (i = 0; i < nfds; ++i) {
    if (fds[i].revents != 0) {
      ++count;
    }
  }
  return count;
}

static void handle_usr1(__attribute__((unused)) int sig) {
  const struct pollfd* fds = __atomic_load_n(&poll_fds, __ATOMIC_SEQ_CST);
  unsigned int nfds = __atomic_load_n(&poll_nfds, __ATOMIC_SEQ_CST);
  __atomic_store_n(&handler_unwritten, count_unwritten(fds, nfds),
                   __ATOMIC_SEQ_CST);
  __atomic_add_fetch(&handler_calls, 1, __ATOMIC_SEQ_CST);
}

static void poll_until_interrupted(struct pollfd* fds, unsigned int nfds,
                                   int fd, int sa_flags) {
  struct sigaction sa;
  unsigned int unwritten;
  unsigned int handler_left;
  long ret;

  __atomic_store_n(&poll_fds, fds, __ATOMIC_SEQ_CST);
  __atomic_store_n(&poll_nfds, nfds, __ATOMIC_SEQ_CST);

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_usr1;
  sa.sa_flags = sa_flags;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));

  /* The syscall buffer's poll() writes every revents before it blocks, so
     make the syscall without it. */
  ret = unbufferable_syscall(RR_poll, (uintptr_t)fds, nfds, -1);
  test_assert(ret == -EINTR);
  test_assert(1 == __atomic_load_n(&handler_calls, __ATOMIC_SEQ_CST));
  test_assert(fds[0].fd == fd && fds[0].events == POLLIN);

  handler_left = __atomic_load_n(&handler_unwritten, __ATOMIC_SEQ_CST);
  unwritten = count_unwritten(fds, nfds);
  if (handler_left || unwritten) {
    atomic_printf("%u of %u revents unwritten when the handler ran, %u after "
                  "poll() returned\n",
                  handler_left, nfds, unwritten);
  }
  test_assert(handler_left == 0 && unwritten == 0);
}

/* The child sleeps in poll(), or in restart_syscall once the kernel has
   restarted poll() after a stop. */
static void wait_until_asleep_in_poll(pid_t child) {
  while (!task_asleep_in_syscall(child, RR_poll, -1) &&
         !task_asleep_in_syscall(child, RR_restart_syscall, -1)) {
    sched_yield();
  }
}

static void interrupt_poll(unsigned int nfds, enum interruption how) {
  size_t size = nfds * sizeof(struct pollfd);
  struct pollfd* poll_array;
  unsigned int unwritten;
  unsigned int i;
  int pipe_fds[2];
  pid_t child;
  int status;

  atomic_printf("%u pollfds, %s\n", nfds, interruption_names[how]);
  test_assert(0 == pipe(pipe_fds));
  poll_array = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(poll_array != MAP_FAILED);
  for (i = 0; i < nfds; ++i) {
    poll_array[i].fd = -1;
    poll_array[i].events = POLLIN;
    poll_array[i].revents = STALE_REVENTS;
  }
  poll_array[0].fd = pipe_fds[0];

  child = fork();
  test_assert(child >= 0);
  if (child == 0) {
    poll_until_interrupted(poll_array, nfds, pipe_fds[0],
                           how == HANDLER_WITH_SA_RESTART ? SA_RESTART : 0);
    exit(0);
  }
  test_assert(child > 1);

  wait_until_asleep_in_poll(child);
  if (how == STOP_THEN_HANDLER) {
    test_assert(0 == kill(child, SIGSTOP));
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    unwritten = count_unwritten(poll_array, nfds);
    if (unwritten) {
      atomic_printf("%u of %u revents unwritten while the child was stopped\n",
                    unwritten, nfds);
    }
    test_assert(unwritten == 0);
    for (i = 0; i < nfds; ++i) {
      poll_array[i].revents = STALE_REVENTS;
    }
    test_assert(0 == kill(child, SIGCONT));
    wait_until_asleep_in_poll(child);
  }
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  test_assert(0 == munmap(poll_array, size));
  test_assert(0 == close(pipe_fds[0]));
  test_assert(0 == close(pipe_fds[1]));
}

int main(void) {
  struct rlimit limit;
  int big = 1;
  int how;

  if (RR_poll < 0) {
    atomic_puts("poll() doesn't exist here, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* poll() fails with EINVAL for more pollfds than RLIMIT_NOFILE. */
  test_assert(0 == getrlimit(RLIMIT_NOFILE, &limit));
  if (limit.rlim_cur < BIG_NFDS) {
    if (limit.rlim_max < BIG_NFDS) {
      atomic_puts("Can't raise RLIMIT_NOFILE, skipping the big array");
      big = 0;
    } else {
      limit.rlim_cur = BIG_NFDS;
      test_assert(0 == setrlimit(RLIMIT_NOFILE, &limit));
    }
  }

  for (how = HANDLER; how <= STOP_THEN_HANDLER; ++how) {
    interrupt_poll(SMALL_NFDS, how);
    if (big) {
      interrupt_poll(BIG_NFDS, how);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
