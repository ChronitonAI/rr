/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* Check the siginfo of the SIGCHLD we get when a child stops, and when a
   tracee reaches a signal-delivery-stop, a group-stop, a ptrace event stop
   or a syscall stop, whether we take it in a handler, with sigwaitinfo() (in
   the thread that is the ptracer or in another one) or from a signalfd
   (with read(), readv() or preadv2()). SIGCHLD is blocked except in
   sigsuspend(), so we don't depend on timing. (Natively, whether two stops'
   SIGCHLDs merge depends on timing, so we check that only under rr; see
   below.) We also check that after setting SIGCHLD's action to SIG_IGN or
   SIG_DFL has discarded a pending SIGCHLD, the SIGCHLD for the next stop is
   for that stop.

   A sigwaitinfo() or sigtimedwait() that is woken up without a signal from
   its set to take fails with EINTR and isn't restarted, even when no signal
   has a handler: natively after a stop and SIGCONT (see signal(7)), and
   under rr when one of rr's own signals or a PTRACE_INTERRUPT wakes it up.
   So we retry it. */

enum {
  HANDLER,
  SIGWAITINFO,
  OTHER_THREAD,
  SIGNALFD,
  /* read() from a signalfd at a high fd, which rr's syscall buffering
     handles differently from low ones. */
  SIGNALFD_HIGH_FD,
  SIGNALFD_READV,
  /* readv() with room for more than one record: we read a SIGUSR2 with the
     SIGCHLD. */
  SIGNALFD_READV_MULTIPLE,
  /* preadv2() with offset -1, which reads like readv(). */
  SIGNALFD_PREADV2,
  /* readv() with an iovec bigger than rr's scratch memory, so that rr has
     the kernel write to our buffers rather than to scratch memory. */
  SIGNALFD_READV_BIG,
  /* As SIGNALFD_READV_BIG, with the record overwriting the iovec array. */
  SIGNALFD_READV_OVER_IOVECS,
  /* readv() into two iovecs at the same address, the second one bigger than
     rr's scratch memory: we read a SIGUSR2 into the first one and then the
     SIGCHLD into the second one, over the SIGUSR2. */
  SIGNALFD_READV_ALIASED,
  NUM_MODES
};

#define HIGH_FD 20000

static int mode;
static int sfd;
static int high_sfd;

/* Whether readv() from a signalfd fills its iovecs like one buffer, so that
   a record can be split across iovecs (Linux 6.10 and later). Otherwise it
   read()s each iovec in turn, going on to the next one only when a read()
   fills its iovec, and that read() waits for a signal like any read(). A
   read() into an iovec without room for a record fails with EINVAL, and
   readv() returns that error for the first iovec, and otherwise what it has
   read. */
static int split_records;

/* We readv() into iov_buf. Most iovecs are in its first 1024 bytes, the
   iovec array is at IOVECS_OFFSET, and from BIG_OFFSET to its end there's
   room for an iovec twice as big as rr's scratch memory (512 pages). */
#define MAX_IOVECS 8
#define IOVECS_OFFSET 1024
#define BIG_OFFSET (IOVECS_OFFSET + MAX_IOVECS * (int)sizeof(struct iovec))
static unsigned char* iov_buf;
static size_t iov_buf_size;
/* What we expect iov_buf to hold after a readv() */
static unsigned char* expected_buf;

/* An iovec for readv(), at |offset| in iov_buf, or NULL if |offset| is -1.
   A |len| of TO_END reaches the end of iov_buf. Our iovecs aren't in order
   in iov_buf and have gaps between them. A layout ends with END_OF_LAYOUT. */
struct segment {
  int offset;
  size_t len;
};
#define TO_END ((size_t)-1)
#define END_OF_LAYOUT { -2, 0 }
/* One byte too little room for a record. */
static const struct segment too_short[] = {
  { 600, 100 }, { 300, 0 }, { 200, 27 }, END_OF_LAYOUT
};
/* The layouts for a kernel that splits records across iovecs: */
/* Room for one record, split three ways, with a zero-length iovec. */
static const struct segment one_record[] = {
  { 600, 40 }, { 300, 0 }, { 200, 60 }, { 100, 28 }, END_OF_LAYOUT
};
/* Room for three records. The first two are split across iovecs. */
static const struct segment three_records[] = {
  { 800, 100 }, { -1, 0 }, { 400, 60 }, { 0, 200 }, { 600, 24 },
  END_OF_LAYOUT
};
/* The record is split between a small iovec and a big one. */
static const struct segment big[] = {
  { 600, 40 }, { 300, 0 }, { BIG_OFFSET, TO_END }, END_OF_LAYOUT
};
/* As |big|, with the small iovec at the iovec array. */
static const struct segment over_iovecs[] = {
  { IOVECS_OFFSET, 40 }, { 300, 0 }, { BIG_OFFSET, TO_END }, END_OF_LAYOUT
};
/* The first iovec has room for one record, and the second one, at the same
   address, is big. Both kinds of kernel read a record into each. */
static const struct segment aliased[] = {
  { BIG_OFFSET, sizeof(struct signalfd_siginfo) }, { BIG_OFFSET, TO_END },
  END_OF_LAYOUT
};
/* The layouts for a kernel that read()s each iovec in turn, where each iovec
   that readv() gets to has room for a record: */
/* The record partly fills the first iovec. */
static const struct segment one_record_unsplit[] = {
  { 600, 200 }, { -1, 0 }, { 200, 128 }, END_OF_LAYOUT
};
/* The first record fills the first iovec, and the second one partly fills
   the second. */
static const struct segment three_records_unsplit[] = {
  { 800, 128 }, { 400, 256 }, { 300, 0 }, { 0, 128 }, END_OF_LAYOUT
};
/* The record partly fills the big iovec. */
static const struct segment big_unsplit[] = {
  { BIG_OFFSET, TO_END }, { 300, 0 }, { 200, 128 }, END_OF_LAYOUT
};
/* The record partly fills the first iovec, which covers the iovec array. */
static const struct segment over_iovecs_unsplit[] = {
  { IOVECS_OFFSET - 72, 200 }, { 300, 0 }, { BIG_OFFSET, TO_END },
  END_OF_LAYOUT
};

static volatile int handler_ran;
static siginfo_t handler_si;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  handler_si = *si;
  handler_ran = 1;
}

static int sigwaitinfo_retry(const sigset_t* set, siginfo_t* si) {
  int ret;
  do {
    ret = sigwaitinfo(set, si);
  } while (ret < 0 && errno == EINTR);
  return ret;
}

static void* sigwaitinfo_thread(void* p) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo_retry(&set, (siginfo_t*)p));
  return NULL;
}

/* Read records from the signalfd with readv(), or preadv2() in
   SIGNALFD_PREADV2 mode, into iovecs laid out as |layout|, and gather the
   data read into |records|, which has room for |size| bytes. Returns what
   the syscall returned, with its errno. */
static ssize_t readv_records(const struct segment* layout,
                             struct signalfd_siginfo* records, size_t size) {
  struct iovec* iov = (struct iovec*)(iov_buf + IOVECS_OFFSET);
  struct iovec iov_copy[MAX_IOVECS];
  size_t end = BIG_OFFSET;
  size_t done = 0;
  ssize_t ret;
  int saved_errno;
  int count;
  int i;

  for (count = 0; layout[count].offset != -2; ++count) {
    test_assert(count < MAX_IOVECS);
    if (layout[count].offset < 0) {
      iov_copy[count].iov_base = NULL;
      iov_copy[count].iov_len = layout[count].len;
    } else {
      iov_copy[count].iov_base = iov_buf + layout[count].offset;
      iov_copy[count].iov_len = layout[count].len == TO_END
                                    ? iov_buf_size - layout[count].offset
                                    : layout[count].len;
      if (end < layout[count].offset + iov_copy[count].iov_len) {
        end = layout[count].offset + iov_copy[count].iov_len;
      }
    }
  }
  memset(iov_buf, 0xa5, end);
  memcpy(iov, iov_copy, count * sizeof(*iov));
  if (mode == SIGNALFD_PREADV2) {
    ret = syscall(SYS_preadv2, sfd, iov, count, -1L, -1L, 0);
  } else {
    ret = readv(sfd, iov, count);
  }
  saved_errno = errno;

  /* iov_buf is as we left it, except for the data read, which is the first
     |ret| bytes of the iovecs. */
  memset(expected_buf, 0xa5, end);
  memcpy(expected_buf + IOVECS_OFFSET, iov_copy, count * sizeof(*iov));
  for (i = 0; i < count && ret > 0; ++i) {
    size_t len = (size_t)ret - done;
    if (len > iov_copy[i].iov_len) {
      len = iov_copy[i].iov_len;
    }
    if (len) {
      size_t offset = (unsigned char*)iov_copy[i].iov_base - iov_buf;
      test_assert(done + len <= size);
      memcpy((char*)records + done, iov_copy[i].iov_base, len);
      memcpy(expected_buf + offset, iov_copy[i].iov_base, len);
    }
    done += len;
  }
  test_assert(ret < 0 || done == (size_t)ret);
  test_assert(0 == memcmp(iov_buf, expected_buf, end));
  errno = saved_errno;
  return ret;
}

/* Sets split_records: a readv() into two iovecs with room for half a
   record each reads a record if it fills them like one buffer, and
   otherwise fails with EINVAL for the first iovec. */
static void check_readv_splits_records(const sigset_t* mask) {
  struct signalfd_siginfo ssi;
  struct iovec iov[2];
  ssize_t ret;
  int fd = signalfd(-1, mask, SFD_NONBLOCK);

  test_assert(fd >= 0);
  iov[0].iov_base = &ssi;
  iov[0].iov_len = 64;
  iov[1].iov_base = (char*)&ssi + 64;
  iov[1].iov_len = sizeof(ssi) - 64;
  test_assert(0 == raise(SIGUSR2));
  ret = readv(fd, iov, 2);
  if (ret < 0) {
    test_assert(errno == EINVAL);
    test_assert(sizeof(ssi) == read(fd, &ssi, sizeof(ssi)));
    atomic_puts("readv() reads each iovec separately");
  } else {
    test_assert(ret == sizeof(ssi));
    split_records = 1;
  }
  test_assert(ssi.ssi_signo == SIGUSR2);
  test_assert(0 == close(fd));
}

static void wait_for_pending_sigchld(void) {
  sigset_t pending;
  while (1) {
    test_assert(0 == sigpending(&pending));
    if (sigismember(&pending, SIGCHLD)) {
      return;
    }
    sched_yield();
  }
}

static void check_sigchld(pid_t child, int code, int status) {
  sigset_t unblocked;
  sigset_t set;
  siginfo_t si;
  struct signalfd_siginfo ssi;
  struct signalfd_siginfo records[4];
  pthread_t thread;
  int i;

  sigemptyset(&unblocked);
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  memset(&si, 0, sizeof(si));
  switch (mode) {
    case HANDLER:
      handler_ran = 0;
      while (!handler_ran) {
        sigsuspend(&unblocked);
      }
      si = handler_si;
      break;
    case SIGWAITINFO:
      test_assert(SIGCHLD == sigwaitinfo_retry(&set, &si));
      break;
    case OTHER_THREAD:
      test_assert(0 == pthread_create(&thread, NULL, sigwaitinfo_thread, &si));
      test_assert(0 == pthread_join(thread, NULL));
      break;
    case SIGNALFD:
    case SIGNALFD_HIGH_FD:
      test_assert(sizeof(ssi) ==
                  read(mode == SIGNALFD ? sfd : high_sfd, &ssi, sizeof(ssi)));
      break;
    case SIGNALFD_READV:
    case SIGNALFD_PREADV2:
      test_assert(-1 == readv_records(too_short, records, sizeof(records)) &&
                  errno == EINVAL);
      test_assert(sizeof(ssi) ==
                  readv_records(split_records ? one_record : one_record_unsplit,
                                records, sizeof(records)));
      ssi = records[0];
      break;
    case SIGNALFD_READV_MULTIPLE:
      wait_for_pending_sigchld();
      test_assert(0 == raise(SIGUSR2));
      test_assert(2 * sizeof(ssi) ==
                  readv_records(split_records ? three_records
                                              : three_records_unsplit,
                                records, sizeof(records)));
      i = records[0].ssi_signo == SIGCHLD ? 0 : 1;
      test_assert(records[1 - i].ssi_signo == SIGUSR2);
      test_assert(records[1 - i].ssi_pid == (uint32_t)getpid());
      ssi = records[i];
      break;
    case SIGNALFD_READV_BIG:
      test_assert(sizeof(ssi) ==
                  readv_records(split_records ? big : big_unsplit, records,
                                sizeof(records)));
      ssi = records[0];
      break;
    case SIGNALFD_READV_OVER_IOVECS:
      test_assert(sizeof(ssi) ==
                  readv_records(split_records ? over_iovecs
                                              : over_iovecs_unsplit,
                                records, sizeof(records)));
      ssi = records[0];
      break;
    case SIGNALFD_READV_ALIASED:
      wait_for_pending_sigchld();
      test_assert(0 == raise(SIGUSR2));
      test_assert(2 * sizeof(ssi) ==
                  readv_records(aliased, records, sizeof(records)));
      /* Both iovecs hold the SIGCHLD now. */
      ssi = records[1];
      break;
  }
  if (mode >= SIGNALFD) {
    test_assert(ssi.ssi_signo == SIGCHLD);
    test_assert(ssi.ssi_code == code);
    test_assert(ssi.ssi_pid == (uint32_t)child);
    test_assert(ssi.ssi_status == status);
    return;
  }
  test_assert(si.si_signo == SIGCHLD);
  test_assert(si.si_code == code);
  test_assert(si.si_pid == child);
  test_assert(si.si_status == status);
}

/* Discard any SIGCHLD that is pending, e.g. for a child's exit. */
static void drain_sigchld(void) {
  sigset_t set;
  struct timespec ts = { 0, 0 };
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  while (SIGCHLD == sigtimedwait(&set, NULL, &ts)) {
  }
}

/* copy_file_range() fails before it reads or writes anything if either fd is
   a signalfd, which isn't a regular file: with EINVAL for these other fds (or
   with ENOSYS if the kernel doesn't have it). */
static void check_copy_file_range_fails(void) {
  int fd = open("dummy.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
  int fds[][2] = { { sfd, fd }, { fd, sfd }, { sfd, STDOUT_FILENO } };
  size_t i;

  test_assert(fd >= 0);
  test_assert(0 == unlink("dummy.txt"));
  for (i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
    test_assert(-1 == syscall(RR_copy_file_range, fds[i][0], NULL, fds[i][1],
                              NULL, (size_t)1, 0));
    test_assert(errno == EINVAL || errno == ENOSYS);
  }
  test_assert(0 == close(fd));
}

/* Set SIGCHLD's action to |action|, which discards a pending SIGCHLD, and
   then back to our handler. */
static void discard_sigchld(void (*action)(int)) {
  struct sigaction sa;
  struct sigaction old_sa;
  sigset_t pending;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = action;
  test_assert(0 == sigaction(SIGCHLD, &sa, &old_sa));
  test_assert(0 == sigaction(SIGCHLD, &old_sa, NULL));
  test_assert(0 == sigpending(&pending));
  test_assert(!sigismember(&pending, SIGCHLD));
}

static void run_scenarios(int* pipe_fds);

int main(void) {
  int pipe_fds[2];
  struct sigaction sa;
  sigset_t mask;
  struct rlimit limit;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGUSR2);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(pipe_fds));
  test_assert(0 <= (sfd = signalfd(-1, &mask, 0)));
  check_readv_splits_records(&mask);
  iov_buf_size = BIG_OFFSET + 1024 * sysconf(_SC_PAGESIZE);
  iov_buf = mmap(NULL, iov_buf_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(iov_buf != MAP_FAILED);
  expected_buf = mmap(NULL, iov_buf_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(expected_buf != MAP_FAILED);
  high_sfd = sfd;
  test_assert(0 == getrlimit(RLIMIT_NOFILE, &limit));
  if (limit.rlim_max > HIGH_FD) {
    if (limit.rlim_cur <= HIGH_FD) {
      limit.rlim_cur = HIGH_FD + 1;
      test_assert(0 == setrlimit(RLIMIT_NOFILE, &limit));
    }
    test_assert(HIGH_FD == (high_sfd = dup2(sfd, HIGH_FD)));
  } else {
    atomic_puts("Can't open a high fd, reading the low one instead");
  }

  for (mode = 0; mode < NUM_MODES; ++mode) {
    run_scenarios(pipe_fds);
  }
  check_copy_file_range_fails();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

static void run_scenarios(int* pipe_fds) {
  pid_t child;
  int status;
  char ch = 'x';

  /* A child stops. */
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    exit(77);
  }
  check_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a signal-delivery-stop. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    raise(SIGUSR1);
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGUSR1);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a group-stop (a PTRACE_EVENT_STOP, since it was
     seized): CLD_STOPPED with the stop signal. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    raise(SIGSTOP);
    exit(77);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  check_sigchld(child, CLD_STOPPED, SIGSTOP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a ptrace event stop: CLD_TRAPPED with SIGTRAP. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEEXIT));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGTRAP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  /* A tracee reaches a syscall stop under PTRACE_O_TRACESYSGOOD (at
     sched_yield()): CLD_TRAPPED with SIGTRAP, without the 0x80. */
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    raise(SIGUSR1);
    sched_yield();
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  check_sigchld(child, CLD_TRAPPED, SIGUSR1);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  check_sigchld(child, CLD_TRAPPED, SIGTRAP);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  drain_sigchld();

  {
    /* A tracee stops, and setting SIGCHLD's action to SIG_IGN discards the
       pending SIGCHLD for that. A child stops, and setting the action to
       SIG_DFL (which for SIGCHLD is to ignore it) discards its SIGCHLD.
       Another child stops, and the SIGCHLD must be for that one. */
    pid_t tracee;
    pid_t stopped_child;
    pid_t child2;
    if (0 == (tracee = fork())) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    wait_for_pending_sigchld();
    discard_sigchld(SIG_IGN);
    if (0 == (stopped_child = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    wait_for_pending_sigchld();
    discard_sigchld(SIG_DFL);
    if (0 == (child2 = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    check_sigchld(child2, CLD_STOPPED, SIGSTOP);
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(stopped_child, SIGCONT));
    test_assert(stopped_child == waitpid(stopped_child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(child2, SIGCONT));
    test_assert(child2 == waitpid(child2, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    drain_sigchld();
  }

  if (mode != HANDLER) {
    /* A tracee stops, and while the SIGCHLD for that is pending, a child
       stops: Linux merges the child's SIGCHLD into the pending one, which is
       for the tracee. Once we've waited for both, another child stops, and
       the SIGCHLD must be for that one. (We poll for the first child's stop
       with waitid(WNOHANG), so that this checks the SIGCHLDs and not whether
       the stop wakes a thread blocked in a wait while the tracee's SIGCHLD is
       pending. Under rr, the child's SIGCHLD is sent by the time we see its
       stop, so the merge is deterministic. Natively it isn't guaranteed:
       Linux marks the child stopped before it sends the SIGCHLD
       (do_signal_stop()), so the SIGCHLD can even arrive after we've waited
       for the stop. So we check the second child's SIGCHLD only under rr. In
       a handler, we'd get a SIGCHLD for the first child too, as rr sends
       another one for the stops it still owes us.) */
    pid_t tracee;
    pid_t stopped_child;
    pid_t child2;
    siginfo_t si;
    if (0 == (tracee = fork())) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    wait_for_pending_sigchld();
    if (0 == (stopped_child = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    while (1) {
      memset(&si, 0, sizeof(si));
      test_assert(
          0 == waitid(P_PID, stopped_child, &si, WSTOPPED | WNOWAIT | WNOHANG));
      if (si.si_pid == stopped_child) {
        break;
      }
      sched_yield();
    }
    test_assert(si.si_code == CLD_STOPPED);
    check_sigchld(tracee, CLD_TRAPPED, SIGUSR1);
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(stopped_child == waitpid(stopped_child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    if (0 == (child2 = fork())) {
      raise(SIGSTOP);
      exit(77);
    }
    if (running_under_rr()) {
      check_sigchld(child2, CLD_STOPPED, SIGSTOP);
    }
    test_assert(child2 == waitpid(child2, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(stopped_child, SIGCONT));
    test_assert(stopped_child == waitpid(stopped_child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(0 == kill(child2, SIGCONT));
    test_assert(child2 == waitpid(child2, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    drain_sigchld();
  }

  if (mode == SIGWAITINFO) {
    /* We take the SIGCHLD for a tracee's stop without asking for its
       siginfo (sigtimedwait(set, NULL, ...)). After we've resumed the
       tracee, another tracee stops, and the SIGCHLD must be for that one. */
    pid_t tracee;
    pid_t tracee2;
    int pipe2_fds[2];
    sigset_t set;
    int ret;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    test_assert(0 == pipe(pipe2_fds));
    if (0 == (tracee = fork())) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    do {
      ret = sigtimedwait(&set, NULL, NULL);
    } while (ret < 0 && errno == EINTR);
    test_assert(SIGCHLD == ret);
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
    if (0 == (tracee2 = fork())) {
      test_assert(1 == read(pipe2_fds[0], &ch, 1));
      raise(SIGUSR1);
      exit(77);
    }
    test_assert(0 == ptrace(PTRACE_SEIZE, tracee2, NULL, NULL));
    test_assert(1 == write(pipe2_fds[1], &ch, 1));
    check_sigchld(tracee2, CLD_TRAPPED, SIGUSR1);
    test_assert(tracee2 == waitpid(tracee2, &status, 0));
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_CONT, tracee2, NULL, NULL));
    test_assert(tracee2 == waitpid(tracee2, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    test_assert(1 == write(pipe_fds[1], &ch, 1));
    test_assert(tracee == waitpid(tracee, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    drain_sigchld();
    close(pipe2_fds[0]);
    close(pipe2_fds[1]);
  }
}
