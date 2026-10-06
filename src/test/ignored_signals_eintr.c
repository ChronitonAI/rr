/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

/* Our main thread waits, without a timeout, in a syscall that fails with
   EINTR rather than being restarted when a signal wakes it up:
   rt_sigtimedwait (and rt_sigtimedwait_time64 on 32-bit x86), epoll_wait,
   epoll_pwait, epoll_pwait2, semop (ipc SEMOP on 32-bit x86) or semtimedop
   (ipc SEMTIMEDOP, and semtimedop_time64, on 32-bit x86). Another thread
   sends it signals that it ignores (SIGUSR1, whose handler is SIG_IGN, and
   SIGWINCH, whose handler is SIG_DFL), each once the main thread is asleep
   in its syscall, and then gives it what it waits for. Linux discards the
   ignored signals, so they don't wake up the main thread, and its syscall
   must succeed. Then a single-threaded child waits in sigwaitinfo(), and we
   send the same signals to its process. Finally, a child that we trace waits
   in sigwaitinfo(), and we send it SIGUSR1. Linux queues that for a traced
   process, so its sigwaitinfo() must fail with EINTR. */

enum {
  SIGWAITINFO,
  RT_SIGTIMEDWAIT_TIME64,
  EPOLL_WAIT,
  EPOLL_PWAIT,
  EPOLL_PWAIT2,
  SEMOP,
  SEMTIMEDOP,
  SEMTIMEDOP_TIME64,
  NUM_CASES
};

static pid_t main_tid;
static volatile int waiting;
static int pipe_fds[2];
static int epfd;
static int semid;

static void read_proc_file(const char* path, char* buf, size_t size) {
  int fd = open(path, O_RDONLY);
  ssize_t len;
  test_assert(fd >= 0);
  len = read(fd, buf, size - 1);
  test_assert(len >= 0);
  close(fd);
  buf[len] = 0;
}

/* Whether the main thread is asleep. Once it has set |waiting|, it makes no
   syscall other than the one it waits in. */
static int main_thread_asleep(void) {
  char path[100];
  char buf[1000];
  char* p;
  sprintf(path, "/proc/self/task/%d/stat", main_tid);
  read_proc_file(path, buf, sizeof(buf));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  return p[1] == ' ' && p[2] == 'S';
}

static void wait_until_main_thread_asleep(void) {
  while (!waiting || !main_thread_asleep()) {
    sched_yield();
  }
}

static void* sender(void* p) {
  int c = (int)(uintptr_t)p;
  static const int ignored_sigs[] = { SIGUSR1, SIGWINCH };
  size_t i;
  char ch = 'x';
  struct sembuf up = { 0, 1, 0 };

  for (i = 0; i < sizeof(ignored_sigs) / sizeof(ignored_sigs[0]); ++i) {
    wait_until_main_thread_asleep();
    test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, ignored_sigs[i]));
  }
  wait_until_main_thread_asleep();
  switch (c) {
    case SIGWAITINFO:
    case RT_SIGTIMEDWAIT_TIME64:
      test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR2));
      break;
    case EPOLL_WAIT:
    case EPOLL_PWAIT:
    case EPOLL_PWAIT2:
      test_assert(1 == write(pipe_fds[1], &ch, 1));
      break;
    case SEMOP:
    case SEMTIMEDOP:
    case SEMTIMEDOP_TIME64:
      test_assert(0 == semop(semid, &up, 1));
      break;
  }
  return NULL;
}

/* Whether process |pid| is asleep in sigwaitinfo(). */
static int asleep_in_sigwaitinfo(pid_t pid) {
  char path[100];
  char buf[1000];
  char* p;
  long nr;
  sprintf(path, "/proc/%d/stat", pid);
  read_proc_file(path, buf, sizeof(buf));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  /* If it has exited, its sigwaitinfo() failed. */
  test_assert(p[2] != 'Z');
  if (p[1] != ' ' || p[2] != 'S') {
    return 0;
  }
  /* "running", or the syscall number and its arguments */
  sprintf(path, "/proc/%d/syscall", pid);
  read_proc_file(path, buf, sizeof(buf));
  if (1 != sscanf(buf, "%ld", &nr)) {
    return 0;
  }
#ifdef SYS_rt_sigtimedwait_time64
  if (nr == SYS_rt_sigtimedwait_time64) {
    return 1;
  }
#endif
  return nr == SYS_rt_sigtimedwait;
}

static void run_process_case(void) {
  static const int sigs[] = { SIGUSR1, SIGWINCH, SIGUSR2 };
  size_t i;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    sigset_t set;
    siginfo_t si;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    test_assert(SIGUSR2 == sigwaitinfo(&set, &si));
    exit(77);
  }
  for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); ++i) {
    while (!asleep_in_sigwaitinfo(child)) {
      sched_yield();
    }
    test_assert(0 == kill(child, sigs[i]));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void run_traced_case(void) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    sigset_t set;
    siginfo_t si;
    int ret;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    ret = sigwaitinfo(&set, &si);
    exit(ret < 0 && errno == EINTR ? 77 : 1);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  while (!asleep_in_sigwaitinfo(child)) {
    sched_yield();
  }
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGUSR1));
  /* This would end a sigwaitinfo() that had been restarted. */
  test_assert(0 == kill(child, SIGUSR2));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void run_case(int c) {
  pthread_t thread;
  sigset_t set;
  siginfo_t si;
  struct epoll_event ev;
  struct sembuf down = { 0, -1, 0 };
  char ch;
  int ret;

  waiting = 0;
  test_assert(0 == pthread_create(&thread, NULL, sender, (void*)(uintptr_t)c));
  waiting = 1;
  switch (c) {
    case SIGWAITINFO:
      sigemptyset(&set);
      sigaddset(&set, SIGUSR2);
      test_assert(SIGUSR2 == sigwaitinfo(&set, &si));
      break;
    case RT_SIGTIMEDWAIT_TIME64:
      sigemptyset(&set);
      sigaddset(&set, SIGUSR2);
      ret = -1;
      errno = ENOSYS;
#ifdef SYS_rt_sigtimedwait_time64
      ret = syscall(SYS_rt_sigtimedwait_time64, &set, &si, NULL, 8);
#endif
      if (ret < 0 && errno == ENOSYS) {
        /* Not 32-bit x86, or Linux < 5.1 */
        ret = sigwaitinfo(&set, &si);
      }
      test_assert(SIGUSR2 == ret);
      break;
    case EPOLL_WAIT:
      test_assert(1 == epoll_wait(epfd, &ev, 1, -1));
      break;
    case EPOLL_PWAIT:
      test_assert(1 == epoll_pwait(epfd, &ev, 1, -1, NULL));
      break;
    case EPOLL_PWAIT2:
      ret = syscall(SYS_epoll_pwait2, epfd, &ev, 1, NULL, NULL, 0);
      if (ret < 0 && errno == ENOSYS) {
        /* Linux < 5.11 */
        ret = epoll_wait(epfd, &ev, 1, -1);
      }
      test_assert(1 == ret);
      break;
    case SEMOP:
      /* glibc's semop() uses semtimedop */
#if defined(SYS_semop)
      test_assert(0 == syscall(SYS_semop, semid, &down, 1));
#elif defined(SYS_ipc)
      /* SEMOP */
      test_assert(0 == syscall(SYS_ipc, 1, semid, 1, 0, &down));
#else
      test_assert(0 == semop(semid, &down, 1));
#endif
      break;
    case SEMTIMEDOP:
      test_assert(0 == semtimedop(semid, &down, 1, NULL));
      break;
    case SEMTIMEDOP_TIME64:
      ret = -1;
      errno = ENOSYS;
#ifdef SYS_semtimedop_time64
      ret = syscall(SYS_semtimedop_time64, semid, &down, 1, NULL);
#endif
      if (ret < 0 && errno == ENOSYS) {
        /* Not 32-bit x86, or Linux < 5.1 */
        ret = semtimedop(semid, &down, 1, NULL);
      }
      test_assert(0 == ret);
      break;
  }
  waiting = 0;
  test_assert(0 == pthread_join(thread, NULL));
  if (c == EPOLL_WAIT || c == EPOLL_PWAIT || c == EPOLL_PWAIT2) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
  }
}

int main(void) {
  sigset_t set;
  struct epoll_event ev;
  int c;

  test_assert(SIG_ERR != signal(SIGUSR1, SIG_IGN));
  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
  main_tid = sys_gettid();
  test_assert(0 == pipe(pipe_fds));
  epfd = epoll_create1(0);
  test_assert(epfd >= 0);
  ev.events = EPOLLIN;
  ev.data.fd = pipe_fds[0];
  test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &ev));
  semid = semget(IPC_PRIVATE, 1, 0600);
  test_assert(semid >= 0);

  for (c = 0; c < NUM_CASES; ++c) {
    run_case(c);
  }
  run_process_case();
  run_traced_case();

  test_assert(0 == semctl(semid, 0, IPC_RMID));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
