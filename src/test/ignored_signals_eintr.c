/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Our main thread waits, without a timeout, in a syscall that fails with
   EINTR rather than being restarted when a signal wakes it up:
   rt_sigtimedwait (and rt_sigtimedwait_time64 on 32-bit x86), epoll_wait
   (on x86; elsewhere glibc's epoll_wait() makes epoll_pwait), epoll_pwait,
   epoll_pwait2, semop (ipc SEMOP on 32-bit x86) or semtimedop (ipc
   SEMTIMEDOP, and semtimedop_time64, on 32-bit x86). Another thread
   sends it signals that it ignores (SIGUSR1, whose handler is SIG_IGN, and
   SIGWINCH, whose handler is SIG_DFL), each once the main thread is asleep
   in its syscall, and then gives it what it waits for. Linux discards the
   ignored signals, so they don't wake up the main thread, and its syscall
   must succeed. Then a single-threaded child waits in sigwaitinfo(), and we
   send the same signals to its process.

   Linux also discards a signal whose handler is SIG_DFL, other than SIGKILL
   and SIGSTOP, when it's sent to a pid namespace's init. So if we may make
   a pid namespace, its init waits in sigwaitinfo(), we send it SIGTERM, and
   its sigwaitinfo() must succeed.

   Linux queues a signal that a process ignores if the thread that kill()
   names blocks it, and wakes up a thread that doesn't block it. So when a
   child's main thread waits in sigwaitinfo() while its other thread blocks
   SIGWINCH, and we send SIGWINCH with kill() naming the other thread, the
   main thread's sigwaitinfo() must fail with EINTR.

   Linux queues a signal that a process ignores if the process is traced
   when it's sent, even if its ptracer then leaves. So a child's
   sigwaitinfo() must fail with EINTR when
   - we seize the child and send it SIGUSR1;
   - a sibling of the child seizes it, sends it SIGWINCH and exits;
   - the child makes us its ptracer, and we send it SIGWINCH at its
     syscall-entry stop for sigwaitinfo() and detach;
   - we seize the child, send it SIGWINCH, stop it with PTRACE_INTERRUPT
     and detach.
   The races that the second and the last of these test only happen in some
   recordings: rr deals with the end of the child's wait only after its
   ptracer has left.

   SIGSTOP wakes up a thread even if a SIGCONT discards it before the
   thread stops. So a child's sigwaitinfo() must fail with EINTR when we
   send it SIGSTOP and at once SIGCONT, while it ignores SIGCONT and while
   it blocks SIGCONT. The race it tests only happens in some recordings: rr
   deals with the end of the child's wait only after the SIGCONT has
   discarded the SIGSTOP, when the SIGCONT that the child ignores is the
   only signal pending that it doesn't block, or none is.

   Finally, a child's main thread, which blocks SIGCONT, waits in
   epoll_wait(). The child's other thread sends the main thread SIGWINCH and
   then, once the main thread is asleep again, stops the process. While the
   child is stopped, we send its main thread SIGWINCH too, and then continue
   the child. The stop wakes up the main thread, so its epoll_wait() must
   fail with EINTR. The race it tests only happens in some recordings: rr
   deals with the end of the wait only after the stop has ended, when that
   SIGWINCH is the only signal pending for the main thread that it doesn't
   block. */

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
static int waiting;
static int pipe_fds[2];
static int epfd;
static int semid;

/* Wait until the main thread is asleep. Once it has set |waiting|, it
   sleeps only in the syscall that it waits in. */
static void wait_until_main_thread_asleep(void) {
  while (!__atomic_load_n(&waiting, __ATOMIC_SEQ_CST) ||
         get_task_state(main_tid) != 'S') {
    sched_yield();
  }
}

static void* sender(void* p) {
  int c = (int)(uintptr_t)p;
  static const int ignored_sigs[] = { SIGUSR1, SIGWINCH };
  size_t i;
  char ch = 'x';
  struct sembuf up = { 0, 1, 0 };

  test_assert(main_tid > 1);
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
  return task_asleep_in_syscall(pid, RR_rt_sigtimedwait_time64, -1) ||
         task_asleep_in_syscall(pid, SYS_rt_sigtimedwait, -1);
}

/* Wait until |child| is asleep in sigwaitinfo(). */
static void wait_until_child_asleep(pid_t child) {
  while (!asleep_in_sigwaitinfo(child)) {
    /* If it has exited, its sigwaitinfo() failed. */
    test_assert(get_task_state(child) != 'Z');
    sched_yield();
  }
}

static void run_process_case(void) {
  static const int sigs[] = { SIGUSR1, SIGWINCH, SIGUSR2 };
  size_t i;
  pid_t child;
  int status;

  child = fork();
  test_assert(child >= 0);
  if (0 == child) {
    sigset_t set;
    siginfo_t si;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    test_assert(SIGUSR2 == sigwaitinfo(&set, &si));
    exit(77);
  }
  for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); ++i) {
    wait_until_child_asleep(child);
    test_assert(0 == kill(child, sigs[i]));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Fork a child that makes a pid namespace, if it may, and forks the
   namespace's init, which waits in sigwaitinfo(). The child sends the init
   SIGTERM, whose handler is SIG_DFL, and then SIGUSR2. */
static void run_namespace_init_case(void) {
  pid_t child = fork();
  int status;

  test_assert(child >= 0);
  if (0 == child) {
    pid_t init;
    if (unshare(CLONE_NEWPID) < 0) {
      /* We may not have permission to make a pid namespace. */
      test_assert(errno == EPERM || errno == EINVAL);
      exit(77);
    }
    init = fork();
    test_assert(init >= 0);
    if (0 == init) {
      sigset_t set;
      siginfo_t si;
      sigemptyset(&set);
      sigaddset(&set, SIGUSR2);
      exit(SIGUSR2 == sigwaitinfo(&set, &si) ? 77 : 1);
    }
    wait_until_child_asleep(init);
    test_assert(0 == kill(init, SIGTERM));
    wait_until_child_asleep(init);
    test_assert(0 == kill(init, SIGUSR2));
    test_assert(init == waitpid(init, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Wait in sigwaitinfo() for SIGUSR2 and exit, with 77 if that fails with
   EINTR. */
static void wait_expecting_eintr(void) {
  sigset_t set;
  siginfo_t si;
  int ret;

  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  ret = sigwaitinfo(&set, &si);
  exit(ret < 0 && errno == EINTR ? 77 : 1);
}

/* Fork a child that runs wait_expecting_eintr(). If |traceme|, it makes us
   its ptracer and stops first. */
static pid_t fork_child_expecting_eintr(int traceme) {
  pid_t child = fork();
  test_assert(child >= 0);
  if (0 == child) {
    /* So that a sibling can trace us, under Yama. This fails without Yama. */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    if (traceme) {
      test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
      test_assert(0 == kill(getpid(), SIGSTOP));
    }
    wait_expecting_eintr();
  }
  return child;
}

/* Wait for |child|, which has no ptracer and whose sigwaitinfo() a signal
   has woken up, to exit. If it's asleep in sigwaitinfo() again, its
   sigwaitinfo() was restarted: end it. */
static void wait_for_child_expecting_eintr(pid_t child) {
  int status;
  pid_t ret;

  while (0 == (ret = waitpid(child, &status, WNOHANG))) {
    if (asleep_in_sigwaitinfo(child)) {
      test_assert(0 == kill(child, SIGUSR2));
      ret = waitpid(child, &status, 0);
      break;
    }
    sched_yield();
  }
  test_assert(child == ret);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Block SIGWINCH, write our tid to the fd |p| and sleep. */
static void* sigwinch_blocker(void* p) {
  int fd = (int)(uintptr_t)p;
  pid_t tid = sys_gettid();
  sigset_t set;

  sigemptyset(&set);
  sigaddset(&set, SIGWINCH);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &set, NULL));
  test_assert((ssize_t)sizeof(tid) == write(fd, &tid, sizeof(tid)));
  while (1) {
    pause();
  }
  return NULL;
}

static void run_kill_blocking_thread_case(void) {
  int fds[2];
  pid_t child;
  pid_t tid;

  test_assert(0 == pipe(fds));
  child = fork();
  test_assert(child >= 0);
  if (0 == child) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, sigwinch_blocker,
                                    (void*)(uintptr_t)fds[1]));
    wait_expecting_eintr();
  }
  test_assert((ssize_t)sizeof(tid) == read(fds[0], &tid, sizeof(tid)));
  test_assert(tid > 1);
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));
  wait_until_child_asleep(child);
  /* This sends SIGWINCH to the child's process. Linux queues it, since the
     thread that kill() names blocks it, and wakes up the main thread. */
  test_assert(0 == kill(tid, SIGWINCH));
  wait_for_child_expecting_eintr(child);
}

static void run_traced_case(void) {
  pid_t child = fork_child_expecting_eintr(0);
  int status;

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_until_child_asleep(child);
  test_assert(0 == kill(child, SIGUSR1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGUSR1));
  /* If the child's sigwaitinfo() was restarted, this ends it. */
  test_assert(0 == kill(child, SIGUSR2));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void run_tracer_exit_case(void) {
  pid_t child = fork_child_expecting_eintr(0);
  pid_t tracer;
  int status;

  wait_until_child_asleep(child);
  tracer = fork();
  test_assert(tracer >= 0);
  if (0 == tracer) {
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
    test_assert(0 == syscall(SYS_tgkill, child, child, SIGWINCH));
    _exit(0);
  }
  test_assert(tracer == waitpid(tracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  wait_for_child_expecting_eintr(child);
}

static void run_entry_stop_detach_case(void) {
  pid_t child = fork_child_expecting_eintr(1);
  int status;

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, NULL,
                          (void*)PTRACE_O_TRACESYSGOOD));
  /* The child's next syscall is sigwaitinfo()'s. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGWINCH));
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
  wait_for_child_expecting_eintr(child);
}

static void run_interrupt_detach_case(void) {
  pid_t child = fork_child_expecting_eintr(0);
  int status;

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_until_child_asleep(child);
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGWINCH));
  /* Wait until the child has left its syscall and is in a ptrace stop. */
  while (get_task_state(child) != 't') {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status));
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
  wait_for_child_expecting_eintr(child);
}

/* Fork a child that runs wait_expecting_eintr() while it blocks SIGCONT, if
   |block_sigcont|, or ignores it. Once it's asleep, send it SIGSTOP and
   SIGCONT. */
static void run_stop_continue_case(int block_sigcont) {
  pid_t child = fork();

  test_assert(child >= 0);
  if (0 == child) {
    if (block_sigcont) {
      sigset_t set;
      sigemptyset(&set);
      sigaddset(&set, SIGCONT);
      test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
    } else {
      test_assert(SIG_ERR != signal(SIGCONT, SIG_IGN));
    }
    wait_expecting_eintr();
  }
  wait_until_child_asleep(child);
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(0 == kill(child, SIGCONT));
  wait_for_child_expecting_eintr(child);
}

static void* stopper(__attribute__((unused)) void* p) {
  char ch = 'x';

  test_assert(main_tid > 1);
  wait_until_main_thread_asleep();
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGWINCH));
  /* The main thread is asleep only while no signal that it doesn't block is
     pending for it. So once it's asleep again, only the stop wakes it up. */
  wait_until_main_thread_asleep();
  test_assert(0 == kill(getpid(), SIGSTOP));
  /* If the main thread is asleep again, its epoll_wait() was restarted: end
     it. */
  while (__atomic_load_n(&waiting, __ATOMIC_SEQ_CST)) {
    if (get_task_state(main_tid) == 'S') {
      test_assert(1 == write(pipe_fds[1], &ch, 1));
      break;
    }
    sched_yield();
  }
  return NULL;
}

static void run_group_stop_case(void) {
  pid_t child;
  siginfo_t si;
  int status;

  child = fork();
  test_assert(child >= 0);
  if (0 == child) {
    pthread_t thread;
    struct epoll_event ev;
    sigset_t set;
    int ret;
    main_tid = sys_gettid();
    __atomic_store_n(&waiting, 0, __ATOMIC_SEQ_CST);
    test_assert(0 == pthread_create(&thread, NULL, stopper, NULL));
    /* Block SIGCONT, so that the SIGCONT that continues the process isn't
       pending for the main thread. */
    sigemptyset(&set);
    sigaddset(&set, SIGCONT);
    test_assert(0 == pthread_sigmask(SIG_BLOCK, &set, NULL));
    __atomic_store_n(&waiting, 1, __ATOMIC_SEQ_CST);
    ret = epoll_wait(epfd, &ev, 1, -1);
    __atomic_store_n(&waiting, 0, __ATOMIC_SEQ_CST);
    test_assert(ret < 0 && errno == EINTR);
    exit(77);
  }
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WEXITED));
  test_assert(si.si_pid == child && si.si_code == CLD_STOPPED &&
              si.si_status == SIGSTOP);
  /* The stop has woken up the main thread, so its epoll_wait() fails with
     EINTR whether or not a signal that it ignores is pending. */
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGWINCH));
  test_assert(0 == kill(child, SIGCONT));
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

  __atomic_store_n(&waiting, 0, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, sender, (void*)(uintptr_t)c));
  __atomic_store_n(&waiting, 1, __ATOMIC_SEQ_CST);
  switch (c) {
    case SIGWAITINFO:
      sigemptyset(&set);
      sigaddset(&set, SIGUSR2);
      test_assert(SIGUSR2 == sigwaitinfo(&set, &si));
      break;
    case RT_SIGTIMEDWAIT_TIME64:
      sigemptyset(&set);
      sigaddset(&set, SIGUSR2);
      if (RR_rt_sigtimedwait_time64 >= 0) {
        ret = syscall(RR_rt_sigtimedwait_time64, &set, &si, NULL, 8);
      }
      if (RR_rt_sigtimedwait_time64 < 0 || (ret < 0 && errno == ENOSYS)) {
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
      ret = syscall(RR_epoll_pwait2, epfd, &ev, 1, NULL, NULL, 0);
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
      if (RR_semtimedop_time64 >= 0) {
        ret = syscall(RR_semtimedop_time64, semid, &down, 1, NULL);
      }
      if (RR_semtimedop_time64 < 0 || (ret < 0 && errno == ENOSYS)) {
        /* Not 32-bit x86, or Linux < 5.1 */
        ret = semtimedop(semid, &down, 1, NULL);
      }
      test_assert(0 == ret);
      break;
  }
  __atomic_store_n(&waiting, 0, __ATOMIC_SEQ_CST);
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
  run_namespace_init_case();
  run_kill_blocking_thread_case();
  run_traced_case();
  run_tracer_exit_case();
  run_entry_stop_detach_case();
  run_interrupt_detach_case();
  run_stop_continue_case(0);
  run_stop_continue_case(1);
  run_group_stop_case();

  test_assert(0 == semctl(semid, 0, IPC_RMID));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
