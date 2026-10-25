/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Killing a stopped child ends its job-control stop, so no wait reports
   that stop after the kill. We block SIGCHLD and:
   - stop a child, which may have a second thread. Once the SIGCHLD for the
     stop is pending, we kill the child with kill(), or with tgkill() of its
     second thread, without waiting for the stop. A WUNTRACED wait for the
     child reports its exit, another one then fails with ECHILD, and when we
     unblock SIGCHLD, our handler gets the SIGCHLD for the stop.
   - stop a child whose main thread has exited and take the SIGCHLD for the
     stop with sigwaitinfo(). A tgkill() of the exited main thread with
     SIGKILL kills nothing, so a WNOWAIT waitid() still reports the stop. We
     kill the child with kill(), and once a WNOWAIT waitid() has seen its
     exit, a WUNTRACED waitpid() reports the exit.
   - stop a child that another thread of ours forked with a parent death
     signal of SIGKILL, and have that thread exit, so that the kernel kills
     the child. Once /proc shows the SIGKILL pending for the child, a
     WUNTRACED waitpid() reports the exit. The race it tests only happens
     in some recordings.
   - stop a child that leads its own process group, and have another child
     join that group and kill it with kill(0, SIGKILL), which kills that
     child too. Once we have reaped that child, a WUNTRACED wait for the
     stopped child reports its exit. The race it tests only happens in some
     recordings.
   - stop a child, kill it with kill() and reap it with a wait without
     WUNTRACED. A WUNTRACED wait for any child then fails with ECHILD. */

static int ready_fds[2];
static int go_fds[2];
static volatile int handler_calls;
static siginfo_t handler_si;

static void handle_sigchld(__attribute__((unused)) int sig, siginfo_t* si,
                           __attribute__((unused)) void* context) {
  handler_si = *si;
  ++handler_calls;
}

static void set_sigchld_blocked(int how) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(0 == sigprocmask(how, &sigs, NULL));
}

static void wait_for_sigchld_pending(void) {
  sigset_t pending;
  do {
    sched_yield();
    test_assert(0 == sigpending(&pending));
  } while (!sigismember(&pending, SIGCHLD));
}

static void take_sigchld(void) {
  sigset_t sigs;
  siginfo_t si;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo(&sigs, &si));
}

static void write_tid(void) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(ready_fds[1], &tid, sizeof(tid)));
}

/* Returns true if SIGKILL is pending for the process |pid|, as
   /proc/<pid>/status shows it. */
static int is_SIGKILL_pending_for_process(pid_t pid) {
  char path[64];
  char buf[8192];
  char* p;
  unsigned long long mask;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/status", pid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strstr(buf, "\nShdPnd:");
  test_assert(p != NULL);
  test_assert(1 == sscanf(p + strlen("\nShdPnd:"), "%llx", &mask));
  return (mask >> (SIGKILL - 1)) & 1;
}

static void* child_thread_main(__attribute__((unused)) void* p) {
  write_tid();
  for (;;) {
    pause();
  }
  return NULL;
}

/* Forks a child, which leads its own process group if |own_group|. Returns
   the child's pid and sets *tid to the tid of its second thread, if it has
   one, or to the child's pid. */
static pid_t fork_child(int with_thread, int main_thread_exits, int own_group,
                        pid_t* tid) {
  pthread_t thread;
  pid_t child;

  child = fork();
  if (0 == child) {
    if (own_group) {
      test_assert(0 == setpgid(0, 0));
    }
    if (with_thread) {
      test_assert(0 == pthread_create(&thread, NULL, child_thread_main, NULL));
    } else {
      write_tid();
    }
    if (main_thread_exits) {
      pthread_exit(NULL);
    }
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(sizeof(*tid) == read(ready_fds[0], tid, sizeof(*tid)));
  test_assert(*tid > 1);
  test_assert(with_thread ? *tid != child : *tid == child);
  if (own_group) {
    test_assert(getpgid(child) == child);
  }
  if (main_thread_exits) {
    while (get_task_state(child) != 'Z') {
      sched_yield();
    }
  }
  return child;
}

static void kill_without_waiting_for_stop(int with_thread, int kill_thread) {
  pid_t child;
  pid_t tid;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  child = fork_child(with_thread, 0, 0, &tid);
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_sigchld_pending();
  if (kill_thread) {
    test_assert(0 == syscall(SYS_tgkill, child, tid, SIGKILL));
  } else {
    test_assert(0 == kill(child, SIGKILL));
  }
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(-1 == waitpid(child, &status, WUNTRACED | WNOHANG));
  test_assert(errno == ECHILD);

  handler_calls = 0;
  set_sigchld_blocked(SIG_UNBLOCK);
  test_assert(handler_calls == 1);
  test_assert(handler_si.si_code == CLD_STOPPED);
  test_assert(handler_si.si_pid == child);
  test_assert(handler_si.si_status == SIGSTOP);
}

static void kill_with_exited_main_thread(void) {
  siginfo_t si;
  pid_t child;
  pid_t tid;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  child = fork_child(1, 1, 0, &tid);
  test_assert(0 == kill(child, SIGSTOP));
  take_sigchld();
  test_assert(0 == syscall(SYS_tgkill, child, child, SIGKILL));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOHANG | WNOWAIT));
  test_assert(si.si_pid == child);
  test_assert(si.si_code == CLD_STOPPED);
  test_assert(si.si_status == SIGSTOP);
  test_assert(0 == kill(child, SIGKILL));
  test_assert(0 == waitid(P_PID, child, &si, WEXITED | WNOWAIT));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  take_sigchld();
  set_sigchld_blocked(SIG_UNBLOCK);
}

static void* parent_thread_main(__attribute__((unused)) void* p) {
  pid_t child;
  char ch;

  child = fork();
  if (0 == child) {
    test_assert(0 == prctl(PR_SET_PDEATHSIG, SIGKILL));
    write_tid();
    for (;;) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(1 == read(go_fds[0], &ch, 1));
  return NULL;
}

static void kill_by_parent_thread_exit(void) {
  pthread_t thread;
  pid_t child;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  test_assert(0 == pthread_create(&thread, NULL, parent_thread_main, NULL));
  test_assert(sizeof(child) == read(ready_fds[0], &child, sizeof(child)));
  test_assert(child > 1);
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_sigchld_pending();
  test_assert(1 == write(go_fds[1], "g", 1));
  test_assert(0 == pthread_join(thread, NULL));
  while (!is_SIGKILL_pending_for_process(child)) {
    sched_yield();
  }
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  take_sigchld();
  set_sigchld_blocked(SIG_UNBLOCK);
}

static void kill_by_group_member(void) {
  pid_t child;
  pid_t tid;
  pid_t killer;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  child = fork_child(1, 0, 1, &tid);
  test_assert(getpgid(0) != child);
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_sigchld_pending();
  killer = fork();
  if (0 == killer) {
    test_assert(child > 1);
    test_assert(0 == setpgid(0, child));
    test_assert(getpgid(0) == child);
    test_assert(getpgid(getppid()) != child);
    test_assert(0 == kill(0, SIGKILL));
    _exit(1);
  }
  test_assert(killer > 0);
  test_assert(killer == waitpid(killer, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  take_sigchld();
  set_sigchld_blocked(SIG_UNBLOCK);
}

static void reap_without_WUNTRACED(void) {
  pid_t child;
  pid_t tid;
  int status;

  set_sigchld_blocked(SIG_BLOCK);
  child = fork_child(1, 0, 0, &tid);
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_sigchld_pending();
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(-1 == waitpid(-1, &status, WUNTRACED | WNOHANG));
  test_assert(errno == ECHILD);
  take_sigchld();
  set_sigchld_blocked(SIG_UNBLOCK);
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigchld;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == pipe(ready_fds));
  test_assert(0 == pipe(go_fds));

  kill_without_waiting_for_stop(0, 0);
  kill_without_waiting_for_stop(1, 0);
  kill_without_waiting_for_stop(1, 1);
  kill_with_exited_main_thread();
  kill_by_parent_thread_exit();
  kill_by_group_member();
  reap_without_WUNTRACED();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
