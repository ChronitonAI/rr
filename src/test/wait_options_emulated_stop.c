/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child or tracee stops, and once a wait with WNOWAIT reports the stop,
   we poll for it with WNOHANG and options that must or must not report it.
   With __WNOTHREAD, a thread waits only for its own tracees and for the
   children it is the parent of: the thread that forked the child, or once
   that thread has exited, the main thread. When another thread traces a
   child's leader, the child's parent thread gets the leader's ptrace stops
   too. Without __WALL, a wait reports a child whose exit signal isn't
   SIGCHLD only with __WCLONE, and other children only without __WCLONE; a
   clone child that execs gets SIGCHLD as its exit signal. A wait for a
   child doesn't report the ptrace stop of a traced thread of the child.
   SIGCHLD is blocked. */

static int pipe_fds[2];

static pid_t fork_child(void) {
  pid_t child = fork();
  if (!child) {
    while (1) {
      pause();
    }
  }
  test_assert(child > 0);
  return child;
}

/* A child whose exit signal is 0 rather than SIGCHLD (a clone child). */
static pid_t fork_clone_child(void) {
  pid_t child = syscall(SYS_clone, 0, 0, 0, 0, 0);
  if (!child) {
    while (1) {
      pause();
    }
  }
  test_assert(child > 0);
  return child;
}

/* A child, or a clone child, that raises SIGUSR1 each time we write 's' to
   the pipe. */
static pid_t fork_signaling_child(int clone_child) {
  char ch;
  pid_t child = clone_child ? syscall(SYS_clone, 0, 0, 0, 0, 0) : fork();
  if (!child) {
    while (1) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      raise(SIGUSR1);
    }
  }
  test_assert(child > 0);
  return child;
}

static void kill_child(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void drain_sigchld(void) {
  sigset_t set;
  struct timespec ts = { 0, 0 };
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  while (SIGCHLD == sigtimedwait(&set, NULL, &ts)) {
  }
}

/* Wait until a wait for |pid| with |options| reports a stop. */
static void wait_for_stop(pid_t pid, int options) {
  siginfo_t si;
  while (1) {
    memset(&si, 0, sizeof(si));
    test_assert(0 == waitid(P_PID, pid, &si,
                            WSTOPPED | WNOHANG | WNOWAIT | options));
    if (si.si_pid) {
      return;
    }
    sched_yield();
  }
}

static void check_stopped(pid_t child, int options) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_ALL, 0, &si, WSTOPPED | WNOHANG | options));
  test_assert(si.si_pid == child);
  test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
}

static void check_no_child(idtype_t idtype, pid_t id, int options) {
  siginfo_t si;
  test_assert(-1 == waitid(idtype, id, &si, WSTOPPED | WNOHANG | options));
  test_assert(errno == ECHILD);
}

static void* check_no_own_child(__attribute__((unused)) void* p) {
  check_no_child(P_ALL, 0, __WNOTHREAD);
  return NULL;
}

static int thread_gone(pid_t tid) {
  char path[64];
  sprintf(path, "/proc/self/task/%d", tid);
  return access(path, F_OK) < 0 && errno == ENOENT;
}

static void* record_tid_and_fork_child(void* p) {
  pid_t* pids = p;
  pids[0] = sys_gettid();
  pids[1] = fork_child();
  return NULL;
}

/* The main thread's child stops, or a child that a thread forked before it
   exited (the main thread is then its parent). Another thread's
   __WNOTHREAD wait doesn't report the stop, and the main thread's does. */
static void wnothread_reports_own_children(int forker_exited) {
  pthread_t thread;
  pid_t child;

  if (forker_exited) {
    pid_t pids[2];
    test_assert(0 == pthread_create(&thread, NULL, record_tid_and_fork_child,
                                    pids));
    test_assert(0 == pthread_join(thread, NULL));
    while (!thread_gone(pids[0])) {
      sched_yield();
    }
    child = pids[1];
  } else {
    child = fork_child();
  }
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_stop(child, 0);
  test_assert(0 == pthread_create(&thread, NULL, check_no_own_child, NULL));
  test_assert(0 == pthread_join(thread, NULL));
  check_stopped(child, __WNOTHREAD);
  kill_child(child);
  drain_sigchld();
}

/* A clone child stops. A wait reports it with __WCLONE and not without. */
static void wclone_reports_clone_child(void) {
  pid_t child = fork_clone_child();

  test_assert(0 == kill(child, SIGSTOP));
  wait_for_stop(child, __WALL);
  check_no_child(P_ALL, 0, 0);
  check_stopped(child, __WCLONE);
  kill_child(child);
  drain_sigchld();
}

/* A clone child execs, and stops. A wait reports it without __WCLONE and
   not with it. */
static void wclone_after_exec(void) {
  char fd_str[16];
  char* argv[] = { "/proc/self/exe", "exec-pause", fd_str, NULL };
  int fds[2];
  pid_t child;
  char ch;

  test_assert(0 == pipe(fds));
  sprintf(fd_str, "%d", fds[1]);
  child = syscall(SYS_clone, 0, 0, 0, 0, 0);
  if (!child) {
    execve("/proc/self/exe", argv, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child > 0);
  test_assert(1 == read(fds[0], &ch, 1));
  test_assert(0 == kill(child, SIGSTOP));
  wait_for_stop(child, __WALL);
  check_no_child(P_PID, child, __WCLONE);
  check_stopped(child, 0);
  kill_child(child);
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));
  drain_sigchld();
}

struct parent_thread {
  pthread_t thread;
  int clone_child;
  pid_t child;
  int go;
  int wrong_ret;
  int wrong_errno;
  int right_ret;
  int right_status;
};

static void* parent_thread_main(void* p) {
  struct parent_thread* pt = p;
  int options = __WNOTHREAD | WNOHANG;
  int status;

  __atomic_store_n(&pt->child, fork_signaling_child(pt->clone_child),
                   __ATOMIC_SEQ_CST);
  while (!__atomic_load_n(&pt->go, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  pt->wrong_ret = waitpid(-1, &status,
                          options | (pt->clone_child ? 0 : __WCLONE));
  pt->wrong_errno = errno;
  pt->right_ret = waitpid(-1, &pt->right_status,
                          options | (pt->clone_child ? __WCLONE : 0));
  return NULL;
}

/* A thread forks a child, or a clone child, which the main thread seizes,
   and the child stops. The thread's __WNOTHREAD wait, without WUNTRACED,
   reports the child's ptrace stop with __WCLONE for the clone child and
   without __WCLONE for the other one, and otherwise fails with ECHILD. */
static void parent_thread_gets_ptrace_stop(int clone_child) {
  struct parent_thread pt;
  pid_t child;

  memset(&pt, 0, sizeof(pt));
  pt.clone_child = clone_child;
  test_assert(0 == pthread_create(&pt.thread, NULL, parent_thread_main, &pt));
  while (!(child = __atomic_load_n(&pt.child, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], "s", 1));
  wait_for_stop(child, __WALL);
  __atomic_store_n(&pt.go, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_join(pt.thread, NULL));
  test_assert(pt.wrong_ret == -1 && pt.wrong_errno == ECHILD);
  test_assert(pt.right_ret == child);
  test_assert(pt.right_status == ((SIGUSR1 << 8) | 0x7f));
  kill_child(child);
  drain_sigchld();
}

static void sigusr1_handler(__attribute__((unused)) int sig) {}

static void* signaling_thread_main(void* p) {
  int fd = *(int*)p;
  pid_t tid = sys_gettid();
  char ch;

  test_assert(sizeof(tid) == write(fd, &tid, sizeof(tid)));
  while (1) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR1));
  }
  return NULL;
}

/* We seize a thread of a child other than its leader, and it stops. A wait
   for the child doesn't report that ptrace stop, and a wait for the thread
   does. */
static void traced_thread_of_child(void) {
  int fds[2];
  pid_t child;
  pid_t tid;
  int status;

  test_assert(0 == pipe(fds));
  child = fork();
  if (!child) {
    pthread_t thread;
    signal(SIGUSR1, sigusr1_handler);
    test_assert(0 == pthread_create(&thread, NULL, signaling_thread_main,
                                    &fds[1]));
    while (1) {
      pause();
    }
  }
  test_assert(child > 0);
  test_assert(sizeof(tid) == read(fds[0], &tid, sizeof(tid)));
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], "s", 1));
  wait_for_stop(tid, __WALL);
  test_assert(0 == waitpid(child, &status, WUNTRACED | WNOHANG));
  test_assert(tid == waitpid(tid, &status, __WALL | WNOHANG));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  test_assert(0 == kill(child, SIGKILL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));
  drain_sigchld();
}

int main(int argc, char** argv) {
  sigset_t mask;

  if (argc > 2 && !strcmp(argv[1], "exec-pause")) {
    test_assert(1 == write(atoi(argv[2]), "e", 1));
    while (1) {
      pause();
    }
  }

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  test_assert(0 == pipe(pipe_fds));

  wnothread_reports_own_children(0);
  wnothread_reports_own_children(1);
  wclone_reports_clone_child();
  wclone_after_exec();
  parent_thread_gets_ptrace_stop(0);
  parent_thread_gets_ptrace_stop(1);
  traced_thread_of_child();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
