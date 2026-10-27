/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* SIGCHLD is blocked. A thread blocked in waitid() for a child or tracee
   must return when that child or tracee stops (Linux wakes up the threads
   that wait for a child of the process), whatever stops' SIGCHLDs are
   pending and whatever other threads wait for. It must not return the
   stop of a child or tracee of another thread if it waits with
   __WNOTHREAD, nor that of a clone child if it waits without __WCLONE,
   nor the ptrace stop of its own child that another thread traces if it
   waits with __WNOTHREAD (Linux doesn't wake it up for that stop). Each
   thread that blocks in waitid() is asleep in it before the child or
   tracee stops. */

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

/* A child that raises SIGUSR1 each time we write 's' to the pipe, and
   exits with 77 when we write 'x'. */
static pid_t fork_signaling_child(void) {
  char ch;
  pid_t child = fork();
  if (!child) {
    while (1) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      if (ch != 's') {
        exit(77);
      }
      raise(SIGUSR1);
    }
  }
  test_assert(child > 0);
  return child;
}

enum own_children { NO_CHILD, OWN_CHILD, TRACED_AND_OWN_CHILD };

struct waiter {
  pthread_t thread;
  pid_t tid;
  enum own_children own_children;
  pid_t traced_child;
  pid_t forked_child;
  idtype_t idtype;
  pid_t id;
  int options;
  siginfo_t si;
  int returned;
};

static void* do_wait(void* p) {
  struct waiter* w = p;
  if (w->own_children == TRACED_AND_OWN_CHILD) {
    w->traced_child = fork_signaling_child();
  }
  if (w->own_children != NO_CHILD) {
    w->forked_child = fork_child();
  }
  __atomic_store_n(&w->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  memset(&w->si, 0, sizeof(w->si));
  test_assert(0 == waitid(w->idtype, w->id, &w->si, w->options));
  __atomic_store_n(&w->returned, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

/* Start a thread that blocks in waitid(), and wait until it's asleep in it.
   It forks a child of its own first if |own_children| says so, after
   another one for the main thread to seize with TRACED_AND_OWN_CHILD. */
static void start_waiter_with(struct waiter* w, idtype_t idtype, pid_t id,
                              int options, enum own_children own_children) {
  pid_t tid;

  w->tid = 0;
  w->own_children = own_children;
  w->traced_child = 0;
  w->forked_child = 0;
  w->idtype = idtype;
  w->id = id;
  w->options = options;
  w->returned = 0;
  test_assert(0 == pthread_create(&w->thread, NULL, do_wait, w));
  while (!(tid = __atomic_load_n(&w->tid, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  wait_for_task_asleep_in_syscall(tid, SYS_waitid, idtype);
}

static void start_waiter(struct waiter* w, idtype_t idtype, pid_t id,
                         int options) {
  start_waiter_with(w, idtype, id, options, NO_CHILD);
}

static void join_waiter(struct waiter* w, pid_t pid, int code, int status) {
  test_assert(0 == pthread_join(w->thread, NULL));
  test_assert(w->si.si_pid == pid);
  test_assert(w->si.si_code == code);
  test_assert(w->si.si_status == status);
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

static void kill_child(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* A seized tracee that reaches a signal-delivery-stop for SIGUSR1 each time
   we write 's' to the pipe, and exits with 77 when we write 'x'. */
static pid_t fork_tracee(void) {
  pid_t tracee = fork_signaling_child();
  test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
  return tracee;
}

static void stop_tracee(void) {
  test_assert(1 == write(pipe_fds[1], "s", 1));
}

static void wait_for_tracee_stop(pid_t tracee) {
  int status;
  test_assert(tracee == waitpid(tracee, &status, 0));
  test_assert(status == ((SIGUSR1 << 8) | 0x7f));
}

/* Resume the stopped tracee and have it exit. */
static void end_tracee(pid_t tracee) {
  int status;
  test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(tracee == waitpid(tracee, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static int sigchld_pending(void) {
  sigset_t pending;
  test_assert(0 == sigpending(&pending));
  return sigismember(&pending, SIGCHLD);
}

static void wait_for_pending_sigchld(void) {
  while (!sigchld_pending()) {
    sched_yield();
  }
}

static void drain_sigchld(void) {
  sigset_t set;
  struct timespec ts = { 0, 0 };
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  while (SIGCHLD == sigtimedwait(&set, NULL, &ts)) {
  }
}

/* Two threads wait for the stops of two children. We've already waited for
   the first child's stop, and its SIGCHLD stays pending. The second child
   stops, and the thread that waits for it must return. We fork the children
   in either order, and a tracee's SIGCHLD is pending too if |with_tracee|. */
static void stop_of_second_child(int fork_second_first, int with_tracee) {
  pid_t tracee = 0;
  pid_t children[2];
  struct waiter w[2];
  siginfo_t si;

  if (with_tracee) {
    tracee = fork_tracee();
    stop_tracee();
    wait_for_pending_sigchld();
  }
  if (fork_second_first) {
    children[1] = fork_child();
    children[0] = fork_child();
  } else {
    children[0] = fork_child();
    children[1] = fork_child();
  }
  test_assert(0 == kill(children[0], SIGSTOP));
  test_assert(0 == waitid(P_PID, children[0], &si, WSTOPPED));
  test_assert(si.si_pid == children[0] && si.si_code == CLD_STOPPED);
  start_waiter(&w[0], P_PID, children[0], WSTOPPED | WEXITED);
  start_waiter(&w[1], P_PID, children[1], WSTOPPED);
  test_assert(0 == kill(children[1], SIGSTOP));
  join_waiter(&w[1], children[1], CLD_STOPPED, SIGSTOP);
  test_assert(0 == kill(children[0], SIGKILL));
  join_waiter(&w[0], children[0], CLD_KILLED, SIGKILL);
  kill_child(children[1]);
  if (with_tracee) {
    wait_for_tracee_stop(tracee);
    end_tracee(tracee);
  }
  drain_sigchld();
}

/* One thread waits for any child's exit, and another one for a child's
   stop, started in either order. The child stops, and the second thread
   must return. */
static void stop_while_another_thread_waits_for_exits(int stop_waiter_first) {
  pid_t child = fork_child();
  struct waiter exit_waiter;
  struct waiter stop_waiter;

  if (stop_waiter_first) {
    start_waiter(&stop_waiter, P_PID, child, WSTOPPED);
    start_waiter(&exit_waiter, P_ALL, 0, WEXITED);
  } else {
    start_waiter(&exit_waiter, P_ALL, 0, WEXITED);
    start_waiter(&stop_waiter, P_PID, child, WSTOPPED);
  }
  test_assert(0 == kill(child, SIGSTOP));
  join_waiter(&stop_waiter, child, CLD_STOPPED, SIGSTOP);
  test_assert(0 == kill(child, SIGKILL));
  join_waiter(&exit_waiter, child, CLD_KILLED, SIGKILL);
  drain_sigchld();
}

static void* fork_child_main(void* p) {
  *(pid_t*)p = fork_child();
  return NULL;
}

enum stopping_child {
  MAIN_THREAD_CHILD,
  MAIN_THREAD_TRACEE,
  CHILD_OF_EXITED_THREAD,
  CLONE_CHILD,
  OWN_CHILD_TRACED_BY_MAIN_THREAD
};

/* A thread forks a child and waits for its own children with __WNOTHREAD
   (for the clone child, for any child, without __WCLONE). A child or tracee
   of the main thread stops, or a child that a thread forked before it
   exited (Linux then makes the main thread its parent), or a clone child of
   the main thread, or a child that the waiting thread forked before and
   that the main thread seized. The waiting thread must not return that
   stop, and we poll for it. Under rr, the race it tests only happens in
   some recordings. */
static void waiter_ignores_stop(enum stopping_child kind) {
  pid_t pid = 0;
  pthread_t thread;
  struct waiter w;
  siginfo_t si;
  struct timespec ts = { 0, 10000000 };
  int options = WSTOPPED | WEXITED | __WNOTHREAD;
  int poll_options = WSTOPPED | WNOHANG;
  int tracee = kind == MAIN_THREAD_TRACEE ||
               kind == OWN_CHILD_TRACED_BY_MAIN_THREAD;

  switch (kind) {
    case MAIN_THREAD_CHILD:
      pid = fork_child();
      break;
    case MAIN_THREAD_TRACEE:
      pid = fork_tracee();
      break;
    case CHILD_OF_EXITED_THREAD:
      test_assert(0 == pthread_create(&thread, NULL, fork_child_main, &pid));
      test_assert(0 == pthread_join(thread, NULL));
      break;
    case CLONE_CHILD:
      pid = fork_clone_child();
      options = WSTOPPED | WEXITED;
      poll_options |= __WCLONE;
      break;
    case OWN_CHILD_TRACED_BY_MAIN_THREAD:
      break;
  }
  start_waiter_with(&w, P_ALL, 0, options,
                    kind == OWN_CHILD_TRACED_BY_MAIN_THREAD
                        ? TRACED_AND_OWN_CHILD
                        : OWN_CHILD);
  if (kind == OWN_CHILD_TRACED_BY_MAIN_THREAD) {
    pid = w.traced_child;
    test_assert(0 == ptrace(PTRACE_SEIZE, pid, NULL, NULL));
  }
  if (tracee) {
    stop_tracee();
  } else {
    test_assert(pid > 1);
    test_assert(0 == kill(pid, SIGSTOP));
  }
  while (1) {
    test_assert(!__atomic_load_n(&w.returned, __ATOMIC_SEQ_CST));
    memset(&si, 0, sizeof(si));
    test_assert(0 == waitid(P_PID, pid, &si, poll_options));
    if (si.si_pid == pid) {
      break;
    }
    nanosleep(&ts, NULL);
  }
  if (tracee) {
    test_assert(si.si_code == CLD_TRAPPED && si.si_status == SIGUSR1);
  } else {
    test_assert(si.si_code == CLD_STOPPED && si.si_status == SIGSTOP);
  }
  test_assert(w.forked_child > 1);
  test_assert(0 == kill(w.forked_child, SIGKILL));
  join_waiter(&w, w.forked_child, CLD_KILLED, SIGKILL);
  if (tracee) {
    end_tracee(pid);
  } else {
    kill_child(pid);
  }
  drain_sigchld();
}

int main(void) {
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  test_assert(0 == pipe(pipe_fds));

  stop_of_second_child(0, 0);
  stop_of_second_child(1, 0);
  stop_of_second_child(0, 1);
  stop_of_second_child(1, 1);
  stop_while_another_thread_waits_for_exits(0);
  stop_while_another_thread_waits_for_exits(1);
  waiter_ignores_stop(MAIN_THREAD_CHILD);
  waiter_ignores_stop(MAIN_THREAD_TRACEE);
  waiter_ignores_stop(CHILD_OF_EXITED_THREAD);
  waiter_ignores_stop(CLONE_CHILD);
  waiter_ignores_stop(OWN_CHILD_TRACED_BY_MAIN_THREAD);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
