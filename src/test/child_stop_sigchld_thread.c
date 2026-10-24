/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Linux queues the SIGCHLD for a child's or tracee's stop for the process
   and tries the child's parent thread, or the ptracer thread, first: that
   thread takes it if it doesn't block SIGCHLD, and otherwise another thread
   that doesn't, or it stays pending for the process, even when another
   thread waited for the stop. SIGCHLD is blocked, except where a part says
   otherwise. Each thread that blocks in a syscall is asleep in it before the
   child or tracee stops. */

static int pipe_fds[2];
static pid_t main_tid;

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

struct waiter {
  pthread_t thread;
  pid_t tid;
  int unblock_sigchld;
  pid_t id;
  siginfo_t si;
};

static void* do_wait(void* p) {
  struct waiter* w = p;
  if (w->unblock_sigchld) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &mask, NULL));
  }
  __atomic_store_n(&w->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  memset(&w->si, 0, sizeof(w->si));
  test_assert(0 == waitid(P_PID, w->id, &w->si, WSTOPPED));
  return NULL;
}

/* Start a thread that blocks in waitid() for |id|'s stop, and wait until
   it's asleep in it. */
static void start_waiter(struct waiter* w, pid_t id, int unblock_sigchld) {
  pid_t tid;

  w->tid = 0;
  w->unblock_sigchld = unblock_sigchld;
  w->id = id;
  test_assert(0 == pthread_create(&w->thread, NULL, do_wait, w));
  while (!(tid = __atomic_load_n(&w->tid, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  wait_for_task_asleep_in_syscall(tid, SYS_waitid, P_PID);
}

static void join_waiter(struct waiter* w, pid_t pid, int code, int status) {
  test_assert(0 == pthread_join(w->thread, NULL));
  test_assert(w->si.si_pid == pid);
  test_assert(w->si.si_code == code);
  test_assert(w->si.si_status == status);
}

static void kill_child(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* A seized tracee that reaches a signal-delivery-stop for SIGUSR1 each time
   we write 's' to the pipe, and exits with 77 when we write 'x'. */
static pid_t fork_tracee(void) {
  char ch;
  pid_t tracee = fork();
  if (!tracee) {
    while (1) {
      test_assert(1 == read(pipe_fds[0], &ch, 1));
      if (ch != 's') {
        exit(77);
      }
      raise(SIGUSR1);
    }
  }
  test_assert(tracee > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
  return tracee;
}

static void stop_tracee(void) {
  test_assert(1 == write(pipe_fds[1], "s", 1));
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

static void take_sigchld(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  test_assert(SIGCHLD == sigwaitinfo(&set, NULL));
}

static void drain_sigchld(void) {
  sigset_t set;
  struct timespec ts = { 0, 0 };
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  while (SIGCHLD == sigtimedwait(&set, NULL, &ts)) {
  }
}

/* A thread waits for a tracee's stop, and the tracee stops. The SIGCHLD for
   that stays pending after that thread has exited. Then another thread
   waits for the tracee's stop while we take the SIGCHLD with sigwaitinfo().
 */
static void tracee_sigchld_pending_for_process(void) {
  pid_t tracee = fork_tracee();
  struct waiter w;

  start_waiter(&w, tracee, 0);
  stop_tracee();
  join_waiter(&w, tracee, CLD_TRAPPED, SIGUSR1);
  test_assert(sigchld_pending());
  take_sigchld();

  test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
  start_waiter(&w, tracee, 0);
  stop_tracee();
  take_sigchld();
  join_waiter(&w, tracee, CLD_TRAPPED, SIGUSR1);
  end_tracee(tracee);
  drain_sigchld();
}

static volatile int handler_ran;

static void handler(__attribute__((unused)) int sig) { handler_ran = 1; }

/* A thread waits for a child's stop, with SIGCHLD unblocked, unlike every
   other thread, and a handler without SA_RESTART. The child stops: the
   SIGCHLD goes to that thread, and its waitid() returns the stop. */
static void stop_while_waiter_takes_sigchld(void) {
  pid_t child = fork_child();
  struct waiter w;
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  handler_ran = 0;
  start_waiter(&w, child, 1);
  test_assert(0 == kill(child, SIGSTOP));
  join_waiter(&w, child, CLD_STOPPED, SIGSTOP);
  test_assert(handler_ran);
  sa.sa_handler = SIG_DFL;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  kill_child(child);
  drain_sigchld();
}

static pid_t handler_tid;
static int handler_count;

static void record_handler_tid(__attribute__((unused)) int sig) {
  if (!__atomic_load_n(&handler_tid, __ATOMIC_SEQ_CST)) {
    __atomic_store_n(&handler_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  }
  __atomic_add_fetch(&handler_count, 1, __ATOMIC_SEQ_CST);
}

struct parent_thread {
  pthread_t thread;
  int tracee;
  int waits;
  pid_t tid;
  pid_t child;
  siginfo_t si;
  int returned;
  int wake_fds[2];
  int done_fds[2];
  int go_fds[2];
};

/* Fork a tracee, or a child, and with SIGCHLD unblocked, wait for its stop,
   or first sleep in read() until woken. When told to, end the tracee or
   child. */
static void* parent_thread_main(void* p) {
  struct parent_thread* pt = p;
  sigset_t mask;
  char ch;

  pt->child = pt->tracee ? fork_tracee() : fork_child();
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &mask, NULL));
  __atomic_store_n(&pt->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  if (!pt->waits) {
    test_assert(1 == read(pt->wake_fds[0], &ch, 1));
  }
  memset(&pt->si, 0, sizeof(pt->si));
  test_assert(0 == waitid(P_PID, pt->child, &pt->si, WSTOPPED));
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));
  __atomic_store_n(&pt->returned, 1, __ATOMIC_SEQ_CST);
  test_assert(1 == write(pt->done_fds[1], "d", 1));
  test_assert(1 == read(pt->go_fds[0], &ch, 1));
  if (pt->tracee) {
    end_tracee(pt->child);
  } else {
    kill_child(pt->child);
  }
  return NULL;
}

static void stop_tracee_or_child(struct parent_thread* pt) {
  if (pt->tracee) {
    stop_tracee();
  } else {
    test_assert(pt->child > 1);
    test_assert(0 == kill(pt->child, SIGSTOP));
  }
}

/* Once the main thread and the parent thread are asleep in read(), stop the
   tracee, or child, and once a handler has taken the SIGCHLD, wake up the
   parent thread. */
static void* stopper_main(void* p) {
  struct parent_thread* pt = p;
  wait_for_task_asleep_in_syscall(main_tid, SYS_read, pt->done_fds[0]);
  wait_for_task_asleep_in_syscall(__atomic_load_n(&pt->tid, __ATOMIC_SEQ_CST),
                                  SYS_read, pt->wake_fds[0]);
  stop_tracee_or_child(pt);
  while (!__atomic_load_n(&handler_tid, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(1 == write(pt->wake_fds[1], "w", 1));
  return NULL;
}

/* A thread forks a tracee, or a child, with SIGCHLD unblocked and a handler,
   as in the main thread. The tracee or child stops while that thread sleeps
   in read() and the main thread too, or while that thread waits for the stop
   and the main thread calls sched_yield() in a loop. Linux tries to deliver
   the SIGCHLD to the ptracer thread, or the thread that forked the child,
   first (do_notify_parent_cldstop()), so that thread takes it. When that
   thread waits, the race it tests only happens in some recordings. */
static void sigchld_goes_to_parent_thread(int tracee, int waits) {
  struct parent_thread pt;
  pid_t tid;
  pthread_t stopper;
  struct sigaction sa;
  sigset_t mask;
  char ch;

  memset(&pt, 0, sizeof(pt));
  pt.tracee = tracee;
  pt.waits = waits;
  test_assert(0 == pipe(pt.wake_fds));
  test_assert(0 == pipe(pt.done_fds));
  test_assert(0 == pipe(pt.go_fds));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = record_handler_tid;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  handler_tid = 0;
  test_assert(0 == pthread_create(&pt.thread, NULL, parent_thread_main, &pt));
  while (!(tid = __atomic_load_n(&pt.tid, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (waits) {
    wait_for_task_asleep_in_syscall(tid, SYS_waitid, P_PID);
    test_assert(0 == sigprocmask(SIG_UNBLOCK, &mask, NULL));
    stop_tracee_or_child(&pt);
    while (!__atomic_load_n(&pt.returned, __ATOMIC_SEQ_CST)) {
      sched_yield();
    }
  } else {
    test_assert(0 == pthread_create(&stopper, NULL, stopper_main, &pt));
    test_assert(0 == sigprocmask(SIG_UNBLOCK, &mask, NULL));
    test_assert(1 == read(pt.done_fds[0], &ch, 1));
  }
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  if (!waits) {
    test_assert(0 == pthread_join(stopper, NULL));
  }
  test_assert(__atomic_load_n(&handler_tid, __ATOMIC_SEQ_CST) == tid);
  test_assert(pt.si.si_pid == pt.child);
  if (tracee) {
    test_assert(pt.si.si_code == CLD_TRAPPED && pt.si.si_status == SIGUSR1);
  } else {
    test_assert(pt.si.si_code == CLD_STOPPED && pt.si.si_status == SIGSTOP);
  }
  test_assert(1 == write(pt.go_fds[1], "g", 1));
  test_assert(0 == pthread_join(pt.thread, NULL));
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = 0;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == close(pt.wake_fds[0]));
  test_assert(0 == close(pt.wake_fds[1]));
  test_assert(0 == close(pt.done_fds[0]));
  test_assert(0 == close(pt.done_fds[1]));
  test_assert(0 == close(pt.go_fds[0]));
  test_assert(0 == close(pt.go_fds[1]));
  drain_sigchld();
}

static void sigusr1_handler(__attribute__((unused)) int sig) {}

struct sleeper {
  pthread_t thread;
  pid_t tid;
  pid_t child;
  int fds[2];
};

/* Fork a child, unblock SIGCHLD and sleep in sigsuspend() with SIGCHLD
   blocked until a SIGUSR1 arrives. */
static void* suspender_main(void* p) {
  struct sleeper* s = p;
  sigset_t mask;

  s->child = fork_child();
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &mask, NULL));
  __atomic_store_n(&s->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(-1 == sigsuspend(&mask) && errno == EINTR);
  return NULL;
}

/* Unblock SIGCHLD, stop the child once the main thread is asleep in
   waitid() for it, and sleep in read(). */
static void* stopper_reader_main(void* p) {
  struct sleeper* s = p;
  sigset_t mask;
  char ch;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &mask, NULL));
  __atomic_store_n(&s->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  wait_for_task_asleep_in_syscall(main_tid, SYS_waitid, P_PID);
  test_assert(s->child > 1);
  test_assert(0 == kill(s->child, SIGSTOP));
  test_assert(1 == read(s->fds[0], &ch, 1));
  return NULL;
}

/* A thread forks a child and sleeps in sigsuspend() with a mask that blocks
   SIGCHLD, unlike its own mask. Another thread, with SIGCHLD unblocked and
   a handler, stops the child once the main thread is asleep in
   waitid(WNOWAIT) for it, and then sleeps in read(). Linux tries the thread
   that forked the child first, which blocks SIGCHLD, so the other thread
   takes the SIGCHLD, the only one there is. */
static void sigchld_skips_thread_that_blocks_it(void) {
  struct sleeper suspender;
  struct sleeper reader;
  pid_t suspender_tid;
  pid_t sigchld_tid;
  struct sigaction sa;
  siginfo_t si;

  memset(&suspender, 0, sizeof(suspender));
  memset(&reader, 0, sizeof(reader));
  test_assert(0 == pipe(reader.fds));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1_handler;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  sa.sa_handler = record_handler_tid;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  handler_tid = 0;
  handler_count = 0;
  test_assert(0 == pthread_create(&suspender.thread, NULL, suspender_main,
                                  &suspender));
  while (!(suspender_tid = __atomic_load_n(&suspender.tid, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  wait_for_task_asleep_in_syscall(suspender_tid, SYS_rt_sigsuspend, -1);
  reader.child = suspender.child;
  test_assert(0 == pthread_create(&reader.thread, NULL, stopper_reader_main,
                                  &reader));
  memset(&si, 0, sizeof(si));
  test_assert(0 == waitid(P_PID, suspender.child, &si, WSTOPPED | WNOWAIT));
  test_assert(si.si_pid == suspender.child && si.si_code == CLD_STOPPED);
  while (!(sigchld_tid = __atomic_load_n(&handler_tid, __ATOMIC_SEQ_CST))) {
    sched_yield();
  }
  test_assert(sigchld_tid == __atomic_load_n(&reader.tid, __ATOMIC_SEQ_CST));
  test_assert(0 == syscall(SYS_tgkill, getpid(), suspender_tid, SIGUSR1));
  test_assert(0 == pthread_join(suspender.thread, NULL));
  test_assert(1 == write(reader.fds[1], "x", 1));
  test_assert(0 == pthread_join(reader.thread, NULL));
  test_assert(__atomic_load_n(&handler_count, __ATOMIC_SEQ_CST) == 1);
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = 0;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  test_assert(0 == close(reader.fds[0]));
  test_assert(0 == close(reader.fds[1]));
  kill_child(suspender.child);
  drain_sigchld();
}

int main(void) {
  sigset_t mask;

  main_tid = sys_gettid();
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
  test_assert(0 == pipe(pipe_fds));

  tracee_sigchld_pending_for_process();
  stop_while_waiter_takes_sigchld();
  sigchld_goes_to_parent_thread(1, 0);
  sigchld_goes_to_parent_thread(0, 0);
  sigchld_goes_to_parent_thread(1, 1);
  sigchld_goes_to_parent_thread(0, 1);
  sigchld_skips_thread_that_blocks_it();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
