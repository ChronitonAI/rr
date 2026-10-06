/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* A ptracer interrupts its tracee, which is blocked in read(), waits for the
   stop and reads the tracee's registers. Meanwhile another thread of the
   ptracer stops the ptracer's process with SIGSTOP, and then our main
   thread continues it with SIGCONT. The read of the registers must succeed.
   (Under rr, the ptracer can still be waiting to make its PTRACE_GETREGS
   when the SIGSTOP comes; scheduling priorities make rr stop the tracee
   only after that, and look at the SIGCONT for the ptracer's main thread
   before its other thread. Another child stays stopped throughout, so that
   rr doesn't collect the tracee's stop while it runs the ptracer.) */

static pid_t main_tid;
static volatile int about_to_get_regs;
static volatile int got_regs;

static void read_proc_file(const char* path, char* buf, size_t size) {
  int fd = open(path, O_RDONLY);
  ssize_t len;
  test_assert(fd >= 0);
  len = read(fd, buf, size - 1);
  test_assert(len >= 0);
  close(fd);
  buf[len] = 0;
}

/* The state of thread |tid| of process |pid|, as in /proc/<pid>/stat. */
static char thread_state(pid_t pid, pid_t tid) {
  char path[100];
  char buf[1000];
  char* p;
  sprintf(path, "/proc/%d/task/%d/stat", pid, tid);
  read_proc_file(path, buf, sizeof(buf));
  p = strrchr(buf, ')');
  test_assert(p != NULL && p[1] == ' ');
  return p[2];
}

/* Whether thread |tid| of process |pid| is asleep in syscall |syscallno|. */
static int asleep_in_syscall(pid_t pid, pid_t tid, long syscallno) {
  char path[100];
  char buf[1000];
  long nr;
  if (thread_state(pid, tid) != 'S') {
    return 0;
  }
  /* "running", or the syscall number and its arguments */
  sprintf(path, "/proc/%d/task/%d/syscall", pid, tid);
  read_proc_file(path, buf, sizeof(buf));
  return 1 == sscanf(buf, "%ld", &nr) && nr == syscallno;
}

static void* stopper(__attribute__((unused)) void* p) {
  pid_t pid = getpid();
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 10));
  /* Natively, wait until the main thread has the registers. Under rr, it
     may still be waiting to make its PTRACE_GETREGS (in a ptrace-stop for
     rr). */
  while (!about_to_get_regs ||
         !(got_regs || thread_state(pid, main_tid) == 't')) {
  }
  raise(SIGSTOP);
  return NULL;
}

static int ptracer(void) {
  pid_t tracee;
  pthread_t thread;
  struct user_regs_struct regs;
  int status;
  int pipe_fds[2];
  char ch = 'x';

  main_tid = sys_gettid();
  test_assert(0 == pipe(pipe_fds));
  if (0 == (tracee = fork())) {
    test_assert(0 == setpriority(PRIO_PROCESS, 0, 15));
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, tracee, NULL, NULL));
  while (!asleep_in_syscall(tracee, tracee, SYS_read)) {
    sched_yield();
  }
  test_assert(0 == pthread_create(&thread, NULL, stopper, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, tracee, NULL, NULL));
  test_assert(tracee == waitpid(tracee, &status, 0));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
  about_to_get_regs = 1;
  ptrace_getregs(tracee, &regs);
  got_regs = 1;
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
  test_assert(0 == pthread_join(thread, NULL));

  test_assert(0 == ptrace(PTRACE_CONT, tracee, NULL, NULL));
  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(tracee == waitpid(tracee, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  return 66;
}

int main(void) {
  pid_t stopped_child;
  pid_t child;
  int status;

  if (0 == (stopped_child = fork())) {
    raise(SIGSTOP);
    exit(77);
  }
  test_assert(stopped_child == waitpid(stopped_child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  if (0 == (child = fork())) {
    exit(ptracer());
  }
  test_assert(0 == setpriority(PRIO_PROCESS, 0, 19));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);

  test_assert(0 == kill(stopped_child, SIGCONT));
  test_assert(stopped_child == waitpid(stopped_child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
