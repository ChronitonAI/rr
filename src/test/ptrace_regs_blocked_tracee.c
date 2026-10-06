/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* The tracee is blocked in read() when it reaches a ptrace-stop that the
   ptracer then waits for, and the ptracer reads the tracee's registers. In
   the first case, the ptracer stops the tracee with PTRACE_INTERRUPT. In
   the second, the tracee is a thread that the ptracer attached to, and
   another thread of its process stops the process with SIGSTOP.
   Throughout, another child is stopped. (Then rr, while it runs the
   ptracer, only waits for the ptracer, so it doesn't collect the tracee's
   stop by chance.) */

static void read_proc_file(const char* path, char* buf, size_t size) {
  int fd = open(path, O_RDONLY);
  ssize_t len;
  test_assert(fd >= 0);
  len = read(fd, buf, size - 1);
  test_assert(len >= 0);
  close(fd);
  buf[len] = 0;
}

/* Whether thread |tid| of process |pid| is asleep in read(). */
static int in_read(pid_t pid, pid_t tid) {
  char path[100];
  char buf[1000];
  char* p;
  long nr;
  sprintf(path, "/proc/%d/task/%d/stat", pid, tid);
  read_proc_file(path, buf, sizeof(buf));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  if (p[1] != ' ' || p[2] != 'S') {
    return 0;
  }
  /* "running", or the syscall number and its arguments */
  sprintf(path, "/proc/%d/task/%d/syscall", pid, tid);
  read_proc_file(path, buf, sizeof(buf));
  return 1 == sscanf(buf, "%ld", &nr) && nr == SYS_read;
}

static void wait_until_in_read(pid_t pid, pid_t tid) {
  while (!in_read(pid, tid)) {
    sched_yield();
  }
}

static void check_regs(pid_t tid) {
  struct user_regs_struct regs;
  ptrace_getregs(tid, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_read);
}

static void interrupt(void) {
  pid_t child;
  int status;
  int pipe_fds[2];
  char ch = 'x';

  test_assert(0 == pipe(pipe_fds));
  if (0 == (child = fork())) {
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    exit(77);
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_until_in_read(child, child);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
  check_regs(child);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));

  test_assert(1 == write(pipe_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  close(pipe_fds[0]);
  close(pipe_fds[1]);
}

static int tid_pipe[2];
static int thread_pipe[2];
static int main_thread_pipe[2];

static void* thread_func(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  /* The ptracer has attached to us. */
  test_assert(1 == read(thread_pipe[0], &ch, 1));
  return NULL;
}

static void group_stop(void) {
  pid_t child;
  pid_t tid;
  int status;
  char ch = 'x';

  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(thread_pipe));
  test_assert(0 == pipe(main_thread_pipe));
  if (0 == (child = fork())) {
    pthread_t thread;
    test_assert(0 == pthread_create(&thread, NULL, thread_func, NULL));
    test_assert(1 == read(main_thread_pipe[0], &ch, 1));
    raise(SIGSTOP);
    test_assert(0 == pthread_join(thread, NULL));
    exit(77);
  }

  test_assert(sizeof(tid) == read(tid_pipe[0], &tid, sizeof(tid)));
  test_assert(0 == ptrace(PTRACE_ATTACH, tid, NULL, NULL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  /* Let the thread block in its second read() before its process stops. */
  wait_until_in_read(child, tid);
  {
    /* Make sure the read is the second one: the first has returned once the
       pipe is empty. */
    int n;
    do {
      test_assert(0 == ioctl(thread_pipe[0], FIONREAD, &n));
    } while (n > 0);
    wait_until_in_read(child, tid);
  }
  test_assert(1 == write(main_thread_pipe[1], &ch, 1));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  check_regs(tid);
  test_assert(0 == ptrace(PTRACE_DETACH, tid, NULL, NULL));

  test_assert(0 == kill(child, SIGCONT));
  test_assert(1 == write(thread_pipe[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  pid_t stopped_child;
  int status;

  if (0 == (stopped_child = fork())) {
    raise(SIGSTOP);
    exit(77);
  }
  test_assert(stopped_child == waitpid(stopped_child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  interrupt();
  group_stop();

  test_assert(0 == kill(stopped_child, SIGCONT));
  test_assert(stopped_child == waitpid(stopped_child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
