/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A wait for the stop of a child process returns the child's pid, whichever
   of its threads stopped first. And a child whose main thread has exited can
   be stopped and killed, without its parent waiting for the stop. */

#define ROUNDS 100

static int fds[2];
static int ready_fds[2];

static void* thread_main(__attribute__((unused)) void* p) {
  char ch;
  test_assert(1 == write(ready_fds[1], "r", 1));
  test_assert(1 == read(fds[0], &ch, 1));
  return NULL;
}

static void run_child(int round) {
  siginfo_t* si;
  pthread_t thread;
  pid_t child;
  int status;
  char ch;

  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(ready_fds));
  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    pthread_join(thread, NULL);
    test_assert(0);
  }
  test_assert(1 == read(ready_fds[0], &ch, 1));

  test_assert(0 == kill(child, SIGSTOP));
  switch (round % 3) {
    case 0:
      test_assert(child == waitpid(child, &status, WUNTRACED));
      test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
      break;
    case 1:
      test_assert(child == wait4(-1, &status, WUNTRACED, NULL));
      test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
      break;
    case 2:
      ALLOCATE_GUARD(si, 'a');
      test_assert(0 == waitid(P_PID, child, si, WSTOPPED));
      test_assert(si->si_pid == child && si->si_code == CLD_STOPPED);
      VERIFY_GUARD(si);
      break;
  }

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));
  test_assert(0 == close(ready_fds[0]));
  test_assert(0 == close(ready_fds[1]));
}

/* Returns true if |pid|'s main thread is a zombie. */
static int main_thread_exited(pid_t pid) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/stat", pid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  return p[2] == 'Z';
}

static void kill_stopped_child_with_exited_main_thread(void) {
  pthread_t thread;
  sigset_t sigs;
  siginfo_t si;
  pid_t child;
  int status;
  char ch;

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigs, NULL));
  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(ready_fds));
  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    pthread_exit(NULL);
  }
  test_assert(1 == read(ready_fds[0], &ch, 1));
  while (!main_thread_exited(child)) {
    sched_yield();
  }

  /* The SIGCHLD tells us that the child has stopped. */
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(SIGCHLD == sigwaitinfo(&sigs, &si));
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  test_assert(0 == sigprocmask(SIG_UNBLOCK, &sigs, NULL));
}

int main(void) {
  int i;
  for (i = 0; i < ROUNDS; ++i) {
    run_child(i);
  }
  kill_stopped_child_with_exited_main_thread();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
