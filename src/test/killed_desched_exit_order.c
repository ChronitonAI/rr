/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* The child blocks in a buffered read() into memory that it shares with us.
   After the read() returns, the syscall buffer code copies the data there,
   and we have rr SIGKILL the child at its next stop, at the ioctl that
   disarms the desched signal, before rr looks at that stop. We wait for the
   data to appear, so the child's execution up to that stop must come before
   ours after the wait in the trace, or replay of our wait goes wrong.
   In chaos mode, rr traces some of the read()s that it would buffer. The
   child isn't killed in those, and reads again. */

static char* shared;
static int fds[2];

static void child(void) {
  if (!rr_arm_kill(RRCALL_KILL_AFTER_DESCHED_DISARM_STOP_WAIT, 0, 0)) {
    test_assert(1 == read(fds[0], shared, 1));
    exit(77);
  }
  while (1) {
    test_assert(1 == read(fds[0], shared, 1));
  }
}

int main(void) {
  char c = 0;
  pid_t pid;
  pid_t ret;
  int status;

  shared = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(shared != MAP_FAILED);
  test_assert(0 == pipe(fds));
  /* Make rr patch read() in libc, so that the child's read()s go through
     the syscall buffer. */
  test_assert(1 == write(fds[1], &c, 1));
  test_assert(1 == read(fds[0], &c, 1));

  pid = fork();
  if (!pid) {
    child();
  }

  c = 1;
  while (1) {
    wait_for_task_asleep_in_syscall(pid, SYS_read, fds[0]);
    test_assert(1 == write(fds[1], &c, 1));
    while (!__atomic_load_n(shared, __ATOMIC_SEQ_CST)) {
    }
    __atomic_store_n(shared, 0, __ATOMIC_SEQ_CST);
    /* Wait until the child has died or reads again. */
    while (0 == (ret = waitpid(pid, &status, WNOHANG)) &&
           !task_asleep_in_syscall(pid, SYS_read, fds[0])) {
      sched_yield();
    }
    if (ret) {
      test_assert(ret == pid);
      break;
    }
  }

  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    /* Without rr */
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
