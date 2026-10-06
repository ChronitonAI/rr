/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Two threads wait for our stopped child: the main thread with
   waitpid(child, 0), another one with WCONTINUED. Once both are blocked in
   their waits, a third thread continues the child. The second waiter must
   see the continue (Linux wakes every waiter), and the main thread the
   child's exit. */

static pid_t child;
static pid_t main_tid;
static pid_t continue_waiter_tid;
static int to_child[2];

/* Whether thread |tid| is asleep in its waitpid(). */
static int in_wait(pid_t tid) {
#ifdef SYS_waitpid
  if (task_asleep_in_syscall(tid, SYS_waitpid, -1)) {
    return 1;
  }
#endif
  return task_asleep_in_syscall(tid, SYS_wait4, -1);
}

static void* continue_waiter(__attribute__((unused)) void* p) {
  int status;
  char ch = 'x';
  __atomic_store_n(&continue_waiter_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(child == waitpid(child, &status, WCONTINUED));
  test_assert(WIFCONTINUED(status));
  /* Now the child may exit. */
  test_assert(1 == write(to_child[1], &ch, 1));
  return NULL;
}

static void* continuer(__attribute__((unused)) void* p) {
  pid_t tid;
  while (!(tid = __atomic_load_n(&continue_waiter_tid, __ATOMIC_SEQ_CST)) ||
         !in_wait(main_tid) || !in_wait(tid)) {
    sched_yield();
  }
  test_assert(child > 1);
  test_assert(0 == kill(child, SIGCONT));
  return NULL;
}

int main(void) {
  pthread_t continue_waiter_thread;
  pthread_t continuer_thread;
  int status;
  char ch;

  test_assert(0 == pipe(to_child));
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    test_assert(1 == read(to_child[0], &ch, 1));
    return 77;
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  main_tid = sys_gettid();
  test_assert(0 == pthread_create(&continue_waiter_thread, NULL,
                                  continue_waiter, NULL));
  test_assert(0 == pthread_create(&continuer_thread, NULL, continuer, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  test_assert(0 == pthread_join(continue_waiter_thread, NULL));
  test_assert(0 == pthread_join(continuer_thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
