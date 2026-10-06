/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* The child's _exit() is the first exit_group syscall in its address space,
   so rr patches that syscall instruction, and we have rr SIGKILL the child
   while it does: before rr takes the child out of the syscall, or with the
   argument "patching", after that, just before patching.
   The child holds a robust mutex in shared memory when it exits. The kernel
   marks the mutex's owner as dead, and rr has to record that while the
   child is in its PTRACE_EVENT_EXIT stop, or replay of our
   pthread_mutex_lock() goes wrong. */

int main(int argc, char** argv) {
  pthread_mutex_t* mutex = mmap(NULL, sizeof(*mutex), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  pthread_mutexattr_t attr;
  int status;
  pid_t child;

  test_assert(mutex != MAP_FAILED);
  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(mutex, &attr));

  child = fork();
  if (!child) {
    test_assert(0 == pthread_mutex_lock(mutex));
    rr_arm_kill(argc > 1 && !strcmp(argv[1], "patching")
                    ? RRCALL_KILL_BEFORE_SYSCALL_PATCH
                    : RRCALL_KILL_BEFORE_SYSCALL_PATCH_EXIT,
                SYS_exit_group, 0);
    _exit(0);
  }
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(mutex));
  test_assert(0 == pthread_mutex_consistent(mutex));
  test_assert(0 == pthread_mutex_unlock(mutex));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
