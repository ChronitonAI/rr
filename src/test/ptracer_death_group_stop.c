/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* A ptracer exits, or detaches, while a SIGSTOP has stopped its tracee's
   process. The tracee must be stopped (again) until a SIGCONT, and its real
   parent must be able to wait for the stop exactly once. The ptracer is not
   the tracee's parent. */

enum {
  /* The ptracer seizes the tracee, which stops itself. */
  SEIZE,
  /* The ptracer attaches with PTRACE_ATTACH, and lets the attach's SIGSTOP
     stop the tracee. */
  ATTACH,
  /* As SEIZE, but the real parent waits for the stop before the ptracer
     exits. */
  PARENT_WAITS_FIRST,
  /* As SEIZE, but the ptracer resumes the tracee before it exits. */
  RESUMED,
  /* As SEIZE, but the ptracer detaches with PTRACE_DETACH before it
     exits. */
  DETACHED,
  NUM_MODES
};

static void run(int mode) {
  pid_t child;
  pid_t ptracer;
  int status;
  int ready_pipe[2];
  int go_pipe[2];
  int ran_pipe[2];
  int cont_pipe[2];
  int to_parent[2];
  int to_ptracer[2];
  char ch = 'x';
  /* In RESUMED mode, the child doesn't make syscalls while the ptracer
     exits: it sets shared[0] once it runs again, and spins until we set
     shared[1]. */
  volatile int* shared =
      (volatile int*)mmap(NULL, 2 * sizeof(int), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  test_assert(shared != MAP_FAILED);
  shared[0] = shared[1] = 0;

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pipe(ran_pipe));
  test_assert(0 == pipe(cont_pipe));
  test_assert(0 == pipe(to_parent));
  test_assert(0 == pipe(to_ptracer));

  if (0 == (child = fork())) {
    /* This fails on some kernels, so don't check its result */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_pipe[1], &ch, 1));
    test_assert(1 == read(go_pipe[0], &ch, 1));
    if (mode != ATTACH) {
      raise(SIGSTOP);
    }
    if (mode == RESUMED) {
      shared[0] = 1;
      while (!shared[1]) {
      }
    } else {
      test_assert(1 == write(ran_pipe[1], &ch, 1));
      test_assert(1 == read(cont_pipe[0], &ch, 1));
    }
    exit(77);
  }

  /* Make sure the prctl has happened before the ptracer attaches. */
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  if (0 == (ptracer = fork())) {
    if (mode == ATTACH) {
      test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
    } else {
      test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
      test_assert(1 == write(go_pipe[1], &ch, 1));
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
    /* Let the SIGSTOP put the child into a group-stop. */
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
    test_assert(child == waitpid(child, &status, 0));
    if (mode == ATTACH) {
      test_assert(status == ((SIGSTOP << 8) | 0x7f));
    } else {
      test_assert(status ==
                  ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
    }
    if (mode == RESUMED) {
      /* Its process stays stopped. */
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    } else if (mode == DETACHED) {
      test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
    }
    test_assert(1 == write(to_parent[1], &ch, 1));
    test_assert(1 == read(to_ptracer[0], &ch, 1));
    /* Now just exit. */
    exit(44);
  }

  test_assert(1 == read(to_parent[0], &ch, 1));
  if (mode == PARENT_WAITS_FIRST) {
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
  } else if (mode == RESUMED) {
    while (!shared[0]) {
    }
  }
  test_assert(1 == write(to_ptracer[1], &ch, 1));
  test_assert(ptracer == waitpid(ptracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);

  /* We can wait for the stop once, unless we did already. */
  if (mode != PARENT_WAITS_FIRST) {
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
  }
  test_assert(0 == waitpid(child, &status, WUNTRACED | WNOHANG));

  /* The child must be stopped. Attaching to a stopped task reports a stop;
     if the child were running, it would be blocked in read() or spinning,
     and we'd never get a stop. */
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  /* Linux reports a PTRACE_EVENT_STOP here, rr just a stop. */
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(0 == kill(child, SIGCONT));
  if (mode == ATTACH) {
    test_assert(1 == write(go_pipe[1], &ch, 1));
  }
  if (mode != RESUMED) {
    test_assert(1 == read(ran_pipe[0], &ch, 1));
  }
  if (mode == RESUMED) {
    shared[1] = 1;
  } else {
    test_assert(1 == write(cont_pipe[1], &ch, 1));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  munmap((void*)shared, 2 * sizeof(int));
}

int main(void) {
  int mode;
  for (mode = 0; mode < NUM_MODES; ++mode) {
    run(mode);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
