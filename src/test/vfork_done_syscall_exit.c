/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

/* A ptracer seizes a child with PTRACE_O_TRACEVFORKDONE and resumes it
   with one command until the child's vfork() reports
   PTRACE_EVENT_VFORK_DONE, and from that stop with another. Linux reports
   PTRACE_EVENT_VFORK_DONE in the syscall, so the second command decides
   what the ptracer gets at the syscall's exit: a syscall-exit stop for
   PTRACE_SYSCALL, a SIGTRAP for PTRACE_SINGLESTEP (tested on x86 only),
   nothing for PTRACE_CONT. rr reports PTRACE_EVENT_VFORK_DONE at the
   syscall's exit, and must report there what the second command asks
   for. */

static int ready_pipe[2];

static void handle_usr1(__attribute__((unused)) int sig) {}

static void child_main(void) {
  sigset_t set;
  pid_t vfork_child;
  int status;
  char ch;

  /* The vfork child's SIGCHLD stays pending, so the first stop after the
     vfork() that the ptracer doesn't ask for is the SIGUSR1 one. */
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
  signal(SIGUSR1, handle_usr1);
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  raise(SIGSTOP);
  vfork_child = vfork();
  if (!vfork_child) {
    _exit(0);
  }
  test_assert(vfork_child > 1);
  raise(SIGUSR1);
  test_assert(vfork_child == waitpid(vfork_child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  exit(77);
}

/* Returns the status of the next stop of |child|. Resumes the vfork child,
   which the ptracer traces too, and notes its exit. */
static int wait_for_child_stop(pid_t child, pid_t* vfork_child,
                               int* vfork_child_exited) {
  while (1) {
    int status;
    pid_t pid = waitpid(-1, &status, __WALL);
    test_assert(pid > 1);
    if (pid == child) {
      test_assert(WIFSTOPPED(status));
      return status;
    }
    /* Its first stop can come before the child's PTRACE_EVENT_VFORK. */
    if (!*vfork_child) {
      *vfork_child = pid;
    }
    test_assert(pid == *vfork_child);
    if (WIFSTOPPED(status)) {
      test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
    } else {
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      *vfork_child_exited = 1;
    }
  }
}

static void run(int command, int command_at_vfork_done) {
  pid_t child;
  pid_t vfork_child = 0;
  int vfork_child_exited = 0;
  int status;
  unsigned long msg;
  struct user_regs_struct regs;
  uintptr_t ip_at_vfork_done;

  test_assert(0 == pipe(ready_pipe));
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    child_main();
  }
  test_assert(child > 1);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACEVFORK |
                                  PTRACE_O_TRACEVFORKDONE |
                                  PTRACE_O_TRACESYSGOOD)));
  test_assert(1 == write(ready_pipe[1], "r", 1));
  status = wait_for_child_stop(child, &vfork_child, &vfork_child_exited);
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  while (1) {
    test_assert(0 == ptrace(command, child, NULL, NULL));
    status = wait_for_child_stop(child, &vfork_child, &vfork_child_exited);
    if (status >> 16 == PTRACE_EVENT_VFORK) {
      test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
      test_assert(msg > 1);
      test_assert(!vfork_child || vfork_child == (pid_t)msg);
      vfork_child = msg;
    } else if (status >> 16 == PTRACE_EVENT_VFORK_DONE) {
      break;
    }
  }
  test_assert(vfork_child > 1);
  ptrace_getregs(child, &regs);
  ip_at_vfork_done = (uintptr_t)regs.IP;

  test_assert(0 == ptrace(command_at_vfork_done, child, NULL, NULL));
  status = wait_for_child_stop(child, &vfork_child, &vfork_child_exited);
  if (command_at_vfork_done == PTRACE_CONT) {
    test_assert(status == ((SIGUSR1 << 8) | 0x7f));
  } else {
    if (command_at_vfork_done == PTRACE_SYSCALL) {
      test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
    } else {
      test_assert(status == ((SIGTRAP << 8) | 0x7f));
    }
    /* At the exit of the vfork(). */
    ptrace_getregs(child, &regs);
    test_assert((uintptr_t)regs.IP == ip_at_vfork_done);
    test_assert((pid_t)regs.SYSCALL_RESULT == vfork_child);
  }

  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
  while (!vfork_child_exited) {
    test_assert(vfork_child == waitpid(vfork_child, &status, __WALL));
    if (WIFSTOPPED(status)) {
      test_assert(0 == ptrace(PTRACE_CONT, vfork_child, NULL, NULL));
    } else {
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      vfork_child_exited = 1;
    }
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(0 == close(ready_pipe[0]));
  test_assert(0 == close(ready_pipe[1]));
}

int main(void) {
  run(PTRACE_SYSCALL, PTRACE_SYSCALL);
  run(PTRACE_SYSCALL, PTRACE_CONT);
  run(PTRACE_CONT, PTRACE_SYSCALL);
  run(PTRACE_CONT, PTRACE_CONT);
#if defined(__i386__) || defined(__x86_64__)
  run(PTRACE_SINGLESTEP, PTRACE_SINGLESTEP);
  run(PTRACE_SINGLESTEP, PTRACE_CONT);
  run(PTRACE_SINGLESTEP, PTRACE_SYSCALL);
  run(PTRACE_SYSCALL, PTRACE_SINGLESTEP);
  run(PTRACE_CONT, PTRACE_SINGLESTEP);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
