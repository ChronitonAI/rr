/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"
#include "ptrace_util.h"

/* Like exec_killed_at_exec_stop, but the parent ptraces each child, as gdb
   would (PTRACE_O_TRACECLONE and PTRACE_O_TRACEEXEC, no PTRACE_O_TRACEEXIT),
   or as strace would (also PTRACE_O_TRACESYSGOOD, resuming with
   PTRACE_SYSCALL), and the child has a third thread. The exec kills that
   thread, and rr keeps its task until the parent has collected its exit;
   that mustn't keep rr from ending the execve when rr SIGKILLs the child at
   the kill point named by argv[1]. rr reports the exec stop to the parent
   once it has recorded the execve's return, so the parent sees the child die
   without one, except at before-exec-exit-event, where the child dies after
   it. Either way, the parent sees the execve's syscall-exit stop only after
   the exec stop. The new image prints a line if it runs, i.e. if the child
   wasn't killed. */

static const struct {
  const char* name;
  int point;
  /* Whether rr reports the exec stop. */
  int exec_stop;
} kill_points[] = {
  { "before-exec-stop", RRCALL_KILL_BEFORE_EXEC_STOP, 0 },
  { "before-geteventmsg", RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG, 0 },
  { "before-geteventmsg-at-exit-stop",
    RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG_AT_EXIT_STOP, 0 },
  { "after-exec-stop", RRCALL_KILL_AFTER_EXEC_STOP, 0 },
  { "before-exec-exit-event", RRCALL_KILL_BEFORE_EXEC_EXIT_EVENT, 1 },
};

/* Old systems don't have these. glibc's sys/ptrace.h defines the
   PTRACE_SYSCALL_INFO_* values in an enum, hence the RR_ prefix. */
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#define RR_PTRACE_SYSCALL_INFO_ENTRY 1
#define RR_PTRACE_SYSCALL_INFO_EXIT 2

struct rr_ptrace_syscall_info {
  uint8_t op;
  uint8_t pad[3];
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t stack_pointer;
  struct {
    uint64_t nr;
    uint64_t args[6];
  } entry;
};

static char* exe;
static int kill_point_index = -1;
static int kill_point = -1;
static int go_fds[2];
static int block_fds[2];

static void* do_exec(__attribute__((unused)) void* p) {
  char* argv[] = { exe, "exec'd", NULL };
  rr_arm_kill(kill_point, 0, 0);
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

static void* do_exec_when_told(void* p) {
  char ch;
  test_assert(1 == read(go_fds[0], &ch, 1));
  return do_exec(p);
}

static void* do_pause(__attribute__((unused)) void* p) {
  for (;;) {
    pause();
  }
  return NULL;
}

static void run_child(int from_thread, int resume) {
  int fds[2];
  char ch;
  int status;
  pid_t child;
  pid_t w;
  int child_died = 0;
  pid_t new_tids[2] = { 0, 0 };
  int num_new_tids = 0;
  int entered_execve = 0;
  int exec_stopped = 0;
  int told = 0;

  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(go_fds));
  test_assert(0 == pipe(block_fds));
  child = fork();
  if (!child) {
    pthread_t thread;
    test_assert(1 == read(fds[0], &ch, 1));
    pthread_create(&thread, NULL, do_pause, NULL);
    if (from_thread) {
      /* The main thread blocks in this read, which nothing ever satisfies,
         unless the exec kills it first. */
      pthread_create(&thread, NULL, do_exec_when_told, NULL);
      test_assert(1 == read(block_fds[0], &ch, 1));
      test_assert(0 && "Read returned");
    }
    do_exec(NULL);
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                  PTRACE_O_TRACESYSGOOD)));
  test_assert(1 == write(fds[1], "p", 1));
  /* With PTRACE_SYSCALL, the parent lets the second new thread exec once it
     has seen the main thread enter its read (below). With PTRACE_CONT, it
     sees no syscall stops, and nothing here depends on that order. */
  if (from_thread && resume == PTRACE_CONT) {
    test_assert(1 == write(go_fds[1], "g", 1));
  }
  /* Let every thread of the child run until they're all gone. The child's
     own death comes last, and only once. The thread that execs takes over
     the child's pid, so its death is never reported under its own tid (the
     second new thread's). */
  while ((w = waitpid(-1, &status, __WALL)) > 0) {
    test_assert(!child_died);
    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      if (sig == (SIGTRAP | 0x80)) {
        struct rr_ptrace_syscall_info info;
        if (ptrace(PTRACE_GET_SYSCALL_INFO, w, (void*)sizeof(info), &info) <
            0) {
          /* The thread has been killed out of the stop since. Or Linux is
             older than 5.3, which doesn't support this (rr's emulation
             does). */
          test_assert(errno == ESRCH ||
                      (errno == EIO && !running_under_rr()));
        } else {
          if (info.op == RR_PTRACE_SYSCALL_INFO_ENTRY &&
              info.entry.nr == SYS_execve) {
            entered_execve = 1;
          }
          /* Once a thread has entered the execve, no thread with the
             child's pid leaves a syscall before the exec stop. If the main
             thread doesn't exec itself, we've seen it enter its read, which
             never returns, and the exec kills it there (a thread killed at
             a syscall stop gets no syscall-exit stop). */
          if (info.op == RR_PTRACE_SYSCALL_INFO_EXIT && w == child &&
              entered_execve) {
            test_assert(exec_stopped);
          }
        }
        if (from_thread && w == child && !told) {
          struct user_regs_struct regs;
          ptrace_getregs(w, &regs);
          if (regs.ORIG_SYSCALLNO == SYS_read &&
              (int)regs.SYSCALL_ARG1 == block_fds[0]) {
            /* The main thread's entry stop for its read. */
            test_assert(1 == write(go_fds[1], "g", 1));
            told = 1;
          }
        }
        sig = 0;
      }
      if ((status >> 16) == PTRACE_EVENT_EXEC) {
        exec_stopped = 1;
      }
      if ((status >> 16) == PTRACE_EVENT_CLONE) {
        unsigned long msg;
        test_assert(num_new_tids < 2);
        test_assert(0 == ptrace(PTRACE_GETEVENTMSG, w, NULL, &msg));
        new_tids[num_new_tids++] = msg;
      }
      if ((status >> 16) || sig == SIGTRAP) {
        sig = 0;
      }
      ptrace(resume, w, NULL, (void*)(long)sig);
    } else if (w == child) {
      child_died = 1;
    } else {
      test_assert(!from_thread || w != new_tids[1]);
    }
  }
  test_assert(errno == ECHILD);
  test_assert(exec_stopped == (running_under_rr() ?
                               kill_points[kill_point_index].exec_stop : 1));
  /* Under rr, the parent can miss the child's death: when the kernel
     completes a wait with it while the emulated exit stop of a thread that
     the exec killed is still pending, rr returns that stop instead, and the
     death is lost. */
  test_assert(child_died || running_under_rr());
  close(fds[0]);
  close(fds[1]);
  close(go_fds[0]);
  close(go_fds[1]);
  close(block_fds[0]);
  close(block_fds[1]);
}

int main(int argc, char** argv) {
  size_t i;

  test_assert(argc == 2);
  if (!strcmp(argv[1], "exec'd")) {
    atomic_puts("new image ran");
    return 0;
  }
  for (i = 0; i < sizeof(kill_points) / sizeof(kill_points[0]); ++i) {
    if (!strcmp(argv[1], kill_points[i].name)) {
      kill_point_index = i;
      kill_point = kill_points[i].point;
    }
  }
  test_assert(kill_point >= 0);
  exe = argv[0];
  run_child(1, PTRACE_CONT);
  run_child(0, PTRACE_CONT);
  run_child(1, PTRACE_SYSCALL);
  run_child(0, PTRACE_SYSCALL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
