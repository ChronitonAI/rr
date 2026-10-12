/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Like exec_killed_at_exec_stop, but the process that execs is ptraced by
   a sibling, not by its parent (PTRACE_SEIZE with PTRACE_O_TRACECLONE).
   Its main thread starts a thread that waits, and then one that execs, which
   rr kills at the kill point named by argv[1]. The tracer waits for the
   death of the thread that waits, which the exec kills, and of the thread
   that execs, which the exec has given the process's pid, so nothing is
   reported under its own tid. Before collecting each, it checks that ptrace
   requests on it behave as for any dead tracee. */

static const struct {
  const char* name;
  int point;
} kill_points[] = {
  { "before-exec-stop", RRCALL_KILL_BEFORE_EXEC_STOP },
  { "before-geteventmsg", RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG },
  { "before-geteventmsg-at-exit-stop",
    RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG_AT_EXIT_STOP },
  { "after-exec-stop", RRCALL_KILL_AFTER_EXEC_STOP },
};

static char* exe;
static int kill_point = -1;

static void* do_exec(__attribute__((unused)) void* p) {
  char* argv[] = { exe, "exec'd", NULL };
  rr_arm_kill(kill_point, 0, 0);
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

static void* do_pause(__attribute__((unused)) void* p) {
  for (;;) {
    pause();
  }
  return NULL;
}

/* Waits for |tid|'s PTRACE_EVENT_CLONE stop, continues it and returns the
   new thread's tid, after waiting for its first stop and continuing it. */
static pid_t wait_for_new_thread(pid_t tid) {
  int status;
  unsigned long new_tid;
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_CLONE);
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, tid, NULL, &new_tid));
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert((pid_t)new_tid == waitpid(new_tid, &status, __WALL));
  test_assert(WIFSTOPPED(status));
  test_assert(0 == ptrace(PTRACE_CONT, new_tid, NULL, NULL));
  return new_tid;
}

/* Waits for |tid| to die, without collecting it, and checks that ptrace
   requests on it fail, except PTRACE_KILL and (since we seized it)
   PTRACE_INTERRUPT, which do nothing. */
static void wait_for_death(pid_t tid) {
  siginfo_t si;
  test_assert(0 == waitid(P_PID, tid, &si, WEXITED | WNOWAIT | __WALL));
  test_assert(si.si_code == CLD_EXITED || si.si_code == CLD_KILLED);
  test_assert(-1 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert(errno == ESRCH);
  test_assert(-1 == ptrace(PTRACE_DETACH, tid, NULL, NULL));
  test_assert(errno == ESRCH);
  test_assert(0 == ptrace(PTRACE_KILL, tid, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
}

static void trace(pid_t child, int ready_fd, int go_fd) {
  pid_t waiting;
  pid_t execing;
  int status;
  char ch;

  test_assert(1 == read(ready_fd, &ch, 1));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)PTRACE_O_TRACECLONE));
  test_assert(1 == write(go_fd, "g", 1));
  waiting = wait_for_new_thread(child);
  execing = wait_for_new_thread(child);
  wait_for_death(waiting);
  test_assert(waiting == waitpid(waiting, &status, __WALL));
  test_assert(WIFEXITED(status) || WIFSIGNALED(status));
  wait_for_death(child);
  test_assert(-1 == waitpid(execing, &status, __WALL));
  test_assert(errno == ECHILD);
  test_assert(child == waitpid(child, &status, __WALL));
  if (running_under_rr()) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

int main(int argc, char** argv) {
  size_t i;
  int ready_fds[2];
  int go_fds[2];
  pid_t child;
  pid_t tracer;
  int status;
  char ch;

  test_assert(argc == 2);
  if (!strcmp(argv[1], "exec'd")) {
    return 0;
  }
  for (i = 0; i < sizeof(kill_points) / sizeof(kill_points[0]); ++i) {
    if (!strcmp(argv[1], kill_points[i].name)) {
      kill_point = kill_points[i].point;
    }
  }
  test_assert(kill_point >= 0);
  exe = argv[0];
  test_assert(0 == pipe(ready_fds));
  test_assert(0 == pipe(go_fds));

  child = fork();
  if (!child) {
    pthread_t thread;
    /* Let the sibling ptrace us. */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    test_assert(1 == write(ready_fds[1], "r", 1));
    test_assert(1 == read(go_fds[0], &ch, 1));
    pthread_create(&thread, NULL, do_pause, NULL);
    pthread_create(&thread, NULL, do_exec, NULL);
    do_pause(NULL);
  }
  tracer = fork();
  if (!tracer) {
    trace(child, ready_fds[0], go_fds[1]);
    return 0;
  }
  test_assert(tracer == waitpid(tracer, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  test_assert(child == waitpid(child, &status, 0));
  if (running_under_rr()) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
