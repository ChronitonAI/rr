/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Has rr SIGKILL a child at its exec, at the kill point named by argv[1]
   (see RRCALL_KILL_BEFORE_EXEC_STOP and the points after it), after the
   exec has replaced the child's image but before the new image runs: first
   a child in which a thread other than the main thread execs, then one in
   which the main thread execs.
   Until the child is about to exec, the parent spins without making
   syscalls. So when the child is killed, the parent is stopped where rr
   preempted it, runnable, and doesn't report anything new by itself.
   With "in-initial-process" as argv[2], a thread of this process execs
   instead, so that the process's exit is rr's. */

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
static volatile int* about_to_exec;

static void* do_exec(__attribute__((unused)) void* p) {
  char* argv[] = { exe, "exec'd", NULL };
  rr_arm_kill(kill_point, 0, 0);
  *about_to_exec = 1;
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

static void run_child(int from_thread) {
  int status;
  pid_t child;

  *about_to_exec = 0;
  child = fork();
  if (!child) {
    if (from_thread) {
      pthread_t thread;
      pthread_create(&thread, NULL, do_exec, NULL);
      for (;;) {
        pause();
      }
    }
    do_exec(NULL);
  }
  while (!*about_to_exec) {
  }
  test_assert(child == waitpid(child, &status, 0));
  if (running_under_rr()) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

int main(int argc, char** argv) {
  size_t i;

  test_assert(argc == 2 || argc == 3);
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
  about_to_exec = mmap(NULL, sizeof(*about_to_exec), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(about_to_exec != MAP_FAILED);
  if (argc == 3) {
    pthread_t thread;
    test_assert(!strcmp(argv[2], "in-initial-process"));
    pthread_create(&thread, NULL, do_exec, NULL);
    for (;;) {
      pause();
    }
  }
  run_child(1);
  run_child(0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
