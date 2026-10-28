/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Has rr SIGKILL a child at its exec, at the kill point named by argv[1]
   (see RRCALL_KILL_BEFORE_EXEC_STOP and the points after it), after the
   exec has replaced the child's image but before the new image runs: first
   a child in which a thread other than the main thread execs, then, at the
   points that rr also reaches when the main thread execs, a child in which
   the main thread does.
   Until the child is about to exec, the parent spins without making
   syscalls. So when the child is killed, the parent is stopped where rr
   preempted it, runnable, and doesn't report anything new by itself.
   With "in-initial-process" as argv[2], a thread of this process execs
   instead, so that the process's exit is rr's. */

static const struct {
  const char* name;
  int point;
  /* Whether rr reaches the point when the main thread execs. It reads the
     former tid only when another thread exec'd. */
  int for_main_thread_exec;
} kill_points[] = {
  { "before-exec-stop", RRCALL_KILL_BEFORE_EXEC_STOP, 1 },
  { "before-geteventmsg", RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG, 0 },
  { "before-geteventmsg-at-exit-stop",
    RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG_AT_EXIT_STOP, 0 },
  { "after-exec-stop", RRCALL_KILL_AFTER_EXEC_STOP, 1 },
};

static char* exe;
static int kill_point = -1;
static int for_main_thread_exec;
static int* about_to_exec;

static void do_exec(void) {
  char* argv[] = { exe, "exec'd", NULL };
  __atomic_store_n(about_to_exec, 1, __ATOMIC_SEQ_CST);
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
}

static void* exec_thread(__attribute__((unused)) void* p) {
  do_exec();
  return NULL;
}

static void run_child(int from_thread) {
  int status;
  pid_t child;
  /* The child and its threads get a copy of the arming. */
  int armed = rr_arm_kill(kill_point, 0, RRCALL_ARM_KILL_INHERIT);

  __atomic_store_n(about_to_exec, 0, __ATOMIC_SEQ_CST);
  child = fork();
  if (!child) {
    if (from_thread) {
      pthread_t thread;
      test_assert(0 == pthread_create(&thread, NULL, exec_thread, NULL));
      for (;;) {
        pause();
      }
    }
    do_exec();
  }
  test_assert(child > 0);
  while (!__atomic_load_n(about_to_exec, __ATOMIC_SEQ_CST)) {
  }
  test_assert(child == waitpid(child, &status, 0));
  if (armed) {
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
      for_main_thread_exec = kill_points[i].for_main_thread_exec;
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
    /* The thread gets a copy of the arming. */
    rr_arm_kill(kill_point, 0, RRCALL_ARM_KILL_INHERIT);
    test_assert(0 == pthread_create(&thread, NULL, exec_thread, NULL));
    for (;;) {
      pause();
    }
  }
  run_child(1);
  if (for_main_thread_exec) {
    run_child(0);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
