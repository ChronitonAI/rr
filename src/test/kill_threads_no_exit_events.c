/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* kill_threads_no_exit_events.run records this with
   --disable-ptrace-exit-events, so rr only learns that a task died when it
   gets its exit status, like when the kernel skips the PTRACE_EVENT_EXIT stop
   of a SIGKILLed task. We SIGKILL a child with two threads, both blocked in
   read(), and wait until both are zombies or gone. Then we change our fds,
   which the child shares, so rr updates the child's syscallbuf fd state
   through one of its threads, and we wait for the child. When rr handles the
   death of the first thread, it reads the child's memory through the other
   one. The child's address space is usually gone when rr accesses it. rr
   must handle that without warning. The race it tests only happens in some
   recordings. */

static int pipe_fds[2];
static int ready_fds[2];

static void* thread_fn(__attribute__((unused)) void* p) {
  char ch = 'r';
  test_assert(write(ready_fds[1], &ch, 1) == 1);
  test_assert(read(pipe_fds[0], &ch, 1) == 1);
  return NULL;
}

static int child_fn(__attribute__((unused)) void* p) {
  pthread_t thread;
  char ch;
  pthread_create(&thread, NULL, thread_fn, NULL);
  test_assert(read(pipe_fds[0], &ch, 1) == 1);
  return 1;
}

/* Returns the number of threads of `pid`. Sets `*sleeping` to the number of
   them that are sleeping and `*dead` to the number of them that are zombies
   (or gone). */
static int count_threads(pid_t pid, int* sleeping, int* dead) {
  char path[PATH_MAX];
  DIR* dir;
  struct dirent* e;
  int n = 0;

  sprintf(path, "/proc/%d/task", pid);
  dir = opendir(path);
  test_assert(dir != NULL);
  *sleeping = *dead = 0;
  while ((e = readdir(dir))) {
    char buf[1024];
    char* p;
    FILE* f;
    size_t len;

    if (e->d_name[0] == '.') {
      continue;
    }
    ++n;
    sprintf(path, "/proc/%d/task/%s/stat", pid, e->d_name);
    f = fopen(path, "r");
    len = 0;
    if (f) {
      len = fread(buf, 1, sizeof(buf) - 1, f);
      fclose(f);
    }
    buf[len] = 0;
    p = strrchr(buf, ')');
    if (!p) {
      /* The thread is gone: it has no stat file, or reading the file fails
         with ESRCH, so fread() returns 0. */
      ++*dead;
      continue;
    }
    test_assert(p[1] == ' ');
    if (p[2] == 'S') {
      ++*sleeping;
    } else if (p[2] == 'Z' || p[2] == 'X') {
      ++*dead;
    }
  }
  closedir(dir);
  return n;
}

int main(void) {
  const size_t stack_size = 1 << 20;
  int sleeping;
  int dead;
  int status;
  int fd;
  pid_t child;
  char ch;
  char* stack;

  test_assert(0 == pipe(pipe_fds));
  test_assert(0 == pipe(ready_fds));
  stack = (char*)mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);
  child = clone(child_fn, stack + stack_size, CLONE_FILES | SIGCHLD, NULL);
  test_assert(child > 0);

  test_assert(read(ready_fds[0], &ch, 1) == 1);
  while (count_threads(child, &sleeping, &dead) != 2 || sleeping != 2) {
    sched_yield();
  }
  kill(child, SIGKILL);
  while (count_threads(child, &sleeping, &dead) != dead) {
    sched_yield();
  }

  fd = dup(STDOUT_FILENO);
  test_assert(fd >= 0);
  test_assert(0 == close(fd));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
