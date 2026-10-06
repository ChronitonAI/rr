/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "../ptrace_util.h"

/* A tracer single-steps its tracee through read(), getpid(), a syscall
   instruction followed by three nops, and raise(). Under rr, those can go
   through rr's syscall hooks. The tracer must not see single-steps in rr's
   code (its preload library or its stubs), and a step over a patched syscall
   instruction must end right after the patched instructions, with si_addr
   pointing there.
   The tracee has SIGTRAP blocked. The kernel forces the SIGTRAPs of the
   single-steps, which unblocks it, and rr must keep track of that. */

#define MAX_MAPS 1024

/* The length of the instructions that rr replaces with a jump when it
   patches my_geteuid's syscall instruction: the syscall instruction and
   three nops. */
#define PATCHED_LENGTH 5

static struct {
  uintptr_t start;
  uintptr_t end;
  int bad;
} maps[MAX_MAPS];
static int num_maps;

extern char syscall_addr;

static void read_maps(pid_t pid) {
  char path[64];
  FILE* f;
  sprintf(path, "/proc/%d/maps", pid);
  f = fopen(path, "r");
  test_assert(f != NULL);
  while (1) {
    char* line = NULL;
    size_t len = 0;
    char perms[8];
    char name[512];
    unsigned long start, end;
    int fields;
    if (getline(&line, &len, f) == -1) {
      free(line);
      break;
    }
    name[0] = 0;
    fields = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511s", &start, &end, perms,
                    name);
    free(line);
    test_assert(fields >= 3);
    test_assert(num_maps < MAX_MAPS);
    maps[num_maps].start = start;
    maps[num_maps].end = end;
    /* Anonymous executable memory, or rr's preload library. */
    maps[num_maps].bad = (perms[2] == 'x' && name[0] == 0) ||
                         strstr(name, "librrpreload") != NULL;
    ++num_maps;
  }
  fclose(f);
}

static int in_bad_mapping(uintptr_t ip) {
  int i;
  for (i = 0; i < num_maps; ++i) {
    if (maps[i].start <= ip && ip < maps[i].end) {
      return maps[i].bad;
    }
  }
  return 0;
}

int main(void) {
  struct user_regs_struct regs;
  siginfo_t si;
  int fds[2];
  pid_t pid;
  int status;
  int steps = 0;
  uintptr_t step_target = 0;
  int checked_patched_step = 0;
  char ch;

  test_assert(0 == pipe(fds));
  /* rr doesn't patch syscalls in a task that has a ptracer. Make these calls
     here, so that rr patches them in libc, and so that the child doesn't
     resolve any symbols while it's being single-stepped. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(1 == read(fds[0], &ch, 1));
  test_assert(getpid() > 0);
  my_geteuid();
  test_assert(0 == raise(SIGWINCH));

  if (0 == (pid = fork())) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTRAP);
    test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    raise(SIGSTOP);
    test_assert(1 == read(fds[0], &ch, 1));
    test_assert(ch == 'y');
    test_assert(getpid() > 0);
    my_geteuid();
    raise(SIGUSR1);
    return 77;
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(1 == write(fds[1], "y", 1));
  read_maps(pid);

  while (1) {
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSTOPPED(status));
    if (WSTOPSIG(status) == SIGUSR1) {
      break;
    }
    test_assert(WSTOPSIG(status) == SIGTRAP);
    ptrace_getregs(pid, &regs);
    test_assert(!in_bad_mapping((uintptr_t)regs.IP));
    test_assert(0 == ptrace(PTRACE_GETSIGINFO, pid, NULL, &si));
    if (si.si_code == TRAP_TRACE || si.si_code == TRAP_BRKPT) {
      test_assert((uintptr_t)si.si_addr == (uintptr_t)regs.IP);
    }
    if (step_target) {
      test_assert((uintptr_t)regs.IP == step_target);
      step_target = 0;
      checked_patched_step = 1;
    }
    if ((uintptr_t)regs.IP == (uintptr_t)&syscall_addr) {
      /* If rr patched the syscall instruction, it's now a jump (0xe9), and
         the step must end after the patched instructions. Otherwise it ends
         after the syscall instruction. */
      errno = 0;
      long insn = ptrace(PTRACE_PEEKTEXT, pid, &syscall_addr, NULL);
      test_assert(errno == 0);
      step_target = (uintptr_t)&syscall_addr +
                    ((insn & 0xff) == 0xe9 ? PATCHED_LENGTH : SYSCALL_SIZE);
    }
    test_assert(++steps < 100000);
  }
  test_assert(checked_patched_step);

  test_assert(0 == ptrace(PTRACE_CONT, pid, NULL, NULL));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
