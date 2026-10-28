/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"
#include "ptrace_util.h"

/* The parent ptraces the child as gdb would (PTRACE_O_TRACECLONE and
   PTRACE_O_TRACEEXEC). The child starts a thread that waits, and then
   execs, from another thread or from its main thread. At the exec stop,
   the parent checks which thread exec'd and the registers, writes to the
   new image's stack (what's there already) with PTRACE_POKEDATA,
   process_vm_writev and /proc/<pid>/task/<pid>/mem (and through a
   /proc/<pid>/task/<pid>/mem it opened before the exec, which refers to the
   old image), sets a hardware watchpoint (on x86), and writes the
   registers, including the syscall result register, where the kernel
   stores the execve's return value when the child leaves the stop. It
   resumes the child with PTRACE_SYSCALL or PTRACE_SINGLESTEP, checks the
   stop that the execve's return causes, and single-steps the new image's
   first instruction. It also does a PTRACE_INTERRUPT at the exec stop
   (before PTRACE_SYSCALL) or at the single-step trap. Then it continues the
   child, writes to the stack again right away, collects the watchpoint
   trap, and writes to the new image through the /proc file again, which the
   new image waits for. */

#if defined(__x86_64__)
#define OTHER_REG r15
#elif defined(__i386__)
#define OTHER_REG esi
#elif defined(__aarch64__)
#define OTHER_REG regs[15]
#endif

#if defined(__x86_64__) || defined(__i386__)
#define HW_WATCHPOINT 1
/* DR7: enable DR0, break on 4-byte writes. */
#define DR7_WRITE_4_BYTES_AT_DR0 0xd0001
#endif

static char* exe;
static char addr_fd_str[16];
static int flag;
static volatile int hw_watched;

static void* do_exec(__attribute__((unused)) void* p) {
  char* argv[] = { exe, "exec'd", addr_fd_str, NULL };
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
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)));
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, tid, NULL, &new_tid));
  test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, NULL));
  test_assert((pid_t)new_tid == waitpid(new_tid, &status, __WALL));
  test_assert(WIFSTOPPED(status));
  test_assert(0 == ptrace(PTRACE_CONT, new_tid, NULL, NULL));
  return new_tid;
}

#ifdef HW_WATCHPOINT
/* The start of the mapping of offset 0 of |pid|'s executable. */
static uintptr_t exe_base(pid_t pid) {
  char path[100];
  char exe_path[PATH_MAX];
  char line[PATH_MAX + 100];
  ssize_t len;
  FILE* f;
  sprintf(path, "/proc/%d/exe", pid);
  len = readlink(path, exe_path, sizeof(exe_path) - 1);
  test_assert(len > 0);
  exe_path[len] = 0;
  sprintf(path, "/proc/%d/maps", pid);
  f = fopen(path, "r");
  test_assert(f != NULL);
  while (fgets(line, sizeof(line), f)) {
    unsigned long start;
    unsigned long offset;
    char name[PATH_MAX] = "";
    if (sscanf(line, "%lx-%*x %*s %lx %*s %*s %4095s", &start, &offset,
               name) == 3 &&
        offset == 0 && !strcmp(name, exe_path)) {
      fclose(f);
      return start;
    }
  }
  test_assert(0 && "Executable not mapped");
  return 0;
}

static void poke_debug_reg(pid_t pid, int regno, uintptr_t value) {
  test_assert(0 == ptrace(PTRACE_POKEUSER, pid,
                          (void*)offsetof(struct user, u_debugreg[regno]),
                          (void*)value));
}
#endif

static void run_child(int from_thread) {
  int fds[2];
  int addr_fds[2];
  pid_t child;
  pid_t waiting;
  pid_t execing;
  int status;
  unsigned long msg;
  struct user_regs_struct regs;
  struct user_regs_struct written;
  struct user_regs_struct after;
  siginfo_t si;
  long word;
  struct iovec local;
  struct iovec remote;
  char path[100];
  int mem_fd;
  int old_mem_fd;
  uintptr_t flag_addr;
  int one = 1;
  char ch;

  test_assert(0 == pipe(fds));
  test_assert(0 == pipe(addr_fds));
  sprintf(addr_fd_str, "%d", addr_fds[1]);
  child = fork();
  if (!child) {
    pthread_t thread;
    test_assert(1 == read(fds[0], &ch, 1));
    test_assert(0 == pthread_create(&thread, NULL, do_pause, NULL));
    if (from_thread) {
      test_assert(0 == pthread_create(&thread, NULL, do_exec, NULL));
      do_pause(NULL);
    }
    /* The exec's SIGKILL would take the new thread's first stop away if it
       came before we collected that. */
    test_assert(1 == read(fds[0], &ch, 1));
    do_exec(NULL);
  }
  test_assert(child > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                  PTRACE_O_TRACESYSGOOD)));
  sprintf(path, "/proc/%d/task/%d/mem", child, child);
  old_mem_fd = open(path, O_RDWR);
  test_assert(old_mem_fd >= 0);
  test_assert(1 == write(fds[1], "p", 1));
  waiting = wait_for_new_thread(child);
  if (!from_thread) {
    test_assert(1 == write(fds[1], "e", 1));
  }
  execing = from_thread ? wait_for_new_thread(child) : child;

  /* The exec kills the thread that waits, and can't finish until we've
     collected that. */
  test_assert(waiting == waitpid(waiting, &status, __WALL));
  test_assert(WIFEXITED(status) || WIFSIGNALED(status));
  /* The exec stop is reported under the child's pid, which the thread that
     exec'd has taken over, if it wasn't the main thread. */
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
  test_assert((pid_t)msg == execing);
  if (from_thread) {
    /* The kernel leaves the stop alone. */
    test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
    test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
    test_assert(si.si_code == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  }
  ptrace_getregs(child, &regs);
#if defined(__x86_64__)
  /* As at any syscall entry. */
  test_assert((long)regs.SYSCALL_RESULT == -ENOSYS);
#elif defined(__i386__)
  /* As at any syscall entry, except that a 32-bit kernel (whose user code
     segment is 0x73) has zeroed it. */
  test_assert((long)regs.SYSCALL_RESULT == (regs.xcs == 0x73 ? 0 : -ENOSYS));
#else
  /* start_thread() zeroed it. */
  test_assert(regs.SYSCALL_RESULT == 0);
#endif

  errno = 0;
  word = ptrace(PTRACE_PEEKDATA, child, (void*)regs.SP, NULL);
  test_assert(errno == 0);
  test_assert(0 == ptrace(PTRACE_POKEDATA, child, (void*)regs.SP,
                          (void*)word));
  local.iov_base = &word;
  local.iov_len = sizeof(word);
  remote.iov_base = (void*)regs.SP;
  remote.iov_len = sizeof(word);
  test_assert(sizeof(word) == process_vm_writev(child, &local, 1, &remote, 1,
                                                0));
  mem_fd = open(path, O_RDWR);
  test_assert(mem_fd >= 0);
  test_assert(sizeof(word) == pwrite64(mem_fd, &word, sizeof(word),
                                       (off64_t)(uintptr_t)regs.SP));
  /* That one refers to the old image, which is gone. */
  test_assert(0 == pwrite64(old_mem_fd, &word, sizeof(word),
                            (off64_t)(uintptr_t)regs.SP));
#ifdef HW_WATCHPOINT
  poke_debug_reg(child, 0,
                 (uintptr_t)&hw_watched - exe_base(getpid()) +
                     exe_base(child));
  poke_debug_reg(child, 7, DR7_WRITE_4_BYTES_AT_DR0);
#endif

  written = regs;
  written.SYSCALL_RESULT = 12345;
  written.OTHER_REG = 0x5a5a;
  ptrace_setregs(child, &written);
  test_assert(0 == ptrace(from_thread ? PTRACE_SYSCALL : PTRACE_SINGLESTEP,
                          child, NULL, NULL));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
  if (from_thread) {
    /* The execve's syscall-exit stop. */
    test_assert(status >> 8 == (SIGTRAP | 0x80));
  } else {
    /* The kernel reports the single-step at the execve's return, before
       the new image runs. */
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    if (running_under_rr()) {
      /* rr gives this trap the siginfo of its single-step trap after any
         syscall. */
      test_assert(si.si_code == SI_KERNEL);
    } else {
#if defined(__x86_64__) || defined(__i386__)
      test_assert(si.si_code == TRAP_BRKPT);
      test_assert(si.si_addr == (void*)regs.IP);
#else
      test_assert(si.si_code == SI_USER);
#endif
    }
    /* The kernel leaves the stop alone, and reports the interrupt with a
       PTRACE_EVENT_STOP once the child leaves it (rr doesn't report that
       stop). */
    test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
    test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
    test_assert(si.si_signo == SIGTRAP);
  }
  ptrace_getregs(child, &after);
  test_assert(after.IP == regs.IP);
  test_assert(after.SYSCALL_RESULT == 0);
  test_assert(after.OTHER_REG == 0x5a5a);
  /* Run the new image's first instruction. */
  do {
    test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, __WALL));
  } while (!from_thread && status >> 16 == PTRACE_EVENT_STOP);
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  /* The new image may not have started yet. */
  test_assert(sizeof(word) == process_vm_writev(child, &local, 1, &remote, 1,
                                                0));
#ifdef HW_WATCHPOINT
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
  test_assert(si.si_code == TRAP_HWBKPT);
  errno = 0;
  test_assert((ptrace(PTRACE_PEEKUSER, child,
                      (void*)offsetof(struct user, u_debugreg[6]), NULL) &
               1) &&
              errno == 0);
  poke_debug_reg(child, 7, 0);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
#endif

  test_assert(sizeof(flag_addr) ==
              read(addr_fds[0], &flag_addr, sizeof(flag_addr)));
  test_assert(sizeof(one) == pwrite64(mem_fd, &one, sizeof(one),
                                      (off64_t)flag_addr));
  test_assert(child == waitpid(child, &status, __WALL));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  close(mem_fd);
  close(old_mem_fd);
  close(fds[0]);
  close(fds[1]);
  close(addr_fds[0]);
  close(addr_fds[1]);
}

int main(int argc, char** argv) {
  if (argc == 3) {
    /* The new image. Trip the parent's watchpoint, tell the parent where
       |flag| is, and wait for it to set it. */
    uintptr_t flag_addr = (uintptr_t)&flag;
    hw_watched = 1;
    test_assert(sizeof(flag_addr) ==
                write(atoi(argv[2]), &flag_addr, sizeof(flag_addr)));
    while (!__atomic_load_n(&flag, __ATOMIC_SEQ_CST)) {
      sched_yield();
    }
    return 77;
  }
  exe = argv[0];
  run_child(1);
  run_child(0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
