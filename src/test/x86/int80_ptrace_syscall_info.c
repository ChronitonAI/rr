/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* PTRACE_GET_SYSCALL_INFO at the entry and the exit of i386 syscalls that
   an x86-64 tracee makes with int $0x80, and of the x86-64 rt_sigreturn()
   of a handler of a signal that one of them sends, which returns to the
   instruction after the int $0x80. Then at the syscall stops of such a
   syscall for a tracer that doesn't use PTRACE_O_TRACESYSGOOD, where the
   kernel reports op PTRACE_SYSCALL_INFO_NONE and the syscall's arch. */

#if defined(__x86_64__) && defined(PTRACE_GET_SYSCALL_INFO)

#include <linux/audit.h>
#include <linux/ptrace.h>

#define I386_kill 37

static volatile int handled;

static void handler(__attribute__((unused)) int sig) { handled = 1; }

/* Forks a child that stops itself, writes to fd and sends itself a SIGUSR1
   with int $0x80, and exits with status 77 */
static pid_t fork_child(int fd) {
  pid_t child = fork();
  if (!child) {
    char* buf;
    pid_t self = getpid();
    int80_setup();
    buf = int80_low_alloc(4096);
    strcpy(buf, "hello");
    signal(SIGUSR1, handler);
    kill(self, SIGSTOP);
    test_assert(5 == int80_3(I386_write, fd, LOW(buf), 5));
    test_assert(0 == int80_2(I386_kill, self, SIGUSR1));
    test_assert(handled);
    exit(77);
  }
  test_assert(child > 0);
  return child;
}

/* Checks that the instruction before ip is int $0x80 */
static void check_int80_before(pid_t child, uint64_t ip) {
  long ret;
  errno = 0;
  ret = ptrace(PTRACE_PEEKDATA, child, (void*)(uintptr_t)(ip - 2), NULL);
  test_assert(errno == 0);
  test_assert((ret & 0xffff) == 0x80cd);
}

/* Resumes the tracee with sig and waits until it exits with status 77 */
static void finish_child(pid_t child, int sig) {
  int status;
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)(long)sig));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Resumes the tracee with PTRACE_SYSCALL and sig, waits for its next
   syscall stop, and gets its PTRACE_GET_SYSCALL_INFO */
static void next_syscall_stop(pid_t child, int sig,
                              struct ptrace_syscall_info* info) {
  int status;
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)(long)sig));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  memset(info, 0, sizeof(*info));
  test_assert(0 < ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info));
}

int main(void) {
  pid_t child;
  int status;
  int fds[2];
  struct ptrace_syscall_info info;
  long ret;

  test_assert(0 == pipe(fds));
  child = fork_child(fds[1]);
  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* The entry of the write. kill() returns first. */
  while (1) {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
    memset(&info, 0, sizeof(info));
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info);
    if (ret <= 0) {
      test_assert(errno == EIO);
      atomic_puts("PTRACE_GET_SYSCALL_INFO not supported");
      kill(child, SIGKILL);
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.arch == AUDIT_ARCH_I386) {
      break;
    }
  }
  test_assert(info.entry.nr == I386_write);
  /* (The kernel reports the upper halves of the registers too.) */
  test_assert((uint32_t)info.entry.args[0] == (uint32_t)fds[1]);
  test_assert((uint32_t)info.entry.args[2] == 5);

  /* Its exit */
  next_syscall_stop(child, 0, &info);
  test_assert(info.op == PTRACE_SYSCALL_INFO_EXIT);
  test_assert(info.arch == AUDIT_ARCH_I386);
  test_assert(info.exit.rval == 5);

  /* The kill() */
  next_syscall_stop(child, 0, &info);
  test_assert(info.op == PTRACE_SYSCALL_INFO_ENTRY);
  test_assert(info.arch == AUDIT_ARCH_I386);
  test_assert(info.entry.nr == I386_kill);
  next_syscall_stop(child, 0, &info);
  test_assert(info.op == PTRACE_SYSCALL_INFO_EXIT);
  test_assert(info.arch == AUDIT_ARCH_I386);
  test_assert(info.exit.rval == 0);

  /* The SIGUSR1 */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1);

  /* The rt_sigreturn() of its handler, which the kernel reports as an x86-64
     syscall at its exit too, after the int $0x80 */
  next_syscall_stop(child, SIGUSR1, &info);
  test_assert(info.op == PTRACE_SYSCALL_INFO_ENTRY);
  test_assert(info.arch == AUDIT_ARCH_X86_64);
  test_assert(info.entry.nr == SYS_rt_sigreturn);
  next_syscall_stop(child, 0, &info);
  test_assert(info.op == PTRACE_SYSCALL_INFO_EXIT);
  test_assert(info.arch == AUDIT_ARCH_X86_64);
  check_int80_before(child, info.instruction_pointer);
  finish_child(child, 0);

  /* Without PTRACE_O_TRACESYSGOOD, the kernel returns only the fields before
     entry at syscall stops. */
  child = fork_child(fds[1]);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  /* The entry of the write, the first i386 syscall, and its exit */
  do {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((SIGTRAP << 8) | 0x7f));
    memset(&info, 0xff, sizeof(info));
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info);
    test_assert(ret == (long)offsetof(struct ptrace_syscall_info, entry));
    test_assert(info.op == PTRACE_SYSCALL_INFO_NONE);
    test_assert(info.entry.nr == (uint64_t)-1);
  } while (info.arch != AUDIT_ARCH_I386);
  check_int80_before(child, info.instruction_pointer);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  memset(&info, 0xff, sizeof(info));
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info);
  test_assert(ret == (long)offsetof(struct ptrace_syscall_info, entry));
  test_assert(info.op == PTRACE_SYSCALL_INFO_NONE);
  test_assert(info.arch == AUDIT_ARCH_I386);
  test_assert(info.entry.nr == (uint64_t)-1);
  check_int80_before(child, info.instruction_pointer);
  /* The SIGUSR1 */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1);
  finish_child(child, SIGUSR1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
