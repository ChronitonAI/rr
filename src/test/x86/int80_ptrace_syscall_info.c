/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* PTRACE_GET_SYSCALL_INFO at the entry and the exit of i386 syscalls that
   an x86-64 tracee makes with int $0x80, and of the x86-64 rt_sigreturn()
   of a handler of a signal that one of them sends, which returns to the
   instruction after the int $0x80. */

#if defined(__x86_64__) && defined(PTRACE_GET_SYSCALL_INFO)

#include <linux/audit.h>
#include <linux/ptrace.h>

#define I386_kill 37

static volatile int handled;

static void handler(__attribute__((unused)) int sig) { handled = 1; }

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
  if (0 == (child = fork())) {
    char* buf;
    pid_t self = getpid();
    int80_setup();
    buf = int80_low_alloc(4096);
    strcpy(buf, "hello");
    signal(SIGUSR1, handler);
    kill(self, SIGSTOP);
    test_assert(5 == int80_3(I386_write, fds[1], LOW(buf), 5));
    test_assert(0 == int80_2(I386_kill, self, SIGUSR1));
    test_assert(handled);
    return 77;
  }

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
  errno = 0;
  ret = ptrace(PTRACE_PEEKDATA, child, (void*)(info.instruction_pointer - 2),
               NULL);
  test_assert(errno == 0);
  test_assert((ret & 0xffff) == 0x80cd);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
