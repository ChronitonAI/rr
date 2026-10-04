/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* i386 fork, clone, vfork and execve, made by an x86-64 process with
   int $0x80. */

#if defined(__x86_64__)

/* clone80_thread(flags, stack, ptid, tls, ctid, fn): an i386 clone whose
   child calls fn on the new stack and exits the thread with fn's result
   (i386 exit). Returns the child's tid in the parent. */
long clone80_thread(long flags, long stack, long ptid, long tls, long ctid,
                    int (*fn)(void));
__asm__(".text\n"
        ".globl clone80_thread\n"
        ".type clone80_thread, @function\n"
        "clone80_thread:\n"
        "  push %rbx\n"
        "  push %rbp\n"
        "  push %r12\n"
        "  mov %r9, %r12\n"
        "  mov %edi, %ebx\n"
        "  mov %rcx, %rax\n"
        "  mov %esi, %ecx\n"
        "  mov %eax, %esi\n"
        "  mov %r8d, %edi\n"
        "  mov $120, %eax\n"
        "  int $0x80\n"
        "  test %eax, %eax\n"
        "  jz 1f\n"
        "  pop %r12\n"
        "  pop %rbp\n"
        "  pop %rbx\n"
        "  movslq %eax, %rax\n"
        "  ret\n"
        "1:\n"
        "  xor %ebp, %ebp\n"
        "  and $-16, %rsp\n"
        "  call *%r12\n"
        "  mov %eax, %ebx\n"
        "  mov $1, %eax\n"
        "  int $0x80\n"
        "  hlt\n"
        ".size clone80_thread, .-clone80_thread\n");

/* vfork80_execve(path, argv, envp): an i386 vfork whose child makes an i386
   execve (and exits with 77 if that fails). Returns the child's pid. */
long vfork80_execve(long path, long argv, long envp);
__asm__(".text\n"
        ".globl vfork80_execve\n"
        ".type vfork80_execve, @function\n"
        "vfork80_execve:\n"
        "  push %rbx\n"
        "  push %r12\n"
        "  push %r13\n"
        "  push %r14\n"
        "  mov %rdi, %r12\n"
        "  mov %rsi, %r13\n"
        "  mov %rdx, %r14\n"
        "  mov $190, %eax\n"
        "  int $0x80\n"
        "  test %eax, %eax\n"
        "  jz 1f\n"
        "  pop %r14\n"
        "  pop %r13\n"
        "  pop %r12\n"
        "  pop %rbx\n"
        "  movslq %eax, %rax\n"
        "  ret\n"
        "1:\n"
        "  mov %r12d, %ebx\n"
        "  mov %r13d, %ecx\n"
        "  mov %r14d, %edx\n"
        "  mov $11, %eax\n"
        "  int $0x80\n"
        "  mov $77, %ebx\n"
        "  mov $1, %eax\n"
        "  int $0x80\n"
        "  hlt\n"
        ".size vfork80_execve, .-vfork80_execve\n");

static int fds[2];

static int thread_fn(void) {
  char* msg = int80_low_alloc(4096);
  strcpy(msg, "thread");
  test_assert(6 == int80_3(I386_write, fds[1], LOW(msg), 6));
  return 0;
}

static void check_exit(pid_t child, int code) {
  int* status = int80_low_alloc(4096);
  test_assert(child == int80_3(I386_waitpid, child, LOW(status), 0));
  test_assert(WIFEXITED(*status) && WEXITSTATUS(*status) == code);
}

int main(int argc, char** argv) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* low = int80_low_alloc(page_size);
  int* ptid = (int*)low;
  int* ctid = (int*)(low + 64);
  char* stack;
  char buf[16];
  uint32_t* exec_argv = (uint32_t*)(low + 128);
  uint32_t* exec_envp = (uint32_t*)(low + 192);
  char* path = low + 256;
  char* arg1 = low + 1024;
  pid_t child;
  long tid;

  if (argc == 2) {
    test_assert(0 == strcmp(argv[1], "--inner"));
    return 33;
  }

  int80_setup();
  test_assert(0 == pipe(fds));

  /* fork */
  child = int80_0(I386_fork);
  if (!child) {
    _exit(11);
  }
  test_assert(child > 0);
  check_exit(child, 11);

  /* clone like fork, writing the child's tid to both processes */
  *ptid = *ctid = 0;
  child =
      int80_5(I386_clone, SIGCHLD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID, 0,
              LOW(ptid), 0, LOW(ctid));
  if (!child) {
    _exit(*ctid == sys_gettid() ? 22 : 1);
  }
  test_assert(child > 0);
  test_assert(*ptid == child);
  test_assert(*ctid == 0);
  check_exit(child, 22);

  /* clone of a thread, which clears *ctid when it exits */
  stack = int80_low_alloc(16 * page_size);
  *ptid = 0;
  *ctid = -1;
  tid = clone80_thread(
      CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
          CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
      LOW(stack + 16 * page_size), LOW(ptid), 0, LOW(ctid), thread_fn);
  test_assert(tid > 0);
  test_assert(*ptid == tid);
  test_assert(6 == read(fds[0], buf, sizeof(buf)));
  test_assert(0 == memcmp(buf, "thread", 6));
  while (1) {
    int v = *(volatile int*)ctid;
    if (!v) {
      break;
    }
    syscall(SYS_futex, ctid, FUTEX_WAIT, v, NULL, NULL, 0);
  }

  /* vfork and execve */
  test_assert(readlink("/proc/self/exe", path, 512) > 0);
  strcpy(arg1, "--inner");
  exec_argv[0] = LOW(path);
  exec_argv[1] = LOW(arg1);
  exec_argv[2] = 0;
  exec_envp[0] = 0;
  child = vfork80_execve(LOW(path), LOW(exec_argv), LOW(exec_envp));
  test_assert(child > 0);
  check_exit(child, 33);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
