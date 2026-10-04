/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* A seccomp filter that traps an i386 syscall that an x86-64 process makes
   with int $0x80: the SIGSYS reports the i386 arch. Then filters that the
   process installs with the i386 prctl() and seccomp(), which take an i386
   struct sock_fprog. */

#if defined(__x86_64__)

#include <linux/audit.h>

#define I386_getppid 64
#define I386_prctl 172
#define I386_seccomp 354

struct i386_sock_fprog {
  uint16_t len;
  uint16_t padding;
  uint32_t filter;
};

static int sigsys_arch;
static int sigsys_syscall;

static void handler(int sig, siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
  test_assert(sig == SIGSYS);
  sigsys_arch = si->si_arch;
  sigsys_syscall = si->si_syscall;
  ctx->uc_mcontext.gregs[REG_RAX] = 42;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, I386_getpid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(0 == prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
}

/* Installs a filter that makes i386 syscall nr fail with errno err, with the
   i386 prctl() or seccomp() */
static void install_errno_filter_i386(int use_seccomp, long nr, int err) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | err),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  /* Below 4GB. The x86-64 struct sock_fprog would take its filter pointer
     from the 0xff bytes after the i386 one. */
  unsigned char* page = int80_low_alloc(4096);
  struct sock_filter* low_filter = (struct sock_filter*)page;
  struct i386_sock_fprog* prog =
      (struct i386_sock_fprog*)(page + sizeof(filter));
  long ret;

  memset(page, 0xff, 4096);
  memcpy(low_filter, filter, sizeof(filter));
  prog->len = sizeof(filter) / sizeof(filter[0]);
  prog->padding = 0;
  prog->filter = (uint32_t)(uintptr_t)low_filter;
  if (use_seccomp) {
    ret = int80_3(I386_seccomp, SECCOMP_SET_MODE_FILTER,
                  SECCOMP_FILTER_FLAG_TSYNC, LOW(prog));
  } else {
    ret = int80_3(I386_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, LOW(prog));
  }
  test_assert(ret == 0);
  munmap(page, 4096);
}

static int go_pipe[2];

static void* filtered_thread(__attribute__((unused)) void* p) {
  char c;
  test_assert(1 == read(go_pipe[0], &c, 1));
  /* The main thread's seccomp() synchronized all of its filters to this
     thread (SECCOMP_FILTER_FLAG_TSYNC) */
  test_assert(-78 == int80_0(I386_getppid));
  test_assert(-77 == int80_0(I386_gettid));
  return (void*)(long)prctl(PR_GET_SECCOMP);
}

int main(void) {
  struct sigaction sa;
  pid_t pid = getpid();
  pthread_t thread;
  void* thread_seccomp;

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  int80_setup();
  test_assert(0 == pipe(go_pipe));
  test_assert(0 == pthread_create(&thread, NULL, filtered_thread, NULL));
  install_filter();
  test_assert(42 == int80_0(I386_getpid));
  test_assert(sigsys_arch == AUDIT_ARCH_I386);
  test_assert(sigsys_syscall == I386_getpid);
  /* The x86-64 getpid (39, i386 mkdir) is not trapped */
  test_assert(pid == syscall(SYS_getpid));

  install_errno_filter_i386(0, I386_gettid, 77);
  test_assert(-77 == int80_0(I386_gettid));
  test_assert(pid == syscall(SYS_gettid));
  test_assert(42 == int80_0(I386_getpid));
  test_assert(getppid() == syscall(SYS_getppid));
  test_assert(getppid() == int80_0(I386_getppid));
  test_assert(2 == prctl(PR_GET_SECCOMP));

  install_errno_filter_i386(1, I386_getppid, 78);
  test_assert(-78 == int80_0(I386_getppid));
  test_assert(getppid() == syscall(SYS_getppid));
  test_assert(1 == write(go_pipe[1], "g", 1));
  test_assert(0 == pthread_join(thread, &thread_seccomp));
  test_assert(2 == (long)thread_seccomp);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
