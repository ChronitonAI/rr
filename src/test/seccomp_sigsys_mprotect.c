/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A seccomp filter traps a buffered mprotect(), so it must not change the
   protection of the memory, in recording or replay. */

static volatile int sigsys_count;

static void handler(int sig, __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
  test_assert(sig == SIGSYS);
  ++sigsys_count;
#ifdef __i386__
  ctx->uc_mcontext.gregs[REG_EAX] = -EPERM;
#elif defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RAX] = -EPERM;
#elif defined(__aarch64__)
  ctx->uc_mcontext.regs[0] = -EPERM;
#else
#error define architecture here
#endif
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 3 instructions if system call number
       is not SYS_mprotect */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect, 0, 3),
    /* Load prot argument from `seccomp_data` buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
    /* Jump forward 1 instruction if prot is not PROT_NONE */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_NONE, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Allow other system calls */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

int main(void) {
  struct sigaction sa;
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  int* p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  *p = 42;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSYS, &sa, NULL));

  /* Trigger syscall patching for mprotect. */
  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_WRITE));

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();

  test_assert(-1 == mprotect(p, page_size, PROT_NONE));
  test_assert(errno == EPERM);
  test_assert(sigsys_count == 1);
  test_assert(*(volatile int*)p == 42);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
