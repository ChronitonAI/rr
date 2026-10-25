/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread blocks in a futex() wait made from 'mov $0xca,%eax;
   syscall', a site rr patches at the syscall's exit, since the patch
   region ends with the syscall instruction. Another thread interrupts the
   futex() with a signal whose SA_RESTART handler installs a seccomp filter
   that refuses futex()es of that word: with SECCOMP_RET_ERRNO at the first
   such site, with SECCOMP_RET_TRAP at the second, and with
   SECCOMP_RET_ERRNO at the third, where the handler also moves the restart
   to another syscall instruction, which continues at the end of the site.
   The futex() restarts and fails. rr must record that and patch each site:
   the third before the futex() returns, the others at a later syscall made
   there. */

#if defined(__x86_64__)

/* Each site starts a 256-byte block, so that rr's check for branches into
   the patch region doesn't find bytes of the next function that look like
   one. */
#define FUTEX_SITE(name)                                                     \
  extern char name##_start[] __attribute__((visibility("hidden")));        \
  static __attribute__((noinline, aligned(256))) long name(                \
      int* uaddr, int op, int val) {                                       \
    long ret;                                                              \
    register long r10 __asm__("r10") = 0;                                  \
    __asm__ volatile(#name "_start:\n\t"                                   \
                     "mov $0xca,%%eax\n\t"                                 \
                     "syscall\n\t"                                         \
                     #name "_end:\n\t"                                     \
                     /* Match no hook pattern with the following bytes */ \
                     "cmp $0x77,%%rax\n\t"                                 \
                     : "=a"(ret)                                           \
                     : "D"(uaddr), "S"((long)op), "d"((long)val), "r"(r10) \
                     : "rcx", "r11", "flags", "memory");                   \
    return ret;                                                            \
  }

FUTEX_SITE(futex_site_errno)
FUTEX_SITE(futex_site_trap)
FUTEX_SITE(futex_site_moved)

/* A syscall instruction outside the sites, which continues at the end of
   futex_site_moved. rr looks for hooks in the bytes around a syscall
   instruction; the ud2 before this one and the jmp after it match none. */
extern char moved_syscall[] __attribute__((visibility("hidden")));
__asm__(".pushsection .text\n\t"
        "ud2\n"
        "moved_syscall:\n\t"
        "syscall\n\t"
        "jmp futex_site_moved_end\n\t"
        ".popsection\n\t");

static int futex_words[3];
static int other_word;
static pid_t main_tid;
static int* filter_word;
static uint32_t filter_action;
static int move_restart;
static volatile int sigsys_count;

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex, 0, 5),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(uintptr_t)filter_word, 0,
             3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0]) + sizeof(uint32_t)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
             (uint32_t)((uintptr_t)filter_word >> 32), 0, 1),
    BPF_STMT(BPF_RET | BPF_K, filter_action),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  test_assert(0 == syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog));
}

static void handle_usr1(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
  install_filter();
  if (move_restart) {
    ctx->uc_mcontext.gregs[REG_RIP] = (long)moved_syscall;
  }
}

static void handle_sigsys(__attribute__((unused)) int sig, siginfo_t* si,
                          void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
  test_assert(si->si_syscall == SYS_futex);
  ctx->uc_mcontext.gregs[REG_RAX] = -E2BIG;
  ++sigsys_count;
}

static void* signal_thread(__attribute__((unused)) void* p) {
  wait_for_task_asleep_in_syscall(main_tid, SYS_futex, (long)filter_word);
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1));
  return NULL;
}

typedef void* (*SyscallbufPtr)(void);

/* rr patches syscall sites when it records with the syscall buffer, i.e.
   when its preload library gave this thread a syscall buffer. */
static int syscallbuf_enabled(void) {
  SyscallbufPtr syscallbuf_ptr =
      (SyscallbufPtr)dlsym(RTLD_DEFAULT, "syscallbuf_ptr");
  return syscallbuf_ptr && syscallbuf_ptr();
}

static void run_test(long (*futex_site)(int*, int, int), char* start,
                     int* word, uint32_t action, int moved, int patched) {
  pthread_t thread;
  int i;

  filter_word = word;
  filter_action = action;
  move_restart = moved;
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(-E2BIG == futex_site(word, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  /* A patched site starts with a jump to rr's stub. */
  if (patched && moved) {
    test_assert((uint8_t)start[0] == 0xe9);
  }
  /* rr patches the other sites at the first of these syscalls' exit. */
  for (i = 0; i < 3; ++i) {
    test_assert(0 == futex_site(&other_word, FUTEX_WAKE, 1));
  }
  if (patched) {
    test_assert((uint8_t)start[0] == 0xe9);
  }
}

int main(void) {
  struct sigaction sa;
  int patched = syscallbuf_enabled();

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_usr1;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  sa.sa_sigaction = handle_sigsys;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSYS, &sa, NULL));
  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  main_tid = sys_gettid();

  run_test(futex_site_errno, futex_site_errno_start, &futex_words[0],
           SECCOMP_RET_ERRNO | E2BIG, 0, patched);
  test_assert(sigsys_count == 0);
  run_test(futex_site_trap, futex_site_trap_start, &futex_words[1],
           SECCOMP_RET_TRAP, 0, patched);
  test_assert(sigsys_count == 1);
  run_test(futex_site_moved, futex_site_moved_start, &futex_words[2],
           SECCOMP_RET_ERRNO | E2BIG, 1, patched);
  test_assert(sigsys_count == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
