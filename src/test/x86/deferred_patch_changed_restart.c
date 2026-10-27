/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread blocks in futex() waits made from 'mov $0xca,%eax;
   syscall', a site rr patches at the syscall's exit, since the patch
   region ends with the syscall instruction. Another thread interrupts each
   wait with a signal, and the futex() doesn't restart as it was:
   - At the first site, SIGUSR1's SA_RESTART handler changes the syscall
     number to getppid().
   - At the second site, SIGALRM's handler has no SA_RESTART, so the
     futex() fails with EINTR.
   - At the third site, SIGUSR1's handler changes the futex word, so the
     task makes a new futex() wait from the same instruction. SIGUSR2 then
     interrupts the new futex(), which restarts.
   - At the fourth site, SIGUSR1's handler moves the restart to another
     syscall instruction, which continues at the end of the site, and
     makes it a FUTEX_WAKE.
   Each site must return the last syscall's result, and rr must have
   patched each site when it returns. */

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

FUTEX_SITE(futex_site_new_syscall)
FUTEX_SITE(futex_site_no_restart)
FUTEX_SITE(futex_site_new_word)
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

enum TestCase { NEW_SYSCALL, NO_RESTART, NEW_WORD, MOVED };

static int word_a;
static int word_b;
static int other_word;
static pid_t main_tid;
static enum TestCase test_case;
static int usr2_count;

static void handle_usr1(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
  test_assert(ctx->uc_mcontext.gregs[REG_RAX] == SYS_futex);
  test_assert(ctx->uc_mcontext.gregs[REG_RDI] == (long)&word_a);
  switch (test_case) {
    case NEW_SYSCALL:
      ctx->uc_mcontext.gregs[REG_RAX] = SYS_getppid;
      break;
    case NEW_WORD:
      ctx->uc_mcontext.gregs[REG_RDI] = (long)&word_b;
      break;
    case MOVED:
      ctx->uc_mcontext.gregs[REG_RIP] = (long)moved_syscall;
      ctx->uc_mcontext.gregs[REG_RDI] = (long)&other_word;
      ctx->uc_mcontext.gregs[REG_RSI] = FUTEX_WAKE;
      ctx->uc_mcontext.gregs[REG_RDX] = 1;
      break;
    default:
      test_assert(0);
  }
}

static void handle_usr2(__attribute__((unused)) int sig) {
  __atomic_add_fetch(&usr2_count, 1, __ATOMIC_SEQ_CST);
}

static void handle_alrm(__attribute__((unused)) int sig) {}

static void* signal_thread(__attribute__((unused)) void* p) {
  wait_for_task_asleep_in_syscall(main_tid, SYS_futex, (long)&word_a);
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid,
                           test_case == NO_RESTART ? SIGALRM : SIGUSR1));
  if (test_case != NEW_WORD) {
    return NULL;
  }
  wait_for_task_asleep_in_syscall(main_tid, SYS_futex, (long)&word_b);
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR2));
  while (!__atomic_load_n(&usr2_count, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  /* The new futex() restarts after the SIGUSR2 handler. */
  wait_for_task_asleep_in_syscall(main_tid, SYS_futex, (long)&word_b);
  __atomic_store_n(&word_b, 1, __ATOMIC_SEQ_CST);
  test_assert(1 == syscall(SYS_futex, &word_b, FUTEX_WAKE, 1, NULL, NULL, 0));
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

static void check_patched(long (*futex_site)(int*, int, int), char* start,
                          int patched) {
  int i;
  /* A patched site starts with a jump to rr's stub. */
  if (patched) {
    test_assert((uint8_t)start[0] == 0xe9);
  }
  for (i = 0; i < 3; ++i) {
    test_assert(0 == futex_site(&other_word, FUTEX_WAKE, 1));
  }
}

int main(void) {
  struct sigaction sa;
  pthread_t thread;
  int patched = syscallbuf_enabled();

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_usr1;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_usr2;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGUSR2, &sa, NULL));
  sa.sa_handler = handle_alrm;
  sa.sa_flags = 0;
  test_assert(0 == sigaction(SIGALRM, &sa, NULL));
  main_tid = sys_gettid();

  test_case = NEW_SYSCALL;
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(getppid() == futex_site_new_syscall(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  check_patched(futex_site_new_syscall, futex_site_new_syscall_start, patched);

  test_case = NO_RESTART;
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(-EINTR == futex_site_no_restart(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  check_patched(futex_site_no_restart, futex_site_no_restart_start, patched);

  test_case = NEW_WORD;
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(0 == futex_site_new_word(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(__atomic_load_n(&usr2_count, __ATOMIC_SEQ_CST) == 1);
  check_patched(futex_site_new_word, futex_site_new_word_start, patched);

  test_case = MOVED;
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(0 == futex_site_moved(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  check_patched(futex_site_moved, futex_site_moved_start, patched);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
