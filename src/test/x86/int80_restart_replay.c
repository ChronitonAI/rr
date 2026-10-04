/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "../util_internal.h"
#include "int80_util.h"

/* A process-directed signal interrupts the main thread's i386 nanosleep()
   (int $0x80; from an x86-64 process in the 64-bit build), and another
   thread takes the signal. The kernel then restarts the nanosleep() without
   running a handler: it backs up the ip to the syscall instruction and sets
   eax to the i386 restart_syscall's number, 0. By then, the page with the
   syscall instruction isn't executable, so the main thread gets a SIGSEGV
   right there. The handler checks the restarted state, and skips the
   restarted nanosleep(), which would sleep for a very long time. During
   replay, the debugger script checks the restarted state too, before the
   handler runs.
   The main thread is frozen (an rr feature) while the other thread takes the
   signal and changes the page, so this only works under rr. */

#if defined(__x86_64__)
#define REG_IP REG_RIP
#define REG_AX REG_RAX
/* push %rbx; mov %edi, %ebx; xor %ecx, %ecx; mov $162, %eax; int $0x80;
   pop %rbx; ret */
static const uint8_t code[] = { 0x53, 0x89, 0xfb, 0x31, 0xc9, 0xb8, 0xa2,
                                0x00, 0x00, 0x00, 0xcd, 0x80, 0x5b, 0xc3 };
#define SYSCALL_OFFSET 10
#else
#define REG_IP REG_EIP
#define REG_AX REG_EAX
/* push %ebx; mov 8(%esp), %ebx; xor %ecx, %ecx; mov $162, %eax;
   int $0x80; pop %ebx; ret */
static const uint8_t code[] = {
  0x53, 0x8b, 0x5c, 0x24, 0x08, 0x31, 0xc9, 0xb8,
  0xa2, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x5b, 0xc3
};
#define SYSCALL_OFFSET 12
#endif

static uint8_t* code_page;
/* The syscall instruction, for the debugger script */
uint8_t* syscall_insn;
static size_t page_size;
static pid_t main_tid;
static int segvs;

static void handle_usr1(__attribute__((unused)) int sig) {
  test_assert(0 && "The other thread should have taken SIGUSR1");
}

static void handle_segv(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
  test_assert((uint8_t*)ctx->uc_mcontext.gregs[REG_IP] ==
              code_page + SYSCALL_OFFSET);
  test_assert((uint32_t)ctx->uc_mcontext.gregs[REG_AX] == 0);
  ++segvs;
  test_assert(0 == mprotect(code_page, page_size, PROT_READ | PROT_EXEC));
  /* Skip the restarted nanosleep(), returning 0 */
  ctx->uc_mcontext.gregs[REG_IP] += 2;
  ctx->uc_mcontext.gregs[REG_AX] = 0;
}

static void* taker_thread(__attribute__((unused)) void* p) {
  sigset_t set;
  siginfo_t si;
  int80_wait_for_blocked_syscall(main_tid, I386_nanosleep);
  /* Keep rr from resuming the main thread after the signal interrupts its
     nanosleep(). */
  rr_freeze_tid(main_tid, 1);
  /* The kernel picks the main thread, which doesn't block SIGUSR1, to wake
     up for it. */
  kill(getpid(), SIGUSR1);
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  test_assert(SIGUSR1 == sigwaitinfo(&set, &si));
  test_assert(0 == mprotect(code_page, page_size, PROT_READ));
  rr_freeze_tid(main_tid, 0);
  return NULL;
}

int main(void) {
  struct timespec* ts;
  int (*nanosleep_on_page)(uint32_t);
  struct sigaction sa;
  sigset_t set;
  pthread_t thread;

  if (!running_under_rr()) {
    atomic_puts("WARNING: This test only works under rr.");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  page_size = sysconf(_SC_PAGESIZE);
  code_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(code_page != MAP_FAILED);
  memcpy(code_page, code, sizeof(code));
  test_assert(0 == mprotect(code_page, page_size, PROT_READ | PROT_EXEC));
  nanosleep_on_page = (int (*)(uint32_t))code_page;
  syscall_insn = code_page + SYSCALL_OFFSET;
  /* An i386 timespec (two 32-bit fields) below 4GB, of 1000 seconds: the
     signal interrupts the nanosleep() */
  ts = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  test_assert(ts != MAP_FAILED);
  ((int32_t*)ts)[0] = 1000;
  ((int32_t*)ts)[1] = 0;

  signal(SIGUSR1, handle_usr1);
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_segv;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);

  main_tid = sys_gettid();
  /* The other thread blocks SIGUSR1. */
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  pthread_sigmask(SIG_BLOCK, &set, NULL);
  pthread_create(&thread, NULL, taker_thread, NULL);
  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  test_assert(0 == nanosleep_on_page((uint32_t)(uintptr_t)ts));
  test_assert(segvs == 1);
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
