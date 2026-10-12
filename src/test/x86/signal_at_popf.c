/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A popf faults because the stack pointer points to an inaccessible page.
   The SIGSEGV handler, which runs on an alternate stack, makes the page
   accessible, so the popf succeeds when the handler returns. The signal
   arrives with the ip at the popf, but the trap flag (TF) isn't set, so the
   handler's context must not have TF set either. */

#define TF 0x100

static char* page;
static size_t page_size;
static volatile int handled;

static void make_page_accessible(void) {
  test_assert(0 == mprotect(page, page_size, PROT_READ | PROT_WRITE));
  ++handled;
}

static void handler(__attribute__((unused)) int sig) { make_page_accessible(); }

static void siginfo_handler(__attribute__((unused)) int sig,
                            __attribute__((unused)) siginfo_t* si,
                            void* context) {
  ucontext_t* uc = context;
  test_assert(!(uc->uc_mcontext.gregs[REG_EFL] & TF));
  make_page_accessible();
}

static void popf_with_sp_at(char* sp) {
#ifdef __x86_64__
  __asm__ __volatile__("mov %%rsp, %%rsi\n\t"
                       "mov %0, %%rsp\n\t"
                       "popfq\n\t"
                       "mov %%rsi, %%rsp\n\t"
                       :
                       : "r"(sp)
                       : "rsi", "memory", "cc");
#else
  __asm__ __volatile__("mov %%esp, %%esi\n\t"
                       "mov %0, %%esp\n\t"
                       "popfl\n\t"
                       "mov %%esi, %%esp\n\t"
                       :
                       : "r"(sp)
                       : "esi", "memory", "cc");
#endif
}

static void run(int flags, void (*h)(int), void (*sh)(int, siginfo_t*, void*)) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_ONSTACK | flags;
  if (sh) {
    sa.sa_sigaction = sh;
  } else {
    sa.sa_handler = h;
  }
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  test_assert(0 == mprotect(page, page_size, PROT_NONE));
  handled = 0;
  popf_with_sp_at(page + 64);
  test_assert(handled == 1);
}

int main(void) {
  stack_t ss;
  ss.ss_sp = malloc(SIGSTKSZ * 4);
  ss.ss_size = SIGSTKSZ * 4;
  ss.ss_flags = 0;
  test_assert(ss.ss_sp != NULL);
  test_assert(0 == sigaltstack(&ss, NULL));
  page_size = sysconf(_SC_PAGESIZE);
  page = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);

  run(SA_SIGINFO, NULL, siginfo_handler);
  /* On 32-bit x86, this handler gets a non-rt signal frame. */
  run(0, handler, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
