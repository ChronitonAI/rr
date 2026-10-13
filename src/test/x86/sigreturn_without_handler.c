/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Test an rt_sigreturn that doesn't end a signal handler: the program saves a
   copy of a signal frame in its handler, the handler returns normally, and
   then the program executes rt_sigreturn on the copy, to switch to another
   context. (DynamoRIO delivers signals to an application's handler like this,
   on a frame it builds itself after its own handler has returned.) */

static volatile int handler_ran;

static struct {
#ifdef __i386__
  /* rt_sigreturn finds the frame 4 bytes below the stack pointer; the
     ucontext is 144 bytes into it. */
  char frame_head[144];
#endif
  ucontext_t uc;
} frame_copy __attribute__((aligned(64)));

static char landing_stack[65536] __attribute__((aligned(16)));

static void landing(void) {
  test_assert(handler_ran);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

static void handler(__attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* uc = &frame_copy.uc;
  uintptr_t sp = (uintptr_t)(landing_stack + sizeof(landing_stack));

  /* The kernel's ucontext, which ends with a 64-bit signal mask. */
  memcpy(uc, p, offsetof(ucontext_t, uc_sigmask) + sizeof(uint64_t));
  /* No FPU state: rt_sigreturn resets it. */
  uc->uc_mcontext.fpregs = NULL;
#ifdef __x86_64__
  uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)landing;
  /* As if `landing` had been called. */
  uc->uc_mcontext.gregs[REG_RSP] = sp - sizeof(void*);
#else
  uc->uc_mcontext.gregs[REG_EIP] = (uintptr_t)landing;
  uc->uc_mcontext.gregs[REG_ESP] = sp - sizeof(void*);
#endif
  handler_ran = 1;
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  raise(SIGUSR1);
  test_assert(handler_ran);

  /* The handler has returned. Switch to the saved context. */
#ifdef __x86_64__
  __asm__ __volatile__("mov %0, %%rsp\n\t"
                       "syscall\n\t"
                       "ud2\n\t"
                       :
                       : "r"(&frame_copy.uc), "a"(SYS_rt_sigreturn)
                       : "memory");
#else
  __asm__ __volatile__("mov %0, %%esp\n\t"
                       "int $0x80\n\t"
                       "ud2\n\t"
                       :
                       : "r"(frame_copy.frame_head + 4), "a"(SYS_rt_sigreturn)
                       : "memory");
#endif
  test_assert(0 && "rt_sigreturn returned");
  return 1;
}
