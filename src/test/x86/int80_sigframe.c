/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal handler installed with an i386 rt_sigaction() (int $0x80).
   In the 64-bit build, the kernel (since Linux 4.9) runs the handler in 32-bit
   compatibility mode with an i386 signal frame, and the i386 rt_sigreturn()
   returns to 64-bit mode, restoring only the lower halves of the registers. So
   the handler is 32-bit code, and the code that the signal interrupts and its
   stack are below 4GB, all at a fixed address. rr doesn't support this, and
   int80_sigframe.run checks that the recording stops cleanly. */

#define I386_rt_sigaction 174
#define I386_SA_RESTORER 0x04000000

struct i386_sigaction {
  uint32_t handler;
  uint32_t flags;
  uint32_t restorer;
  uint32_t mask[2];
};

#if defined(__x86_64__)

#define LOW 0x31000000UL
/* Results of the handler: sig, si_signo, the interrupted ip, cs, count */
#define RESULTS (LOW + 0x800)
#define SAVED_RSP (LOW + 0x900)
#define ACT (LOW + 0xa00)

extern char code_start[], code_end[], handler32[], restorer32[],
    raise_on_low_stack[], after_tgkill[];
__asm__(".text\n"
        ".globl code_start, code_end, handler32, restorer32\n"
        ".globl raise_on_low_stack, after_tgkill\n"
        "code_start:\n"
        ".code32\n"
        "handler32:\n"
        "  mov 4(%esp), %eax\n"
        "  mov %eax, 0x31000800\n"
        "  mov 8(%esp), %eax\n"
        "  mov (%eax), %eax\n"
        "  mov %eax, 0x31000804\n"
        /* uc->uc_mcontext.ip */
        "  mov 12(%esp), %eax\n"
        "  mov 76(%eax), %ecx\n"
        "  mov %ecx, 0x31000808\n"
        "  mov %cs, %eax\n"
        "  mov %eax, 0x3100080c\n"
        "  incl 0x31000810\n"
        "  ret\n"
        "restorer32:\n"
        "  mov $173, %eax\n" /* i386 rt_sigreturn */
        "  int $0x80\n"
        "  hlt\n"
        ".code64\n"
        /* raise_on_low_stack(tgid, tid, sig): tgkill() on a stack below 4GB.
           The handler's rt_sigreturn() zero-extends rbx and rbp, so save
           the callee-saved registers. */
        "raise_on_low_stack:\n"
        "  push %rbx\n"
        "  push %rbp\n"
        "  push %r12\n"
        "  push %r13\n"
        "  push %r14\n"
        "  push %r15\n"
        "  mov %rsp, 0x31000900\n"
        "  mov $0x31010000, %esp\n"
        "  mov $234, %eax\n" /* tgkill */
        "  syscall\n"
        "after_tgkill:\n"
        "  mov 0x31000900, %rsp\n"
        "  pop %r15\n"
        "  pop %r14\n"
        "  pop %r13\n"
        "  pop %r12\n"
        "  pop %rbp\n"
        "  pop %rbx\n"
        "  ret\n"
        "code_end:\n");

#define ADDR(sym) ((uintptr_t)(sym) - (uintptr_t)code_start + LOW)

int main(void) {
  uint8_t* low = mmap((void*)LOW, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  struct i386_sigaction* act = (struct i386_sigaction*)ACT;
  uint32_t* results = (uint32_t*)RESULTS;
  void (*raise_low)(long, long, long);
  long ret;

  test_assert(low == (uint8_t*)LOW);
  memcpy(low, code_start, code_end - code_start);
  memset(act, 0, sizeof(*act));
  act->handler = ADDR(handler32);
  act->flags = SA_SIGINFO | I386_SA_RESTORER;
  act->restorer = ADDR(restorer32);
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "0"((long)I386_rt_sigaction), "b"((long)SIGUSR1),
                         "c"((long)ACT), "d"(0L), "S"(8L)
                       : "memory");
  test_assert(ret == 0);

  raise_low = (void (*)(long, long, long))ADDR(raise_on_low_stack);
  raise_low(getpid(), sys_gettid(), SIGUSR1);

  test_assert(results[0] == SIGUSR1);
  test_assert(results[1] == SIGUSR1);
  test_assert(results[2] == ADDR(after_tgkill));
  /* The handler ran with the 32-bit user code segment */
  test_assert(results[3] == 0x23);
  test_assert(results[4] == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

static volatile int caught;

static void handler(int sig, siginfo_t* si, __attribute__((unused)) void* uc) {
  test_assert(sig == SIGUSR1);
  test_assert(si->si_signo == SIGUSR1);
  ++caught;
}

extern char restorer[];
__asm__(".text\n"
        ".globl restorer\n"
        "restorer:\n"
        "  mov $173, %eax\n"
        "  int $0x80\n"
        "  hlt\n");

int main(void) {
  struct i386_sigaction act;
  long ret;

  memset(&act, 0, sizeof(act));
  act.handler = (uint32_t)(uintptr_t)handler;
  act.flags = SA_SIGINFO | I386_SA_RESTORER;
  act.restorer = (uint32_t)(uintptr_t)restorer;
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "0"((long)I386_rt_sigaction), "b"((long)SIGUSR1),
                         "c"(&act), "d"(0L), "S"(8L)
                       : "memory");
  test_assert(ret == 0);
  raise(SIGUSR1);
  test_assert(caught == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
