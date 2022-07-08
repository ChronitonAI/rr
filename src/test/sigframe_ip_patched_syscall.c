/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal interrupts a blocking read() from a patched syscall site, which
   rr performs in the site's extended jump patch. The signal frame must show
   an ip in the patched code (a named mapping), not in the extended jump
   patch (an anonymous mapping). On i386, also check the frame of a handler
   without SA_SIGINFO, whose layout differs. */

static int pipefds[2];
static pid_t main_tid;
static uintptr_t frame_ip;
static int handled;

struct mapping_lookup {
  uint64_t addr;
  char* name;
  size_t size;
  int found;
};

static void find_mapping(uint64_t env, char* name, map_properties_t* props) {
  struct mapping_lookup* lookup = (struct mapping_lookup*)(uintptr_t)env;
  if (props->start <= lookup->addr && lookup->addr < props->end) {
    snprintf(lookup->name, lookup->size, "%s", name);
    lookup->found = 1;
  }
}

/* Return the name of the mapping containing |addr|, which is empty for an
   anonymous mapping. */
static void mapping_name(uintptr_t addr, char* name, size_t size) {
  struct mapping_lookup lookup = { addr, name, size, 0 };
  FILE* maps_file = fopen("/proc/self/maps", "r");
  test_assert(maps_file != NULL);
  iterate_maps((uintptr_t)&lookup, find_mapping, maps_file);
  test_assert(0 == fclose(maps_file));
  test_assert(lookup.found && "ip not mapped");
}

static void siginfo_handler(__attribute__((unused)) int sig,
                            __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
#if defined(__i386__)
  uintptr_t ip = ctx->uc_mcontext.gregs[REG_EIP];
#elif defined(__x86_64__)
  uintptr_t ip = ctx->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
  uintptr_t ip = ctx->uc_mcontext.pc;
#else
#error define architecture here
#endif
  __atomic_store_n(&frame_ip, ip, __ATOMIC_SEQ_CST);
  __atomic_store_n(&handled, 1, __ATOMIC_SEQ_CST);
}

#ifdef __i386__
static void plain_handler(int sig) {
  /* Without SA_SIGINFO, the frame has a struct sigcontext right after the
     signal number. */
  int* sig_ptr = &sig;
  struct sigcontext* sc;
  __asm__("" : "+r"(sig_ptr));
  sc = (struct sigcontext*)(sig_ptr + 1);
  __atomic_store_n(&frame_ip, sc->eip, __ATOMIC_SEQ_CST);
  __atomic_store_n(&handled, 1, __ATOMIC_SEQ_CST);
}
#endif

static void* signaler_thread(__attribute__((unused)) void* p) {
  pid_t tid = __atomic_load_n(&main_tid, __ATOMIC_SEQ_CST);
  test_assert(tid > 1);
  /* Wait until the main thread is blocked in its read(). */
  wait_for_task_asleep_in_syscall(tid, SYS_read, pipefds[0]);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR1));
  while (!__atomic_load_n(&handled, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(1 == write(pipefds[1], "x", 1));
  return NULL;
}

static void check_frame_ip(struct sigaction* sa) {
  pthread_t thread;
  char name[1000];
  char ch;
  uintptr_t ip;

  test_assert(0 == sigaction(SIGUSR1, sa, NULL));
  __atomic_store_n(&handled, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&frame_ip, 0, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, signaler_thread, NULL));
  test_assert(1 == read(pipefds[0], &ch, 1));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(__atomic_load_n(&handled, __ATOMIC_SEQ_CST));
  ip = __atomic_load_n(&frame_ip, __ATOMIC_SEQ_CST);
  mapping_name(ip, name, sizeof(name));
  atomic_printf("frame ip %p in '%s'\n", (void*)ip, name);
  test_assert(name[0] != 0);
}

int main(void) {
  struct sigaction sa;
  char ch;

  test_assert(0 == pipe(pipefds));
  __atomic_store_n(&main_tid, sys_gettid(), __ATOMIC_SEQ_CST);

  /* Trigger syscall patching for read. */
  test_assert(1 == write(pipefds[1], "x", 1));
  test_assert(1 == read(pipefds[0], &ch, 1));

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = siginfo_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  check_frame_ip(&sa);

#ifdef __i386__
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = plain_handler;
  sa.sa_flags = SA_RESTART;
  check_frame_ip(&sa);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
