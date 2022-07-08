/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal interrupts a blocking read() from a patched syscall site, which
   rr performs in the site's extended jump patch. The signal frame must show
   an ip in the patched code (a named mapping), not in the extended jump
   patch (an anonymous mapping). On i386, also check the frame of a handler
   without SA_SIGINFO, whose layout differs. */

static int pipefds[2];
static volatile pid_t main_tid;
static volatile uintptr_t frame_ip;
static volatile int handled;

static char task_state(pid_t tid) {
  char path[100];
  char buf[1000];
  char* p;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/stat", tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  /* The state follows the command name in parentheses. */
  p = strrchr(buf, ')');
  test_assert(p && p[1] == ' ');
  return p[2];
}

/* Return the name of the mapping containing |addr|, which is empty for an
   anonymous mapping. */
static void mapping_name(uintptr_t addr, char* name, size_t size) {
  FILE* f = fopen("/proc/self/maps", "r");
  char line[1000];
  test_assert(f != NULL);
  while (fgets(line, sizeof(line), f)) {
    unsigned long start;
    unsigned long end;
    int name_start = 0;
    char* nl;
    test_assert(2 == sscanf(line, "%lx-%lx %*s %*s %*s %*s %n", &start, &end,
                            &name_start));
    if (start <= addr && addr < end) {
      nl = strchr(line + name_start, '\n');
      if (nl) {
        *nl = 0;
      }
      snprintf(name, size, "%s", line + name_start);
      test_assert(0 == fclose(f));
      return;
    }
  }
  test_assert(0 && "ip not mapped");
}

static void siginfo_handler(__attribute__((unused)) int sig,
                            __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
#if defined(__i386__)
  frame_ip = ctx->uc_mcontext.gregs[REG_EIP];
#elif defined(__x86_64__)
  frame_ip = ctx->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
  frame_ip = ctx->uc_mcontext.pc;
#else
#error define architecture here
#endif
  handled = 1;
}

#ifdef __i386__
static void plain_handler(int sig) {
  /* Without SA_SIGINFO, the frame has a struct sigcontext right after the
     signal number. */
  int* sig_ptr = &sig;
  struct sigcontext* sc;
  __asm__("" : "+r"(sig_ptr));
  sc = (struct sigcontext*)(sig_ptr + 1);
  frame_ip = sc->eip;
  handled = 1;
}
#endif

static void* signaler_thread(__attribute__((unused)) void* p) {
  /* Wait until the main thread is blocked in its read(). */
  while (task_state(main_tid) != 'S') {
    sched_yield();
  }
  test_assert(0 == syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1));
  while (!handled) {
    sched_yield();
  }
  test_assert(1 == write(pipefds[1], "x", 1));
  return NULL;
}

static void check_frame_ip(struct sigaction* sa) {
  pthread_t thread;
  char name[1000];
  char ch;

  test_assert(0 == sigaction(SIGUSR1, sa, NULL));
  handled = 0;
  frame_ip = 0;
  test_assert(0 == pthread_create(&thread, NULL, signaler_thread, NULL));
  test_assert(1 == read(pipefds[0], &ch, 1));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(handled);
  mapping_name(frame_ip, name, sizeof(name));
  atomic_printf("frame ip %p in '%s'\n", (void*)frame_ip, name);
  test_assert(name[0] != 0);
}

int main(void) {
  struct sigaction sa;
  char ch;

  test_assert(0 == pipe(pipefds));
  main_tid = sys_gettid();

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
