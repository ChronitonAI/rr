/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal that becomes pending while the parent is entering fork() makes
   the kernel fail the fork with ERESTARTNOINTR. rr then re-enters the
   syscall itself, which stashes the signal, and the retried fork runs with
   the signal mask rr uses while a signal is stashed. The child must still
   get the parent's signal mask. A SIGALRM interval timer makes such signals
   likely. Each child stores to a read-only page, which its SIGSEGV handler
   makes writable (a write barrier), and checks its signal mask. */

#define NUM_FORKS 300

static char* page;
static size_t page_size;
static sigset_t parent_mask;

static void alarm_handler(__attribute__((unused)) int sig) {}

static void segv_handler(__attribute__((unused)) int sig, siginfo_t* si,
                         __attribute__((unused)) void* context) {
  if ((char*)si->si_addr != page ||
      mprotect(page, page_size, PROT_READ | PROT_WRITE)) {
    _exit(3);
  }
}

static int child(void) {
  sigset_t mask;
  int sig;

  *(volatile char*)page = 1;
  if (*(volatile char*)page != 1) {
    return 2;
  }
  if (sigprocmask(SIG_BLOCK, NULL, &mask)) {
    return 4;
  }
  for (sig = 1; sig < 32; ++sig) {
    if (sigismember(&mask, sig) != sigismember(&parent_mask, sig)) {
      return 1;
    }
  }
  return 0;
}

int main(void) {
  struct sigaction sa;
  struct itimerval timer = { { 0, 1000 }, { 0, 1000 } };
  int i;

  page_size = sysconf(_SC_PAGESIZE);
  page = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = segv_handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = alarm_handler;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGALRM, &sa, NULL));

  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &parent_mask));
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));

  for (i = 0; i < NUM_FORKS; ++i) {
    int status;
    pid_t ret;
    pid_t pid = fork();
    if (!pid) {
      _exit(child());
    }
    test_assert(pid > 0);
    do {
      ret = waitpid(pid, &status, 0);
    } while (ret < 0 && errno == EINTR);
    test_assert(ret == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
      atomic_printf("fork %d: child status 0x%x\n", i, status);
      test_assert(0);
    }
  }

  memset(&timer, 0, sizeof(timer));
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
