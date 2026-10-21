/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/bpf.h>
#include <linux/perf_event.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

/* Modes, run by uprobe_from_outside.run:
   offset
     Prints the offset of uretprobed_function in this executable.
   tracepoint ID
     Tries to open a perf event for the tracepoint ID, a uprobe trace
     event on uretprobed_function in this executable. rr must refuse it.
   recorded KIND PID_FIFO GO_FIFO
     Writes our pid to PID_FIFO and waits for a byte from GO_FIFO: 'g' when
     the helper has attached a uprobe of kind KIND to us, or 's' when it
     couldn't. Then calls the probed function (and for nop grows the heap)
     and makes a syscall.
   helper KIND PID_FIFO GO_FIFO
     Runs outside the recording. Attaches a uprobe to the recorded process
     and keeps it attached until that process exits. KIND is
     - uretprobe: a return probe on uretprobed_function,
     - nop: a probe on a nop in nop_function that the kernel turns into a
       call to a trampoline after the first hit (x86-64 only),
     - signal: a return probe on uretprobed_function whose BPF program sends
       us SIGUSR1. */

#define RETPROBE_BIT 1

static __attribute__((noinline)) int uretprobed_function(int x) {
  return x * 3 + 1;
}

static __attribute__((noinline)) void nop_function(void) {
#ifdef __x86_64__
  /* The nops the kernel optimizes uprobes on: the 10-byte nop since Linux
     7.3, the 5-byte nop in 6.18 to 7.2. Each is aligned so it doesn't
     cross a page boundary. */
  __asm__ __volatile__(".p2align 4\n\t"
                       ".globl nop10_insn\n\t"
                       "nop10_insn: .byte 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00,"
                       " 0x00, 0x00, 0x00, 0x00\n\t"
                       ".p2align 3\n\t"
                       ".globl nop5_insn\n\t"
                       "nop5_insn: .byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n\t");
#endif
}

/* The offset of `addr` in the file mapped there */
static uint64_t file_offset_of(void* addr) {
  FILE* maps = fopen("/proc/self/maps", "r");
  char line[4096];
  test_assert(maps != NULL);
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end, offset;
    if (sscanf(line, "%lx-%lx %*s %lx", &start, &end, &offset) == 3 &&
        start <= (uintptr_t)addr && (uintptr_t)addr < end) {
      fclose(maps);
      return (uintptr_t)addr - start + offset;
    }
  }
  test_assert(0 && "Function not mapped");
  return 0;
}

static void tracepoint(uint64_t id) {
  struct perf_event_attr attr;
  int fd;

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.config = id;
  fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  atomic_printf("tracepoint %llu: %d (errno %d)\n", (unsigned long long)id,
                fd, fd < 0 ? errno : 0);
  test_assert(fd == -1 && errno == EINVAL);
}

static void handle_usr1(__attribute__((unused)) int sig) {}

static void recorded(const char* kind, const char* pid_fifo,
                     const char* go_fifo) {
  char go;
  int fd;

  signal(SIGUSR1, handle_usr1);

  fd = open(pid_fifo, O_WRONLY);
  test_assert(fd >= 0);
  dprintf(fd, "%d\n", getpid());
  test_assert(0 == close(fd));

  fd = open(go_fifo, O_RDONLY);
  test_assert(fd >= 0);
  test_assert(1 == read(fd, &go, 1));
  test_assert(0 == close(fd));
  if (go == 's') {
    atomic_puts("Helper couldn't attach a uprobe");
    atomic_puts("EXIT-SUCCESS");
    return;
  }
  test_assert(go == 'g');

  if (!strcmp(kind, "nop")) {
    nop_function();
    nop_function();
    /* The kernel puts the trampoline next to this executable, below the
       heap. rr reads the kernel's mappings up to the heap when it grows. */
    test_assert(sbrk(4096) != (void*)-1);
  } else {
    test_assert(uretprobed_function(1) == 4);
  }
  /* A syscall that rr doesn't buffer */
  sched_yield();
  atomic_puts("EXIT-SUCCESS");
}

/* Returns -1 if there is no uprobe PMU. */
static int uprobe_pmu_type(void) {
  int type = -1;
  FILE* f = fopen("/sys/bus/event_source/devices/uprobe/type", "r");
  if (f) {
    if (fscanf(f, "%d", &type) != 1) {
      type = -1;
    }
    fclose(f);
  }
  return type;
}

/* A BPF program that sends SIGUSR1 to the current process */
static int load_signal_prog(void) {
  static const struct bpf_insn insns[] = {
    /* r1 = SIGUSR1 */
    { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, SIGUSR1 },
    /* call bpf_send_signal */
    { BPF_JMP | BPF_CALL, 0, 0, 0, 109 },
    /* r0 = 0 */
    { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },
    { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
  };
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_KPROBE;
  attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
  attr.insns = (uintptr_t)insns;
  attr.license = (uintptr_t)"GPL";
  return syscall(SYS_bpf, RR_BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int open_uprobe(int type, void* addr, int retprobe, pid_t pid) {
  struct perf_event_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = type;
  attr.config = retprobe ? RETPROBE_BIT : 0;
  attr.config1 = (uintptr_t)"/proc/self/exe";
  attr.config2 = file_offset_of(addr);
  return syscall(SYS_perf_event_open, &attr, pid, -1, -1,
                 PERF_FLAG_FD_CLOEXEC);
}

#ifdef __x86_64__
extern char nop10_insn[];
extern char nop5_insn[];

static int has_uprobe_trampoline(void) {
  FILE* maps = fopen("/proc/self/maps", "r");
  char line[4096];
  int found = 0;
  test_assert(maps != NULL);
  while (fgets(line, sizeof(line), maps)) {
    if (strstr(line, "[uprobes-trampoline]")) {
      found = 1;
    }
  }
  fclose(maps);
  return found;
}

/* Returns the nop in nop_function on which the kernel turns a uprobe into a
   call to a trampoline, trying each on this process, or NULL if there is
   none. */
static char* optimized_nop(int type) {
  char* const nops[] = { nop10_insn, nop5_insn };
  static const int sizes[] = { 10, 5 };
  size_t i;
  for (i = 0; i < sizeof(nops) / sizeof(nops[0]); ++i) {
    int fd = open_uprobe(type, nops[i], 0, 0);
    int optimized;
    if (fd < 0) {
      atomic_printf("uprobe on the %d-byte nop: errno %d\n", sizes[i], errno);
      continue;
    }
    nop_function();
    nop_function();
    optimized = has_uprobe_trampoline();
    test_assert(0 == close(fd));
    if (optimized) {
      return nops[i];
    }
  }
  atomic_puts("skip: the kernel doesn't turn uprobes on nops into calls");
  return NULL;
}
#endif

static int attach(const char* kind, pid_t pid) {
  int type = uprobe_pmu_type();
  void* addr = (void*)uretprobed_function;
  int retprobe = 1;
  int fd;

  if (type < 0) {
    atomic_puts("skip: no uprobe PMU");
    return -1;
  }
  if (!strcmp(kind, "nop")) {
#ifdef __x86_64__
    addr = optimized_nop(type);
    if (!addr) {
      return -1;
    }
    retprobe = 0;
#else
    atomic_puts("skip: only x86-64 kernels turn uprobes on nops into calls");
    return -1;
#endif
  }
  fd = open_uprobe(type, addr, retprobe, pid);
  if (fd < 0) {
    atomic_printf("skip: perf_event_open failed, errno %d\n", errno);
    return -1;
  }
  if (!strcmp(kind, "signal")) {
    int prog_fd = load_signal_prog();
    if (prog_fd < 0) {
      atomic_printf("skip: BPF_PROG_LOAD failed, errno %d\n", errno);
      test_assert(0 == close(fd));
      return -1;
    }
    if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd)) {
      atomic_printf("skip: PERF_EVENT_IOC_SET_BPF failed, errno %d\n", errno);
      test_assert(0 == close(fd));
      test_assert(0 == close(prog_fd));
      return -1;
    }
    test_assert(0 == close(prog_fd));
  }
  return fd;
}

static void helper(const char* kind, const char* pid_fifo,
                   const char* go_fifo) {
  char buf[32];
  ssize_t len;
  pid_t pid;
  int pidfd;
  int uprobe_fd;
  int fd;
  struct pollfd pfd;

  fd = open(pid_fifo, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  pid = atoi(buf);

  pidfd = syscall(SYS_pidfd_open, pid, 0);
  if (pidfd < 0) {
    atomic_printf("skip: pidfd_open failed, errno %d\n", errno);
    uprobe_fd = -1;
  } else {
    uprobe_fd = attach(kind, pid);
  }

  fd = open(go_fifo, O_WRONLY);
  test_assert(fd >= 0);
  test_assert(1 == write(fd, uprobe_fd >= 0 ? "g" : "s", 1));
  test_assert(0 == close(fd));
  if (uprobe_fd < 0) {
    return;
  }
  atomic_puts("attached");

  /* Keep the uprobe until the process exits. */
  pfd.fd = pidfd;
  pfd.events = POLLIN;
  test_assert(1 == poll(&pfd, 1, -1));
  test_assert(0 == close(uprobe_fd));
  atomic_puts("detached");
}

int main(int argc, char* argv[]) {
  if (argc == 2 && !strcmp(argv[1], "offset")) {
    uint64_t offset = file_offset_of((void*)uretprobed_function);
    atomic_printf("%llx\n", (unsigned long long)offset);
  } else if (argc == 3 && !strcmp(argv[1], "tracepoint")) {
    tracepoint(strtoull(argv[2], NULL, 10));
    atomic_puts("EXIT-SUCCESS");
  } else if (argc == 5 && !strcmp(argv[1], "recorded")) {
    recorded(argv[2], argv[3], argv[4]);
  } else if (argc == 5 && !strcmp(argv[1], "helper")) {
    helper(argv[2], argv[3], argv[4]);
  } else {
    test_assert(0 && "Bad arguments");
  }
  return 0;
}
