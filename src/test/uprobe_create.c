/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

#include <linux/bpf.h>
#include <linux/perf_event.h>

/* This process tries each way of creating a uprobe on itself. rr must
   refuse them all. Natively they may succeed (we remove the uprobe right
   away) or fail for lack of permission. */

#define RETPROBE_BIT 1

/* enum bpf_attach_type */
#define TRACE_UPROBE_MULTI 48
#define TRACE_UPROBE_SESSION 57

/* The start of union bpf_attr for BPF_LINK_CREATE with a uprobe_multi
   attach type */
struct uprobe_multi_link_attr {
  uint32_t prog_fd;
  uint32_t target_fd;
  uint32_t attach_type;
  uint32_t flags;
  uint64_t path;
  uint64_t offsets;
  uint64_t ref_ctr_offsets;
  uint64_t cookies;
  uint32_t cnt;
  uint32_t uprobe_flags;
  uint32_t pid;
  uint32_t padding;
};

static int under_rr;

static __attribute__((noinline)) int probed_function(int x) {
  return x * 3 + 1;
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

static void perf_uprobe(int type, uint64_t offset, int retprobe) {
  struct perf_event_attr attr;
  int fd;

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = type;
  attr.config = retprobe ? RETPROBE_BIT : 0;
  attr.config1 = (uintptr_t)"/proc/self/exe";
  attr.config2 = offset;
  fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  atomic_printf("perf uprobe (retprobe=%d): %d (errno %d)\n", retprobe, fd,
                fd < 0 ? errno : 0);
  if (under_rr) {
    test_assert(fd == -1 && errno == ENOENT);
  }
  if (fd >= 0) {
    test_assert(0 == close(fd));
  }
}

static void tracefs_files(void) {
  static const char* const files[] = {
    "/sys/kernel/tracing/uprobe_events",
    "/sys/kernel/tracing/dynamic_events",
    "/sys/kernel/debug/tracing/uprobe_events",
    "/sys/kernel/debug/tracing/dynamic_events",
  };
  size_t i;
  for (i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
    int writable = access(files[i], W_OK) == 0;
    int readable = access(files[i], R_OK) == 0;
    /* No O_TRUNC: that deletes the existing events */
    int fd = open(files[i], O_WRONLY | O_APPEND);
    atomic_printf("%s for writing: %d (errno %d)\n", files[i], fd,
                  fd < 0 ? errno : 0);
    if (under_rr) {
      test_assert(fd == -1 && (!writable || errno == ENOENT));
    }
    if (fd >= 0) {
      test_assert(0 == close(fd));
    }
    if (readable) {
      fd = open(files[i], O_RDONLY);
      test_assert(fd >= 0);
      test_assert(0 == close(fd));
    }
  }
}

static int bpf_load_uprobe_multi_prog(void) {
  /* r0 = 0; exit */
  static const struct bpf_insn insns[] = {
    { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },
    { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
  };
  union bpf_attr attr;
  int fd;

  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_KPROBE;
  attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
  attr.insns = (uintptr_t)insns;
  attr.license = (uintptr_t)"GPL";
  attr.expected_attach_type = TRACE_UPROBE_MULTI;
  fd = syscall(SYS_bpf, RR_BPF_PROG_LOAD, &attr, sizeof(attr));
  atomic_printf("BPF_PROG_LOAD: %d (errno %d)\n", fd, fd < 0 ? errno : 0);
  return fd;
}

static void bpf_uprobe_link(int prog_fd, uint64_t offset, int attach_type) {
  struct uprobe_multi_link_attr attr;
  int fd;

  memset(&attr, 0, sizeof(attr));
  attr.prog_fd = prog_fd;
  attr.attach_type = attach_type;
  attr.path = (uintptr_t)"/proc/self/exe";
  attr.offsets = (uintptr_t)&offset;
  attr.cnt = 1;
  attr.pid = getpid();
  fd = syscall(SYS_bpf, RR_BPF_LINK_CREATE, &attr, sizeof(attr));
  atomic_printf("BPF_LINK_CREATE (attach type %d): %d (errno %d)\n",
                attach_type, fd, fd < 0 ? errno : 0);
  if (under_rr) {
    test_assert(fd == -1 && errno == EOPNOTSUPP);
  }
  if (fd >= 0) {
    test_assert(0 == close(fd));
  }
}

int main(void) {
  uint64_t offset = file_offset_of((void*)probed_function);
  int type = uprobe_pmu_type();
  int prog_fd;

  under_rr = running_under_rr();

  if (type < 0) {
    atomic_puts("No uprobe PMU, skipping perf uprobes");
  } else {
    perf_uprobe(type, offset, 0);
    perf_uprobe(type, offset, 1);
  }

  tracefs_files();

  prog_fd = bpf_load_uprobe_multi_prog();
  bpf_uprobe_link(prog_fd, offset, TRACE_UPROBE_MULTI);
  bpf_uprobe_link(prog_fd, offset, TRACE_UPROBE_SESSION);
  if (prog_fd >= 0) {
    test_assert(0 == close(prog_fd));
  }

  test_assert(probed_function(1) == 4);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
