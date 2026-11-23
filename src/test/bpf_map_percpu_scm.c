/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"

#include <linux/bpf.h>

/* BPF_F_CPU: look up the value of the CPU in the upper 32 bits of flags */
#define LOOKUP_F_CPU 8

static int bpf(int cmd, union bpf_attr* attr) {
  return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int create_map(uint32_t map_type, uint32_t value_size) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = map_type;
  attr.key_size = sizeof(uint32_t);
  attr.value_size = value_size;
  attr.max_entries = 1;
  return bpf(RR_BPF_MAP_CREATE, &attr);
}

/* The number of CPUs in the list of ranges (e.g. "0-3,8-11") in
   /sys/devices/system/cpu/possible */
static int num_possible_cpus(void) {
  char buf[4096];
  int fd = open("/sys/devices/system/cpu/possible", O_RDONLY);
  test_assert(fd >= 0);
  ssize_t len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));

  int count = 0;
  char* p = buf;
  while (1) {
    char* end;
    long first = strtol(p, &end, 10);
    long last = first;
    test_assert(end != p);
    if (*end == '-') {
      p = end + 1;
      last = strtol(p, &end, 10);
      test_assert(end != p);
    }
    test_assert(last >= first);
    count += last - first + 1;
    if (*end != ',') {
      break;
    }
    p = end + 1;
  }
  return count;
}

/* A lookup in a per-CPU map writes the value of every possible CPU, each
   rounded up to 8 bytes. */
static void percpu_lookup(int map_fd) {
  struct percpu_value {
    uint32_t value;
    uint32_t pad;
  };
  int ncpus = num_possible_cpus();
  size_t size = ncpus * sizeof(struct percpu_value);
  struct percpu_value* values = malloc(size);
  test_assert(values != NULL);
  for (int i = 0; i < ncpus; ++i) {
    values[i].value = 0x10000 + i;
    values[i].pad = 0;
  }

  uint32_t key = 0;
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = map_fd;
  attr.key = (uintptr_t)&key;
  attr.value = (uintptr_t)values;
  attr.flags = BPF_ANY;
  test_assert(0 == bpf(RR_BPF_MAP_UPDATE_ELEM, &attr));

  struct percpu_value* out = allocate_guard(size, 'a');
  attr.value = (uintptr_t)out;
  attr.flags = 0;
  test_assert(0 == bpf(RR_BPF_MAP_LOOKUP_ELEM, &attr));
  verify_guard(size, out);
  for (int i = 0; i < ncpus; ++i) {
    test_assert(out[i].value == 0x10000 + (uint32_t)i);
  }
  free_guard(size, out);

  /* With BPF_F_CPU the lookup writes only that CPU's value. */
  uint32_t* cpu0_value = allocate_guard(sizeof(uint32_t), 'b');
  attr.value = (uintptr_t)cpu0_value;
  attr.flags = LOOKUP_F_CPU;
  int ret = bpf(RR_BPF_MAP_LOOKUP_ELEM, &attr);
  if (ret < 0) {
    /* BPF_F_CPU is not supported by this kernel */
    test_assert(errno == EINVAL);
  } else {
    test_assert(ret == 0);
    test_assert(*cpu0_value == 0x10000);
  }
  free_guard(sizeof(uint32_t), cpu0_value);
  free(values);
}

/* Look up a map through a copy of its fd received through SCM_RIGHTS. */
static void scm_rights_lookup(int map_fd) {
  uint32_t key = 0;
  uint64_t value = 0x123456789abcdef0;
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = map_fd;
  attr.key = (uintptr_t)&key;
  attr.value = (uintptr_t)&value;
  attr.flags = BPF_ANY;
  test_assert(0 == bpf(RR_BPF_MAP_UPDATE_ELEM, &attr));

  int sockfds[2];
  test_assert(0 == socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfds));
  char byte = 'x';
  struct iovec iov = { &byte, 1 };
  union {
    struct cmsghdr hdr;
    char buf[CMSG_SPACE(sizeof(int))];
  } cbuf;
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(&cbuf, 0, sizeof(cbuf));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf.buf;
  msg.msg_controllen = sizeof(cbuf.buf);
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &map_fd, sizeof(int));
  test_assert(1 == sendmsg(sockfds[0], &msg, 0));

  memset(&cbuf, 0, sizeof(cbuf));
  msg.msg_controllen = sizeof(cbuf.buf);
  test_assert(1 == recvmsg(sockfds[1], &msg, 0));
  cmsg = CMSG_FIRSTHDR(&msg);
  test_assert(cmsg != NULL);
  test_assert(cmsg->cmsg_level == SOL_SOCKET);
  test_assert(cmsg->cmsg_type == SCM_RIGHTS);
  int received_fd;
  memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
  test_assert(received_fd >= 0 && received_fd != map_fd);

  uint64_t* value_out = allocate_guard(sizeof(uint64_t), 'c');
  attr.map_fd = received_fd;
  attr.value = (uintptr_t)value_out;
  attr.flags = 0;
  test_assert(0 == bpf(RR_BPF_MAP_LOOKUP_ELEM, &attr));
  verify_guard(sizeof(uint64_t), value_out);
  test_assert(*value_out == value);
  free_guard(sizeof(uint64_t), value_out);

  /* Key 1 is past the end of the array, so the next key is 0. */
  uint32_t past_end = 1;
  uint32_t* next_key = allocate_guard(sizeof(uint32_t), 'd');
  attr.key = (uintptr_t)&past_end;
  attr.next_key = (uintptr_t)next_key;
  test_assert(0 == bpf(RR_BPF_MAP_GET_NEXT_KEY, &attr));
  verify_guard(sizeof(uint32_t), next_key);
  test_assert(*next_key == 0);
  free_guard(sizeof(uint32_t), next_key);

  test_assert(0 == close(received_fd));
  test_assert(0 == close(sockfds[0]));
  test_assert(0 == close(sockfds[1]));
}

int main(void) {
  int percpu_fd = create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(uint32_t));
  if (percpu_fd < 0) {
    if (errno == ENOSYS) {
      atomic_puts("bpf syscall not supported");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    if (errno == EPERM) {
      atomic_puts("Skipping test because it requires CAP_BPF");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
  }
  test_assert(percpu_fd >= 0);
  int array_fd = create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint64_t));
  test_assert(array_fd >= 0);

  percpu_lookup(percpu_fd);
  scm_rights_lookup(array_fd);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
