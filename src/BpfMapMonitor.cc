/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "BpfMapMonitor.h"

#include <fstream>
#include <string>

#include "kernel_supplement.h"
#include "log.h"

using namespace std;

namespace rr {

// The kernel's num_possible_cpus(): the number of CPUs in the list of
// ranges (e.g. "0-3,8-11") in /sys/devices/system/cpu/possible.
static uint64_t num_possible_cpus() {
  static uint64_t count = 0;
  if (count) {
    return count;
  }
  ifstream file("/sys/devices/system/cpu/possible");
  string s;
  if (!getline(file, s)) {
    FATAL() << "Can't read /sys/devices/system/cpu/possible";
  }
  const char* p = s.c_str();
  while (true) {
    char* end;
    uint64_t first = strtoull(p, &end, 10);
    uint64_t last = first;
    if (end != p && *end == '-') {
      p = end + 1;
      last = strtoull(p, &end, 10);
    }
    if (end == p || last < first) {
      FATAL() << "Can't parse /sys/devices/system/cpu/possible: " << s;
    }
    count += last - first + 1;
    if (*end != ',') {
      break;
    }
    p = end + 1;
  }
  return count;
}

uint64_t BpfMapParams::lookup_value_size(uint64_t flags) const {
  // This follows bpf_map_value_size() in kernel/bpf/syscall.c. FD maps
  // (map-in-map, prog, perf event and cgroup arrays) always have
  // value_size 4, the size the kernel writes for them.
  if (flags & (RR_BPF_F_CPU | RR_BPF_F_ALL_CPUS)) {
    return value_size;
  }
  switch (map_type) {
    case RR_BPF_MAP_TYPE_PERCPU_HASH:
    case RR_BPF_MAP_TYPE_LRU_PERCPU_HASH:
    case RR_BPF_MAP_TYPE_PERCPU_ARRAY:
    case RR_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
      return ((value_size + 7) & ~uint64_t(7)) * num_possible_cpus();
    default:
      return value_size;
  }
}

} // namespace rr
