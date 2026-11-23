/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_BPF_MAP_MONITOR_H_
#define RR_BPF_MAP_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * The type, key size and value size of a BPF map.
 */
struct BpfMapParams {
  uint32_t map_type;
  uint64_t key_size;
  uint64_t value_size;

  /**
   * The number of bytes BPF_MAP_LOOKUP_ELEM with |flags| writes to its
   * value buffer.
   */
  uint64_t lookup_value_size(uint64_t flags) const;
};

/**
 * A FileMonitor attached to BPF map fds to record their type, key size and
 * value size.
 */
class BpfMapMonitor : public FileMonitor {
public:
  explicit BpfMapMonitor(const BpfMapParams& params) : params_(params) {}

  virtual Type type() override { return BpfMap; }

  const BpfMapParams& params() const { return params_; }

private:
  BpfMapParams params_;
};

} // namespace rr

#endif /* RR_BPF_MAP_MONITOR_H_ */
