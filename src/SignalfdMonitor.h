/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SIGNALFD_MONITOR_H_
#define RR_SIGNALFD_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor for signalfds. A tracee may read a synthetic SIGCHLD from
 * one, and we need to fill in its siginfo, so reads from a signalfd must be
 * traced (the default for monitored fds).
 */
class SignalfdMonitor : public FileMonitor {
public:
  SignalfdMonitor() {}

  virtual Type type() override { return Signalfd; }
};

} // namespace rr

#endif /* RR_SIGNALFD_MONITOR_H_ */
