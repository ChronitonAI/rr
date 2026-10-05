/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HANDLE_SIGNAL_H__
#define RR_HANDLE_SIGNAL_H__

#include <signal.h>

#include "Event.h"

namespace rr {

class RecordTask;

const int SIGCHLD_SYNTHETIC = 0xbeadf00d;

void disarm_desched_event(RecordTask* t);
void arm_desched_event(RecordTask* t);
bool desched_event_armed(RecordTask *t);
bool handle_syscallbuf_breakpoint(RecordTask* t);
enum SyscallbufDebugTrap {
  NOT_SYSCALLBUF_DEBUG_TRAP,
  // SIGTRAP's handler and blocked-ness have been restored. The caller must
  // drop the signal.
  SYSCALLBUF_DEBUG_TRAP_DROPPED,
  // |t| was killed while we handled the trap. We have waited for its
  // PTRACE_EVENT_EXIT stop, unless that's unsafe (see
  // Scheduler::wait_for_killed_task()). The caller must not resume |t|.
  SYSCALLBUF_DEBUG_TRAP_TASK_KILLED
};
/**
 * Called when |t| stops for a SIGTRAP. Handles the SIGTRAP if it came from a
 * hardware breakpoint or watchpoint in |t|'s debug registers (set by its
 * ptracer) that triggered in syscallbuf code.
 */
SyscallbufDebugTrap handle_syscallbuf_debug_trap(RecordTask* t);

enum SignalBlocked { SIG_UNBLOCKED = 0, SIG_BLOCKED = 1 };
enum SignalHandled { SIGNAL_HANDLED, SIGNAL_PTRACE_STOP, DEFER_SIGNAL };
/**
 * Handle the given signal for |t|.
 * Returns SIGNAL_HANDLED if we handled the signal, SIGNAL_PTRACE_STOP if we
 * didn't handle the signal due to an emulated ptrace-stop, and SIGNAL_DEFER
 * if we can't handle the signal right now and should try calling
 * handle_signal again later in task execution.
 * Handling the signal means we either pushed a new signal event, new
 * desched + syscall-interruption events, or no-op.
 */
SignalHandled handle_signal(RecordTask* t, siginfo_t* si,
                            SignalDeterministic deterministic,
                            SignalBlocked signal_was_blocked);

} // namespace rr

#endif /* RR_HANDLE_SIGNAL_H__ */
