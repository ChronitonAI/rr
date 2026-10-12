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
/**
 * |t| stopped for a SIGTRAP that it must not see. The kernel forced that
 * SIGTRAP: if SIGTRAP was blocked or ignored, the kernel unblocked it and
 * reset its handler to SIG_DFL. Undo that.
 */
void restore_signal_state_after_hidden_sigtrap(RecordTask* t);
/**
 * Returns true if |t| is running one of the syscall hooks, i.e. it executed
 * a patched syscall instruction, which jumped to the hook, and the hook
 * hasn't returned to the application yet. (Except for the hook's last few
 * instructions.)
 */
bool is_in_syscall_hook(RecordTask* t);

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
