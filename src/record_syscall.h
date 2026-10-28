/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESS_SYSCALL_H_
#define RR_PROCESS_SYSCALL_H_

#include "util.h"

namespace rr {

class RecordTask;

/**
 * Prepare |t| to enter its current syscall event.  Return ALLOW_SWITCH if
 * a context-switch is allowed for |t|, PREVENT_SWITCH if not.
 */
Switchable rec_prepare_syscall(RecordTask* t);

/**
 * Any prepared syscall is not going to happen (because it was aborted by
 * tracee seccomp filter). Cancel any preparation work.
 */
void rec_abort_prepared_syscall(RecordTask* t);

/**
 * Prepare |t| for its current syscall event to be interrupted and
 * possibly restarted.
 */
void rec_prepare_restart_syscall(RecordTask* t);

/**
 * Restore any argument registers fudged for |t|'s current syscall and
 * store any nondeterministic outparam data.
 */
void rec_process_syscall(RecordTask* t);

/**
 * |t|'s execve has replaced its image, and |t| is at its PTRACE_EVENT_EXEC
 * stop, which we're going to report to its emulated ptracer. Record the new
 * image and an EV_EXEC, so that replay does the exec before anything the
 * ptracer does there. We finish recording the exec at the execve's exit.
 */
void rec_process_exec_stop(RecordTask* t);

/**
 * |t| is about to leave the PTRACE_EVENT_EXEC stop that we've held it in
 * since rec_process_exec_stop(). Save what we need at the execve's exit.
 */
void rec_leave_exec_stop(RecordTask* t);

/**
 * Apply any necessary processing for an executed sigreturn.
 */
void rec_did_sigreturn(RecordTask* t);

/**
 * Return true if we're in a wait-like syscall that should
 * return a status from an emulated stop instead of being interrupted
 * by a signal. Sets the waited-for task as a side effect.
 */
bool rec_return_normally_from_wait(RecordTask* t);

} // namespace rr

#endif /* RR_PROCESS_SYSCALL_H_ */
