/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MONKEYPATCHER_H_
#define RR_MONKEYPATCHER_H_

#include <map>
#include <unordered_set>
#include <vector>

#include "preload/preload_interface.h"

#include "remote_code_ptr.h"
#include "remote_ptr.h"

namespace rr {

class ElfReader;
class RecordTask;
class ScopedFd;
class Task;

/**
 * A class encapsulating patching state. There is one instance of this
 * class per tracee address space. Currently this class performs the following
 * tasks:
 *
 * 1) Patch the VDSO's user-space-only implementation of certain system calls
 * (e.g. gettimeofday) to do a proper kernel system call instead, so rr can
 * trap and record it (x86-64 only).
 *
 * 2) Patch the VDSO __kernel_vsyscall fast-system-call stub to redirect to
 * our syscall hook in the preload library (x86 only).
 *
 * 3) Patch syscall instructions whose following instructions match a known
 * pattern to call the syscall hook.
 *
 * Monkeypatcher only runs during recording, never replay.
 */
class Monkeypatcher {
public:
  Monkeypatcher() {}
  Monkeypatcher(const Monkeypatcher&) = default;

  /**
   * Apply any necessary patching immediately after exec.
   * In this hook we patch everything that doesn't depend on the preload
   * library being loaded.
   */
  void patch_after_exec(RecordTask* t);

  /**
   * During librrpreload initialization, apply patches that require the
   * preload library to be initialized.
   */
  void patch_at_preload_init(RecordTask* t);

  /**
   * Try to patch the syscall instruction that |t| just entered. If this
   * returns false, patching failed and the syscall should be processed
   * as normal. If this returns true, patching succeeded and the syscall
   * was aborted; ip() has been reset to the start of the patched syscall,
   * and execution should resume normally to execute the patched code.
   * Zero or more mapping operations are also recorded to the trace and must
   * be replayed.
   */
  bool try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry);
  bool try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry, remote_code_ptr ip);

  bool try_patch_syscall_x86ish(RecordTask* t, remote_code_ptr ip, bool entering_syscall,
                                SupportedArch arch, bool &should_retry);
  bool try_patch_syscall_aarch64(RecordTask* t, remote_code_ptr ip, bool entering_syscall);

  /**
   * Try to patch the trapping instruction that |t| just trapped on. If this
   * returns false, patching failed and the instruction should be processed
   * as normal. If this returns true, patching succeeded.
   * t->ip() is the address of the trapping instruction.
   * and execution should resume normally to execute the patched code.
   * Zero or more mapping operations are also recorded to the trace and must
   * be replayed.
   */
  bool try_patch_trapping_instruction(RecordTask* t, size_t instruction_length,
                                      bool before_instruction,
                                      bool &should_retry);

  /**
   * Replace all extended jumps by syscalls again. Note that we do not try to
   * patch the original locations, since we don't know what the tracee may have
   * done with them in the meantime, we only patch the extended jump stubs,
   * which the tracee isn't allowed to touch.
   */
  void unpatch_syscalls_in(Task *t);

  /**
   * Try to patch the vsyscall-entry pattern occurring right before ret_addr
   * to instead point into the corresponding entry points in the vdso.
   * Returns true if the patching succeeded, false if it doesn't. The tasks
   * registers are left unmodified.
   */
  bool try_patch_vsyscall_caller(RecordTask *t, remote_code_ptr ret_addr);

  void init_dynamic_syscall_patching(
      RecordTask* t, int syscall_patch_hook_count,
      remote_ptr<syscall_patch_hook> syscall_patch_hooks);

  /**
   * Try to allocate a stub from the sycall patching stub buffer. Returns null
   * if there's no buffer or we've run out of free stubs.
   */
  remote_ptr<uint8_t> allocate_stub(RecordTask* t, size_t bytes);

  enum MmapMode {
    MMAP_EXEC,
    MMAP_SYSCALL,
  };
  /**
   * Apply any necessary patching immediately after an mmap. We use this to
   * patch libpthread.so.
   */
  void patch_after_mmap(RecordTask* t, remote_ptr<void> start, size_t size,
                        size_t offset_bytes, uint64_t prot, int child_fd,
                        MmapMode mode);

  /**
   * The list of pages we've allocated to hold our extended jumps.
   */
  struct ExtendedJumpPage {
    ExtendedJumpPage(remote_ptr<uint8_t> addr) : addr(addr), allocated(0) {}
    remote_ptr<uint8_t> addr;
    size_t allocated;
  };
  std::vector<ExtendedJumpPage> extended_jump_pages;

  void unpatch_dl_runtime_resolves(RecordTask* t);

  /**
   * A patched syscall (or trapping instruction) and its extended jump patch.
   * The patched code region starts at |patch_addr| and ends at the address
   * the extended jump patch returns to. The extended jump patch ends with its
   * safe suffix, which starts with the syscall instruction (the trapping
   * instruction for trapping-instruction patches), followed by a copy of the
   * instructions of the patched code region that follow the syscall
   * instruction, and a jump to the end of the patched code region.
   */
  struct patched_syscall {
    // Pointer to hook inside the syscall_hooks array, which gets initialized
    // once and is fixed afterwards.
    const syscall_patch_hook* hook;
    // Start of the patched code region.
    remote_ptr<uint8_t> patch_addr;
    // Start of the extended jump patch.
    remote_ptr<uint8_t> stub_addr;
    // Size of the extended jump patch.
    size_t size;
    // Size of the patched code region.
    uint16_t patch_region_size;
    // Offset of the syscall instruction in the patched code region.
    uint16_t syscall_offset;
    // Instructions at the start of the extended jump patch that haven't
    // changed any state yet.
    uint16_t safe_prefix = 0;
    // Instructions at the end of the extended jump patch that no longer use
    // the syscallbuf stack. Signals can be delivered there.
    uint16_t safe_suffix = 0;
  };

  /**
   * Return the extended jump patch containing |ip|, if any. Unless
   * |include_safearea| is true, the safe prefix and safe suffix don't count.
   */
  patched_syscall* find_jump_stub(remote_code_ptr ip, bool include_safearea);
  bool is_jump_stub_instruction(remote_code_ptr ip, bool include_safearea) {
    return find_jump_stub(ip, include_safearea) != nullptr;
  }

  /**
   * If |ip| is in the safe prefix or safe suffix of an extended jump patch,
   * return the address in the patched code region where execution would be
   * in the same state without the patch. The safe prefix corresponds to the
   * syscall instruction, the rest of the safe suffix to the original
   * instructions it copies, and the end of the safe suffix to the end of the
   * patched code region. Otherwise return null.
   */
  remote_code_ptr patched_code_ip_for_stub_ip(Task* t, remote_code_ptr ip);

  /**
   * The inverse of patched_code_ip_for_stub_ip: if |ip| is in a patched code
   * region, at or after the syscall instruction, return the corresponding
   * address in the safe suffix of the extended jump patch. Otherwise return
   * null.
   */
  remote_code_ptr stub_ip_for_patched_code_ip(Task* t, remote_code_ptr ip);

  // Return the breakpoint instruction (i.e. the last branch back to caller)
  // if we are on the exit path in the jump stub
  remote_code_ptr get_jump_stub_exit_breakpoint(remote_code_ptr ip,
                                                RecordTask* t);

  /**
   * All syscall patches, and indexes into this vector by the start of their
   * extended jump patch and by the start of their patched code region.
   */
  std::vector<patched_syscall> syscall_stub_list;
  std::map<remote_ptr<uint8_t>, size_t> syscallbuf_stubs_by_extended_patch;
  std::map<remote_ptr<uint8_t>, size_t> syscallbuf_stubs_by_patch_addr;

private:
  void patch_dl_runtime_resolve(RecordTask* t, ElfReader& reader,
                                uintptr_t elf_addr, remote_ptr<void> map_start,
                                size_t map_size, size_t map_offset,
                                uint64_t prot);
  void patch_aarch64_have_lse_atomics(RecordTask* t, ElfReader& reader,
                                      uintptr_t elf_addr,
                                      remote_ptr<void> map_start,
                                      size_t map_size, size_t map_offset,
                                      uint64_t prot);

  /**
   * `ip` is the address of the instruction that triggered the syscall or trap
   */
  const syscall_patch_hook* find_syscall_hook(RecordTask* t,
                                              remote_code_ptr ip,
                                              bool entering_syscall,
                                              size_t instruction_length,
                                              bool &should_retry,
                                              bool &transient_failure);

  /**
   * The list of supported syscall patches obtained from the preload
   * library. Each one matches a specific byte signature for the instruction(s)
   * after a syscall instruction.
   */
  std::vector<syscall_patch_hook> syscall_hooks;
  /**
   * The addresses of the instructions following syscalls or other
   * instructions that we've tried (or are currently trying) to patch.
   */
  std::unordered_set<remote_code_ptr> tried_to_patch_syscall_addresses;

  std::map<remote_ptr<uint8_t>, std::vector<uint8_t>> saved_dl_runtime_resolve_code;
};

} // namespace rr

#endif /* RR_MONKEYPATCHER_H_ */
