/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "SeccompFilterRewriter.h"

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <algorithm>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "RecordTask.h"
#include "Registers.h"
#include "ThreadGroup.h"
#include "kernel_abi.h"
#include "log.h"
#include "seccomp-bpf.h"

using namespace std;

namespace rr {

static void set_syscall_result(RecordTask* t, long ret) {
  Registers r = t->regs();
  r.set_syscall_result(ret);
  t->set_regs(r);
}

namespace {
/**
 * The prctl(PR_SET_SECCOMP) or seccomp(SECCOMP_SET_MODE_FILTER) call that
 * installs a filter. rr makes it with a syscall of the task's arch, but an
 * x86-64 task can make it with an i386 syscall (int $0x80).
 */
struct FilterInstall {
  // The same syscall of the task's arch
  int syscallno;
  // Its first two arguments (the filter program is the third)
  uintptr_t arg1;
  uintptr_t arg2;
  bool is_seccomp;
  // The program as the tracee passed it
  remote_ptr<void> prog;
  SupportedArch prog_arch;
};
} // namespace

static void pass_through_seccomp_filter(RecordTask* t,
                                        const FilterInstall& install) {
  long ret;
  {
    AutoRemoteSyscalls remote(t);
    ret = remote.syscall(install.syscallno, install.arg1, install.arg2,
                         install.prog.as_int());
  }
  set_syscall_result(t, ret);
  ASSERT(t, t->regs().syscall_failed());
}

template <typename Arch>
static bool read_sock_fprog_arch(RecordTask* t, remote_ptr<void> p,
                                 uint16_t* len, remote_ptr<void>* filter) {
  bool ok = true;
  auto prog = t->read_mem(p.cast<typename Arch::sock_fprog>(), &ok);
  if (!ok) {
    return false;
  }
  *len = prog.len;
  *filter = prog.filter.rptr();
  return true;
}

static bool read_sock_fprog(RecordTask* t, SupportedArch arch,
                            remote_ptr<void> p, uint16_t* len,
                            remote_ptr<void>* filter) {
  RR_ARCH_FUNCTION(read_sock_fprog_arch, arch, t, p, len, filter);
}

template <typename Arch>
static void install_patched_seccomp_filter_arch(
    RecordTask* t, const FilterInstall& install,
    unordered_map<uint32_t, uint16_t>& result_to_index,
    vector<uint32_t>& index_to_result) {
  uint16_t len;
  remote_ptr<void> filter;
  if (!read_sock_fprog(t, install.prog_arch, install.prog, &len, &filter)) {
    // We'll probably return EFAULT but a kernel that doesn't support
    // seccomp(2) should return ENOSYS instead, so just run the original
    // system call to get the correct error.
    pass_through_seccomp_filter(t, install);
    return;
  }
  bool ok = true;
  auto code = t->read_mem(filter.cast<typename Arch::sock_filter>(), len, &ok);
  if (!ok) {
    pass_through_seccomp_filter(t, install);
    return;
  }
  // Convert all returns to TRACE returns so that rr can handle them.
  // See handle_ptrace_event in RecordSession.
  for (auto& u : code) {
    if (BPF_CLASS(u.code) == BPF_RET) {
      ASSERT(t, BPF_RVAL(u.code) == BPF_K)
          << "seccomp-bpf program uses BPF_RET with A/X register, not "
             "supported";
      if (u.k != SECCOMP_RET_ALLOW) {
        if (result_to_index.find(u.k) == result_to_index.end()) {
          ASSERT(t,
                 SeccompFilterRewriter::BASE_CUSTOM_DATA +
                         index_to_result.size() <
                     SECCOMP_RET_DATA)
              << "Too many distinct constants used in seccomp-bpf programs";
          result_to_index[u.k] = index_to_result.size();
          index_to_result.push_back(u.k);
        }
        u.k = (SeccompFilterRewriter::BASE_CUSTOM_DATA + result_to_index[u.k]) |
              SECCOMP_RET_TRACE;
      }
    }
  }

  SeccompFilter<typename Arch::sock_filter> f;
  for (auto& e : AddressSpace::rr_page_syscalls()) {
    if (e.privileged == AddressSpace::PRIVILEGED) {
      auto ip = AddressSpace::rr_page_syscall_exit_point(e.traced, e.privileged,
                                                         e.enabled,
                                                         Arch::arch());
      f.allow_syscalls_from_callsite(ip);
    }
  }
  f.filters.insert(f.filters.end(), code.begin(), code.end());

  long ret;
  {
    AutoRemoteSyscalls remote(t);
    typename Arch::sock_fprog prog;
    memset(&prog, 0, sizeof(prog));
    AutoRestoreMem mem(
        remote, nullptr,
        sizeof(prog) + f.filters.size() * sizeof(typename Arch::sock_filter));
    auto code_ptr = mem.get().cast<typename Arch::sock_filter>();
    t->write_mem(code_ptr, f.filters.data(), f.filters.size());
    prog.len = f.filters.size();
    prog.filter = code_ptr;
    auto prog_ptr = remote_ptr<void>(code_ptr + f.filters.size())
                        .cast<typename Arch::sock_fprog>();
    t->write_mem(prog_ptr, prog);

    ret =
        remote.syscall(install.syscallno, install.arg1, install.arg2, prog_ptr);
  }
  set_syscall_result(t, ret);

  if (!t->regs().syscall_failed()) {
    if (install.is_seccomp && (install.arg2 & SECCOMP_FILTER_FLAG_TSYNC)) {
      for (Task* tt : t->thread_group()->task_set()) {
        static_cast<RecordTask*>(tt)->prctl_seccomp_status = 2;
      }
    } else {
      t->prctl_seccomp_status = 2;
    }
  }
}

void SeccompFilterRewriter::install_patched_seccomp_filter(RecordTask* t) {
  // The syscall's arch, which an x86-64 task can make i386 with int $0x80.
  // Take advantage of the fact that the filter program is arg3() in both
  // prctl and seccomp syscalls.
  const Registers& r = t->regs();
  FilterInstall install;
  install.prog_arch = r.syscall_arch();
  install.is_seccomp =
      is_seccomp_syscall(r.original_syscallno(), install.prog_arch);
  install.syscallno = install.is_seccomp ? syscall_number_for_seccomp(t->arch())
                                         : syscall_number_for_prctl(t->arch());
  install.arg1 = r.orig_arg1();
  install.arg2 = r.arg2();
  install.prog = r.arg3();
  RR_ARCH_FUNCTION(install_patched_seccomp_filter_arch, t->arch(), t, install,
                   result_to_index, index_to_result);
}

bool SeccompFilterRewriter::map_filter_data_to_real_result(RecordTask* t,
                                                           uint16_t value,
                                                           uint32_t* result) {
  if (value < BASE_CUSTOM_DATA) {
    return false;
  }
  ASSERT(t, value < BASE_CUSTOM_DATA + index_to_result.size());
  *result = index_to_result[value - BASE_CUSTOM_DATA];
  return true;
}

} // namespace rr
