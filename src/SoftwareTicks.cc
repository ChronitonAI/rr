/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "SoftwareTicks.h"

#include <string.h>

#include "AddressSpace.h"
#include "ElfReader.h"
#include "Task.h"
#include "log.h"
#include "preload/preload_interface.h"

namespace rr {

static bool software_ticks_mode_;

bool software_ticks_mode() { return software_ticks_mode_; }

void set_software_ticks_mode(bool on) { software_ticks_mode_ = on; }

remote_ptr<uint64_t> software_ticks_countdown_address() {
  return remote_ptr<uint64_t>(SOFTWARE_TICKS_COUNTDOWN_ADDR);
}

uint32_t read_software_ticks_note(ElfFileReader& reader) {
  SectionOffsets offsets =
      reader.find_section_file_offsets(RR_SOFTWARE_TICKS_NOTE_SECTION);
  if (!offsets.start) {
    return 0;
  }
  uint64_t off = offsets.start;
  while (off + 12 <= offsets.end) {
    auto hdr = reader.read<uint32_t>(off, 3);
    if (!hdr) {
      return 0;
    }
    uint32_t namesz = hdr[0];
    uint32_t descsz = hdr[1];
    uint32_t type = hdr[2];
    uint64_t name_off = off + 12;
    uint64_t desc_off = name_off + ((uint64_t(namesz) + 3) & ~uint64_t(3));
    uint64_t next = desc_off + ((uint64_t(descsz) + 3) & ~uint64_t(3));
    if (next > offsets.end) {
      return 0;
    }
    if (namesz == 3 && descsz == 4 && type == SOFTWARE_TICKS_NOTE_TYPE) {
      auto name = reader.read<char>(name_off, 3);
      if (name && !memcmp(name, "rr", 3)) {
        auto desc = reader.read<uint32_t>(desc_off);
        return desc ? *desc : 0;
      }
    }
    off = next;
  }
  return 0;
}

bool read_software_ticks_slot(Task* t, uint64_t* value) {
  return t->read_bytes_fallible(software_ticks_countdown_address(),
                                sizeof(*value), value) == sizeof(*value);
}

bool write_software_ticks_slot(Task* t, uint64_t value) {
  bool ok = true;
  t->write_bytes_helper_no_notifications(software_ticks_countdown_address(),
                                         sizeof(value), &value, &ok);
  return ok;
}

void init_software_ticks_slot(Task* t) {
  write_software_ticks_slot(t, SOFTWARE_TICKS_PARKED);
  t->vm()->set_software_ticks_owner(TaskUid());
}

// The tick sequences up to and including their trap instruction
// (include/rr/softticks.h).
static const uint8_t tick_x64[] = {
  0x48, 0xff, 0x0c, 0x25, 0x00, 0x18, 0x00, 0x70, // decq 0x70001800
  0x75, 0x01,                                     // jnz 1f
  0xcc                                            // int3
};
static const uint8_t tick_x86[] = {
  0x83, 0x2d, 0x00, 0x18, 0x00, 0x70, 0x01, // subl $1, 0x70001800
  0x75, 0x0a,                               // jnz 1f
  0x83, 0x3d, 0x04, 0x18, 0x00, 0x70, 0x00, // cmpl $0, 0x70001804
  0x75, 0x01,                               // jnz 1f
  0xcc                                      // int3
};
static const uint8_t tick_arm64[] = {
  0x30, 0x00, 0xae, 0xd2, // movz x16, #0x7001, lsl #16
  0x11, 0x02, 0x44, 0xf9, // ldr x17, [x16, #0x800]
  0x31, 0x06, 0x00, 0xd1, // sub x17, x17, #1
  0x11, 0x02, 0x04, 0xf9, // str x17, [x16, #0x800]
  0x51, 0x00, 0x00, 0xb5, // cbnz x17, 1f
  0x80, 0x6a, 0x2a, 0xd4  // brk #0x5354
};

bool is_software_tick_trap(Task* t) {
  const uint8_t* seq;
  size_t len;
  size_t trap_len;
  const siginfo_t& si = t->get_siginfo();
  switch (t->arch()) {
    case x86_64:
      seq = tick_x64;
      len = sizeof(tick_x64);
      trap_len = 1;
      break;
    case x86:
      seq = tick_x86;
      len = sizeof(tick_x86);
      trap_len = 1;
      break;
    case aarch64:
      seq = tick_arm64;
      len = sizeof(tick_arm64);
      trap_len = 4;
      break;
    default:
      return false;
  }
  if (is_x86ish(t->arch()) ? si.si_code != SI_KERNEL
                           : si.si_code != TRAP_BRKPT) {
    return false;
  }
  // The trap instruction's address: on x86 the pc is after the int3.
  uintptr_t trap = t->ip().register_value() - (is_x86ish(t->arch()) ? 1 : 0);
  if (t->vm()->get_breakpoint_type_at_addr(remote_code_ptr(trap)) !=
      BKPT_NONE) {
    return false;
  }
  uint8_t buf[sizeof(tick_arm64)];
  remote_ptr<void> start = remote_ptr<void>(trap + trap_len - len);
  if (t->read_bytes_fallible(start, len, buf) != (ssize_t)len) {
    return false;
  }
  return !memcmp(buf, seq, len);
}

void normalize_software_ticks_slot(uint8_t* page, size_t size) {
  size_t off = SOFTWARE_TICKS_COUNTDOWN_ADDR - PRELOAD_THREAD_LOCALS_ADDR;
  if (size >= off + sizeof(uint64_t)) {
    memset(page + off, 0, sizeof(uint64_t));
  }
}

} // namespace rr
