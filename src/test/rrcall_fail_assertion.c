/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

int main(void) {
  int under_rr = running_under_rr();
  /* rr rejects a nonzero argument, in any position. */
  for (int i = 0; i < 6; ++i) {
    long args[6] = { 0, 0, 0, 0, 0, 0 };
    args[i] = 1;
    long ret = syscall(SYS_rrcall_fail_assertion, args[0], args[1], args[2],
                       args[3], args[4], args[5]);
    test_assert(ret == -1 && errno == (under_rr ? EINVAL : ENOSYS));
  }
  atomic_puts("nonzero arguments rejected");

  /* While rr records us, this doesn't return. */
  rr_fail_assertion();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
