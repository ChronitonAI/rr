/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static void __attribute__((noinline)) fail_here(void) { rr_fail_assertion(); }

int main(void) {
  /* While rr records us, this doesn't return. */
  fail_here();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
