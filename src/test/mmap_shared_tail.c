/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A MAP_SHARED mapping writes 'J' past the end of a memfd, in its last
   page, and the file grows within that page, which keeps them. After a
   few syscalls, which checkpoint_mmap_shared_tail checkpoints at, prints
   how many of them the mapping still reads. */

#define OLD_SIZE 100

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char data[OLD_SIZE];
  size_t junk = 0;
  size_t i;
  char* p;
  int fd = memfd_create("mmap_shared_tail", 0);

  test_assert(fd >= 0);
  memset(data, 'a', sizeof(data));
  test_assert(OLD_SIZE == write(fd, data, OLD_SIZE));
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  for (i = OLD_SIZE; i < page_size; ++i) {
    __atomic_store_n(p + i, 'J', __ATOMIC_SEQ_CST);
  }
  test_assert(0 == ftruncate(fd, OLD_SIZE + 2));

  for (i = 0; i < 5; ++i) {
    test_assert(0 == sched_yield());
  }

  for (i = OLD_SIZE + 2; i < page_size; ++i) {
    if (__atomic_load_n(p + i, __ATOMIC_SEQ_CST) == 'J') {
      ++junk;
    }
  }
  atomic_printf("'J' past the end: %zu\n", junk);

  test_assert(0 == munmap(p, page_size));
  test_assert(0 == close(fd));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
