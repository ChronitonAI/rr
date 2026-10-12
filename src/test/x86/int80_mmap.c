/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* i386 memory-mapping syscalls, made by an x86-64 process with int $0x80. */

#if defined(__x86_64__)

#include <setjmp.h>

static sigjmp_buf jmpbuf;

static void handle_segv(__attribute__((unused)) int sig) {
  siglongjmp(jmpbuf, 1);
}

/* Returns whether reading *p faults. */
static int read_faults(volatile unsigned char* p) {
  if (sigsetjmp(jmpbuf, 1)) {
    return 1;
  }
  (void)*p;
  return 0;
}

static unsigned char* result_ptr(long ret) {
  /* Addresses can be above 2GB, which makes the 32-bit result negative. */
  test_assert((uint32_t)ret < 0xfffff000);
  return (unsigned char*)(uintptr_t)(uint32_t)ret;
}

#define BIG_LEN 0xa0000000UL

/* An i386 mmap() of 2.5GB. Whether there's room for that below 4GB depends on
   what's mapped there, but it must either fail with ENOMEM or map all of it.
   (rr's chaos mode looks for room itself, and makes the mmap() fail when it
   finds none.) */
static void test_big_mmap(size_t page_size) {
  long ret = int80_6(I386_mmap2, 0, BIG_LEN, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  unsigned char* p;
  unsigned char* vec;
  if (ret == -ENOMEM) {
    return;
  }
  p = result_ptr(ret);
  vec = malloc(BIG_LEN / page_size);
  test_assert(vec != NULL);
  /* mincore() fails with ENOMEM if part of the range isn't mapped */
  test_assert(0 == mincore(p, BIG_LEN, vec));
  free(vec);
  test_assert(0 == int80_2(I386_munmap, LOW(p), BIG_LEN));
}

#define HOLE_PAGES 16
#define FOUR_GB 0x100000000ULL

struct range {
  uint64_t start, end;
};

/* Fills all free address space below 4GB with PROT_NONE reservations, but
   for a hole of HOLE_PAGES pages, so that i386 mmap()s can only go there.
   (rr's chaos mode picks random addresses for them.) */
static void test_only_hole_is_free(size_t page_size) {
  static struct range mapped[4096];
  static struct range reserved[4096];
  int n_mapped = 0;
  int n_reserved = 0;
  uint64_t hole = 0;
  uint64_t gap_start = 0x10000;
  char line[512];
  FILE* f = fopen("/proc/self/maps", "r");
  int i;

  test_assert(f != NULL);
  while (fgets(line, sizeof(line), f)) {
    unsigned long long s, e;
    test_assert(2 == sscanf(line, "%llx-%llx", &s, &e));
    test_assert(n_mapped < 4096);
    mapped[n_mapped].start = s;
    mapped[n_mapped].end = e;
    ++n_mapped;
  }
  fclose(f);
  for (i = 0; i <= n_mapped && gap_start < FOUR_GB; ++i) {
    uint64_t gap_end = i < n_mapped ? mapped[i].start : FOUR_GB;
    if (gap_end > FOUR_GB) {
      gap_end = FOUR_GB;
    }
    if (gap_end > gap_start) {
      uint64_t start = gap_start;
      if (!hole && gap_end - gap_start >= (HOLE_PAGES + 1) * page_size &&
          gap_start >= 0x10000000) {
        hole = gap_start;
        start = gap_start + HOLE_PAGES * page_size;
      }
      void* p = mmap((void*)(uintptr_t)start, gap_end - start, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
                         MAP_FIXED_NOREPLACE,
                     -1, 0);
      test_assert(p == (void*)(uintptr_t)start);
      test_assert(n_reserved < 4096);
      reserved[n_reserved].start = start;
      reserved[n_reserved].end = gap_end;
      ++n_reserved;
    }
    if (i < n_mapped && mapped[i].end > gap_start) {
      gap_start = mapped[i].end;
    }
  }
  test_assert(hole != 0);

  for (i = 0; i < 20; ++i) {
    long ret = int80_6(I386_mmap2, 0, page_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char* p = result_ptr(ret);
    test_assert((uintptr_t)p >= hole &&
                (uintptr_t)p + page_size <= hole + HOLE_PAGES * page_size);
    p[0] = 1;
    test_assert(0 == int80_2(I386_munmap, LOW(p), page_size));
  }

  for (i = 0; i < n_reserved; ++i) {
    munmap((void*)(uintptr_t)reserved[i].start,
           reserved[i].end - reserved[i].start);
  }
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint32_t* old_mmap_args = int80_low_alloc(page_size);
  unsigned char* p;
  unsigned char* q;
  int fd;
  int i;

  int80_setup();
  signal(SIGSEGV, handle_segv);

  /* mmap2 of anonymous memory */
  p = result_ptr(int80_6(I386_mmap2, 0, 3 * page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  for (i = 0; i < 3; ++i) {
    p[i * page_size] = i + 1;
  }
  /* munmap of the middle page */
  test_assert(0 == int80_2(I386_munmap, LOW(p + page_size), page_size));
  test_assert(read_faults(p + page_size));
  test_assert(p[0] == 1 && p[2 * page_size] == 3);
  /* mprotect of the first page */
  test_assert(0 == int80_3(I386_mprotect, LOW(p), page_size, PROT_NONE));
  test_assert(read_faults(p));
  test_assert(0 == int80_3(I386_mprotect, LOW(p), page_size, PROT_READ));
  test_assert(p[0] == 1);
  /* mremap of the last page, to two pages elsewhere */
  q = result_ptr(int80_5(I386_mremap, LOW(p + 2 * page_size), page_size,
                         2 * page_size, MREMAP_MAYMOVE, 0));
  test_assert(q[0] == 3);
  q[page_size] = 4;
  test_assert(0 == int80_2(I386_munmap, LOW(q), 2 * page_size));
  test_assert(0 == int80_2(I386_munmap, LOW(p), page_size));

  /* mmap2 of a file, at a page offset */
  fd = open("/proc/self/exe", O_RDONLY);
  test_assert(fd >= 0);
  p = result_ptr(
      int80_6(I386_mmap2, 0, page_size, PROT_READ, MAP_PRIVATE, fd, 0));
  test_assert(memcmp(p, "\177ELF", 4) == 0);
  test_assert(0 == int80_2(I386_munmap, LOW(p), page_size));
  /* old_mmap, whose arguments are in memory */
  old_mmap_args[0] = 0;
  old_mmap_args[1] = page_size;
  old_mmap_args[2] = PROT_READ;
  old_mmap_args[3] = MAP_PRIVATE;
  old_mmap_args[4] = fd;
  old_mmap_args[5] = 0;
  p = result_ptr(int80_1(I386_old_mmap, LOW(old_mmap_args)));
  test_assert(memcmp(p, "\177ELF", 4) == 0);
  test_assert(0 == int80_2(I386_munmap, LOW(p), page_size));
  close(fd);

  test_big_mmap(page_size);
  test_only_hole_is_free(page_size);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
