/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"

/* SysV IPC ids belong to the caller's IPC namespace. rr has to size
   semctl(GETALL) and shmat() the way the kernel does for the tracee:
   GETALL on an invalid id just fails, and in a child with its own IPC
   namespace, GETALL and shmat() use the set and the segment the child
   created there, whatever has the same id in rr's namespace. On x86-64,
   GETALL also runs through int $0x80, as an x86-32 syscall. */

#ifdef _SEM_SEMUN_UNDEFINED
union semun {
  int val;
  struct semid_ds* buf;
  unsigned short int* array;
  struct seminfo* __buf;
};
#endif

static size_t page_size;

/* The number of semaphores in set 0 of our IPC namespace, 0 if we can't
   stat it. */
static int sem_count_of_id_0(void) {
  struct semid_ds ds;
  union semun un_arg;
  un_arg.buf = &ds;
  if (semctl(0, 0, IPC_STAT, un_arg) < 0) {
    return 0;
  }
  return ds.sem_nsems;
}

/* The number of pages of shm segment 0 of our IPC namespace, 0 if we can't
   stat it. */
static size_t shm_pages_of_id_0(void) {
  struct shmid_ds ds;
  if (shmctl(0, IPC_STAT, &ds) < 0) {
    return 0;
  }
  return (ds.shm_segsz + page_size - 1) / page_size;
}

static void check_getall_invalid_id(void) {
  unsigned short values[4];
  union semun un_arg;
  un_arg.array = values;
  test_assert(-1 == semctl(-1, 0, GETALL, un_arg));
  test_assert(errno == EINVAL);
#if defined(__i386__) && defined(SYS_semctl)
  /* glibc uses ipc(SEMCTL) here. Also use the direct syscall, which x86-32
     has since Linux 5.1:
     https://github.com/torvalds/linux/commit/0d6040d4681735dfc47565de288525de405a5c99 */
  test_assert(-1 == syscall(SYS_semctl, -1, 0, GETALL, values));
  test_assert(errno == EINVAL || errno == ENOSYS);
#endif
}

static void check_values(unsigned short* values, int nsems) {
  int i;
  for (i = 0; i < nsems; ++i) {
    test_assert(values[i] == i + 1);
  }
}

#ifdef __x86_64__
#define SYS32_ipc 117
#define SYS32_semctl 394
#define IPC_CALL_SEMCTL 3 /* SEMCTL in linux/ipc.h */

static long int80_syscall(long nr, long a, long b, long c, long d, long e) {
  long ret;
  __asm__ __volatile__("int $0x80"
                       : "=a"(ret)
                       : "a"(nr), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e)
                       : "memory", "r8", "r9", "r10", "r11");
  return ret;
}

static void check_int80_getall(int semid, int nsems) {
  size_t size = nsems * sizeof(unsigned short);
  size_t map_size =
      (sizeof(uint32_t) + size + page_size - 1) / page_size * page_size;
  /* x86-32 syscalls take 32-bit pointers. */
  char* low = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
  uint32_t* cell;
  unsigned short* values;
  long ret;

  test_assert(low != MAP_FAILED);
  cell = (uint32_t*)low;
  values = (unsigned short*)(low + sizeof(uint32_t));

  /* ipc(SEMCTL) reads the array pointer from *cell. */
  *cell = (uint32_t)(uintptr_t)values;
  ret = int80_syscall(SYS32_ipc, IPC_CALL_SEMCTL, semid, 0, GETALL,
                      (uintptr_t)cell);
  test_assert(ret == 0);
  check_values(values, nsems);

  memset(values, 0, size);
  ret = int80_syscall(SYS32_semctl, semid, 0, GETALL, (uintptr_t)values, 0);
  if (ret == 0) {
    check_values(values, nsems);
  } else {
    test_assert(ret == -ENOSYS);
  }

  test_assert(0 == munmap(low, map_size));
}
#endif

static void check_sem(int nsems) {
  size_t size = nsems * sizeof(unsigned short);
  unsigned short* values = allocate_guard(size, 'v');
  union semun un_arg;
  int semid;
  int i;

  semid = semget(IPC_PRIVATE, nsems, 0600);
  test_assert(semid >= 0);
  atomic_printf("semaphore set %d with %d semaphores\n", semid, nsems);

  for (i = 0; i < nsems; ++i) {
    values[i] = i + 1;
  }
  un_arg.array = values;
  test_assert(0 == semctl(semid, 0, SETALL, un_arg));

  memset(values, 0, size);
  test_assert(0 == semctl(semid, 0, GETALL, un_arg));
  verify_guard(size, values);
  check_values(values, nsems);

#if defined(__i386__) && defined(SYS_semctl)
  /* glibc uses ipc(SEMCTL) here. Also use the direct syscall. */
  memset(values, 0, size);
  if (0 == syscall(SYS_semctl, semid, 0, GETALL, values)) {
    verify_guard(size, values);
    check_values(values, nsems);
  } else {
    test_assert(errno == ENOSYS);
  }
#endif

#ifdef __x86_64__
  check_int80_getall(semid, nsems);
#endif

  test_assert(0 == semctl(semid, 0, IPC_RMID));
  free_guard(size, values);
}

static void check_shm(size_t pages) {
  size_t size = pages * page_size;
  char* p;
  int shmid;

  shmid = shmget(IPC_PRIVATE, size, 0600);
  test_assert(shmid >= 0);
  atomic_printf("shm segment %d with %zu pages\n", shmid, pages);

  p = shmat(shmid, NULL, 0);
  test_assert(p != (char*)-1);
  p[size - 1] = 'x';
  test_assert(p[size - 1] == 'x');

#if defined(__i386__) && defined(SYS_shmat)
  /* glibc uses ipc(SHMAT) here. Also use the direct syscall. */
  {
    long ret = syscall(SYS_shmat, shmid, NULL, 0);
    if (ret == -1) {
      test_assert(errno == ENOSYS);
    } else {
      char* p2 = (char*)ret;
      test_assert(p2[size - 1] == 'x');
      p2[size - 1] = 'y';
      test_assert(p[size - 1] == 'y');
      test_assert(0 == shmdt(p2));
    }
  }
#endif

  test_assert(0 == shmdt(p));
  test_assert(0 == shmctl(shmid, IPC_RMID, NULL));
}

static int run_child(int nsems, size_t shm_pages) {
  if (try_setup_ns(CLONE_NEWIPC) < 0) {
    return 0;
  }

  check_sem(nsems);
  check_shm(shm_pages);
  return 0;
}

int main(void) {
  int nsems;
  size_t shm_pages;
  pid_t child;
  int status;

  page_size = sysconf(_SC_PAGESIZE);

  check_getall_invalid_id();

  /* A new IPC namespace gives its first semaphore set and its first shm
     segment id 0. Make them larger than whatever has id 0 here. */
  nsems = sem_count_of_id_0() + 5;
  shm_pages = shm_pages_of_id_0() + 3;

  child = fork();
  test_assert(child >= 0);
  if (child == 0) {
    return run_child(nsems, shm_pages);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
