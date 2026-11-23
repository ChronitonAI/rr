/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SHM_SIZE 4096
#define NSEMS 3

#ifndef MSG_STAT_ANY
#define MSG_STAT_ANY 13
#endif
#ifndef SHM_STAT_ANY
#define SHM_STAT_ANY 15
#endif
#ifndef SEM_STAT_ANY
#define SEM_STAT_ANY 20
#endif

#ifdef _SEM_SEMUN_UNDEFINED
union semun {
  int val;
  struct semid_ds* buf;
  unsigned short int* array;
  struct seminfo* __buf;
};
#endif

#if defined(__i386__)
#ifndef SEMCTL
#define SEMCTL 3
#endif
#ifndef IPC_64
#define IPC_64 0x0100
#endif
#endif

/* *_STAT and *_STAT_ANY take an index into the kernel's array of objects,
   not an id, and return the id of the object at that index. *_STAT finds
   the index of our object, then *_STAT_ANY reads it. */

/* glibc's semctl() passes no argument with SEM_STAT_ANY before 2.33. */
static int semctl_stat_any(int index, struct semid_ds* ds) {
#if defined(__i386__)
  union semun un_arg;
  un_arg.buf = ds;
  /* glibc's semctl() makes this call on x86-32. */
  return syscall(SYS_ipc, SEMCTL, index, 0, SEM_STAT_ANY | IPC_64, &un_arg);
#else
  return syscall(SYS_semctl, index, 0, SEM_STAT_ANY, ds);
#endif
}

/* Returns 0 if the kernel doesn't support MSG_STAT_ANY. */
static int msg_stat_any(void) {
  struct msginfo info;
  struct msqid_ds ds;
  int id = msgget(IPC_PRIVATE, 0600);
  int max_index;
  int i;
  int ret;
  test_assert(id >= 0);

  max_index = msgctl(0, MSG_INFO, (struct msqid_ds*)&info);
  test_assert(max_index >= 0);
  for (i = 0; i <= max_index; ++i) {
    if (msgctl(i, MSG_STAT, &ds) == id) {
      break;
    }
  }
  test_assert(i <= max_index);

  memset(&ds, 'm', sizeof(ds));
  ret = msgctl(i, MSG_STAT_ANY, &ds);
  if (ret < 0 && errno == EINVAL) {
    test_assert(0 == msgctl(id, IPC_RMID, NULL));
    return 0;
  }
  test_assert(ret == id);
  atomic_printf("MSG_STAT_ANY: index %d -> id %d mode %#o qbytes %lu\n", i, id,
                ds.msg_perm.mode, (unsigned long)ds.msg_qbytes);
  test_assert((ds.msg_perm.mode & 0777) == 0600);
  test_assert(ds.msg_qnum == 0);
  test_assert(ds.msg_qbytes > 0);

  test_assert(0 == msgctl(id, IPC_RMID, NULL));
  return 1;
}

static void shm_stat_any(void) {
  union {
    struct shmid_ds ds;
    struct shm_info info;
  } u;
  struct shmid_ds* ds;
  int id = shmget(IPC_PRIVATE, SHM_SIZE, 0600);
  int max_index;
  int i;
  test_assert(id >= 0);

  max_index = shmctl(0, SHM_INFO, &u.ds);
  test_assert(max_index >= 0);
  for (i = 0; i <= max_index; ++i) {
    if (shmctl(i, SHM_STAT, &u.ds) == id) {
      break;
    }
  }
  test_assert(i <= max_index);

  ALLOCATE_GUARD(ds, 's');
  test_assert(shmctl(i, SHM_STAT_ANY, ds) == id);
  VERIFY_GUARD(ds);
  atomic_printf("SHM_STAT_ANY: index %d -> id %d mode %#o segsz %lu\n", i, id,
                ds->shm_perm.mode, (unsigned long)ds->shm_segsz);
  test_assert((ds->shm_perm.mode & 0777) == 0600);
  test_assert(ds->shm_segsz == SHM_SIZE);
  test_assert(ds->shm_nattch == 0);

  test_assert(0 == shmctl(id, IPC_RMID, NULL));
}

static void sem_stat_any(void) {
  struct seminfo info;
  struct semid_ds stat_ds;
  struct semid_ds* ds;
  union semun un_arg;
  int id = semget(IPC_PRIVATE, NSEMS, 0600);
  int max_index;
  int i;
  test_assert(id >= 0);

  un_arg.__buf = &info;
  max_index = semctl(0, 0, SEM_INFO, un_arg);
  test_assert(max_index >= 0);
  un_arg.buf = &stat_ds;
  for (i = 0; i <= max_index; ++i) {
    if (semctl(i, 0, SEM_STAT, un_arg) == id) {
      break;
    }
  }
  test_assert(i <= max_index);

  ALLOCATE_GUARD(ds, 'e');
  test_assert(semctl_stat_any(i, ds) == id);
  VERIFY_GUARD(ds);
  atomic_printf("SEM_STAT_ANY: index %d -> id %d mode %#o nsems %lu\n", i, id,
                ds->sem_perm.mode, (unsigned long)ds->sem_nsems);
  test_assert((ds->sem_perm.mode & 0777) == 0600);
  test_assert(ds->sem_nsems == NSEMS);

  test_assert(0 == semctl(id, 0, IPC_RMID));
}

int main(void) {
  /* A private IPC namespace keeps our objects from outliving the test if
     it stops before removing them. Without one, use the shared
     namespace. */
  if (unshare(CLONE_NEWIPC) < 0 &&
      unshare(CLONE_NEWUSER | CLONE_NEWIPC) < 0) {
    atomic_printf("Using the shared IPC namespace: unshare failed with %s\n",
                  strerror(errno));
  }

  /* Kernels without MSG_STAT_ANY don't have SHM_STAT_ANY or SEM_STAT_ANY
     either. */
  if (!msg_stat_any()) {
    atomic_puts("MSG_STAT_ANY not supported");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  shm_stat_any();
  sem_stat_any();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
