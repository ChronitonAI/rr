/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* SysV IPC calls that the C library doesn't make: ipc() with a version in
   the high 16 bits of the call, and x86-32's direct msgctl and semctl with
   IPC_64 in cmd. */

#if defined(__i386__)

#define IPC_CALL_MSGRCV 12
#define IPC_CALL_SHMAT 21
#define IPC_CALL_SHMDT 22
#ifndef IPC_64
#define IPC_64 0x0100
#endif

#define MSG_TYPE 7

struct msg {
  long mtype;
  char text[8];
};

/* Only the compat msgctl and semctl of a 64-bit kernel ignore IPC_64 in
   cmd. A 32-bit kernel fails the direct calls with EINVAL. */
static int is_64bit_kernel(void) {
  struct utsname buf;
  test_assert(0 == uname(&buf));
  return strcmp(buf.machine, "x86_64") == 0;
}

static int is_filled(const void* p, size_t size, unsigned char c) {
  const unsigned char* bytes = p;
  size_t i;
  for (i = 0; i < size; ++i) {
    if (bytes[i] != c) {
      return 0;
    }
  }
  return 1;
}

static void check_shm(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int shmid = shmget(IPC_PRIVATE, page_size, 0600);
  test_assert(shmid >= 0);
  char* first = shmat(shmid, NULL, 0);
  test_assert(first != (char*)-1);
  /* The segment goes away when the last attachment does. Linux still
     attaches it by id until then. */
  test_assert(0 == shmctl(shmid, IPC_RMID, NULL));

  long ret = syscall(RR_ipc, IPC_CALL_SHMAT | (1 << 16), shmid, 0, NULL, NULL);
  test_assert(ret == -1 && errno == EINVAL);

  unsigned long raddr = 0;
  ret = syscall(RR_ipc, IPC_CALL_SHMAT | (2 << 16), shmid, 0, &raddr, NULL);
  test_assert(ret == 0);
  char* second = (char*)raddr;
  test_assert(second != NULL && second != first);
  second[0] = 'x';
  test_assert(first[0] == 'x');

  ret = syscall(RR_ipc, IPC_CALL_SHMDT | (1 << 16), 0, 0, 0, second);
  test_assert(ret == 0);
  test_assert(0 == shmdt(first));
}

static void check_msg(void) {
  int msqid = msgget(IPC_PRIVATE, 0600);
  test_assert(msqid >= 0);

  struct msg m = { MSG_TYPE, "hello" };
  test_assert(0 == msgsnd(msqid, &m, sizeof(m.text), 0));

  struct msg* out;
  ALLOCATE_GUARD(out, 'm');
  /* Version 1 passes the message buffer directly and msgtyp in the sixth
     argument. */
  long ret = syscall(RR_ipc, IPC_CALL_MSGRCV | (1 << 16), msqid,
                     sizeof(out->text), 0, out, MSG_TYPE);
  test_assert(ret == (long)sizeof(out->text));
  VERIFY_GUARD(out);
  test_assert(out->mtype == MSG_TYPE);
  test_assert(0 == memcmp(out->text, m.text, sizeof(m.text)));

  struct msqid_ds ds;
  memset(&ds, 0xff, sizeof(ds));
  /* The kernel checks for cmd == IPC_STAT to return 0, so this returns
     the id. */
  ret = syscall(RR_msgctl, msqid, IPC_STAT | IPC_64, &ds);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("msgctl syscall not supported");
  } else if (ret == -1 && errno == EINVAL && !is_64bit_kernel()) {
    test_assert(is_filled(&ds, sizeof(ds), 0xff));
  } else {
    test_assert(ret >= 0);
    test_assert(ds.msg_perm.uid == geteuid());
    test_assert(ds.msg_perm.mode == 0600);
    test_assert(ds.msg_qnum == 0);
  }

  test_assert(0 == msgctl(msqid, IPC_RMID, NULL));
}

static void check_sem(void) {
  int semid = semget(IPC_PRIVATE, 3, 0600);
  test_assert(semid >= 0);

  struct semid_ds ds;
  memset(&ds, 0xff, sizeof(ds));
  long ret = syscall(RR_semctl, semid, 0, IPC_STAT | IPC_64, &ds);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("semctl syscall not supported");
  } else {
    if (ret == -1 && errno == EINVAL && !is_64bit_kernel()) {
      test_assert(is_filled(&ds, sizeof(ds), 0xff));
    } else {
      test_assert(ret >= 0);
      test_assert(ds.sem_perm.uid == geteuid());
      test_assert(ds.sem_perm.mode == 0600);
      test_assert(ds.sem_nsems == 3);
    }

    unsigned short (*values)[3];
    ALLOCATE_GUARD(values, 'v');
    ret = syscall(RR_semctl, semid, 0, GETALL | IPC_64, values);
    test_assert(ret == -1 && errno == EINVAL);
    VERIFY_GUARD(values);
  }

  test_assert(0 == semctl(semid, 0, IPC_RMID));
}

#endif

int main(void) {
#if defined(__i386__)
  check_shm();
  /* A private IPC namespace removes the queue and the semaphore set when
     the test exits, however it exits. Without privileges they live in the
     current namespace until the test removes them. */
  if (unshare(CLONE_NEWIPC) == -1) {
    test_assert(errno == EPERM || errno == EINVAL);
  }
  check_msg();
  check_sem();
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
