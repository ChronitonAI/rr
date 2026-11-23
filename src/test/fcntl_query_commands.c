/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_F_GETOWNER_UIDS 17
#define TEST_F_DUPFD_QUERY 1027
#define TEST_F_CREATED_QUERY 1028
#define TEST_F_GETDELEG 1039
#define TEST_F_SETDELEG 1040

struct test_delegation {
  uint32_t d_flags;
  uint16_t d_type;
  uint16_t pad;
};

/* EINVAL means the kernel doesn't support the command (too old, or
   F_GETOWNER_UIDS without CONFIG_CHECKPOINT_RESTORE). */
static int unsupported(long ret, const char* name) {
  if (ret >= 0) {
    return 0;
  }
  test_assert(errno == EINVAL);
  atomic_printf("%s not supported\n", name);
  return 1;
}

int main(void) {
  int sockfds[2];
  int dup_fd;
  int created_fd;
  int reopened_fd;
  pid_t pid = getpid();
  uid_t* uids;
  struct test_delegation* deleg;
  long ret;

  test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds));

  test_assert(0 == syscall(SYS_fcntl, sockfds[0], F_SETOWN, pid));
  ret = syscall(SYS_fcntl, sockfds[0], F_GETOWN);
  test_assert(ret == pid);

  uids = allocate_guard(sizeof(*uids) * 2, 'u');
  ret = syscall(SYS_fcntl, sockfds[0], TEST_F_GETOWNER_UIDS, uids);
  if (!unsupported(ret, "F_GETOWNER_UIDS")) {
    test_assert(ret == 0);
    test_assert(uids[0] == getuid());
    test_assert(uids[1] == geteuid());
  }
  verify_guard(sizeof(*uids) * 2, uids);

  dup_fd = dup(sockfds[0]);
  test_assert(dup_fd >= 0);
  ret = syscall(SYS_fcntl, sockfds[0], TEST_F_DUPFD_QUERY, dup_fd);
  if (!unsupported(ret, "F_DUPFD_QUERY")) {
    test_assert(ret == 1);
    ret = syscall(SYS_fcntl, sockfds[0], TEST_F_DUPFD_QUERY, sockfds[1]);
    test_assert(ret == 0);
  }

  created_fd = open("created", O_RDWR | O_CREAT | O_EXCL, 0600);
  test_assert(created_fd >= 0);
  reopened_fd = open("created", O_RDWR);
  test_assert(reopened_fd >= 0);
  ret = syscall(SYS_fcntl, created_fd, TEST_F_CREATED_QUERY);
  if (!unsupported(ret, "F_CREATED_QUERY")) {
    test_assert(ret == 1);
    ret = syscall(SYS_fcntl, reopened_fd, TEST_F_CREATED_QUERY);
    test_assert(ret == 0);
  }

  ALLOCATE_GUARD(deleg, 'd');
  deleg->d_flags = 0;
  /* Not F_RDLCK, F_WRLCK or F_UNLCK. */
  deleg->d_type = 0xffff;
  deleg->pad = 0;
  ret = syscall(SYS_fcntl, created_fd, TEST_F_GETDELEG, deleg);
  if (!unsupported(ret, "F_GETDELEG")) {
    test_assert(ret == 0);
    test_assert(deleg->d_flags == 0);
    test_assert(deleg->d_type == F_UNLCK);
    test_assert(deleg->pad == 0);
  }
  VERIFY_GUARD(deleg);

  deleg->d_flags = 0;
  deleg->d_type = F_UNLCK;
  deleg->pad = 0;
  ret = syscall(SYS_fcntl, created_fd, TEST_F_SETDELEG, deleg);
  /* F_UNLCK without a delegation to remove fails with EAGAIN. EINVAL means
     the kernel or the filesystem doesn't support delegations. */
  test_assert(ret == 0 || errno == EAGAIN || errno == EINVAL);
  VERIFY_GUARD(deleg);

  test_assert(0 == close(reopened_fd));
  test_assert(0 == close(created_fd));
  test_assert(0 == unlink("created"));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
