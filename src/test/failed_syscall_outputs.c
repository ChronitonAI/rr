/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"
#include "nsutils.h"

#include <linux/fuse.h>
#include <linux/net.h>
#include <sys/timex.h>

/* Each case makes a syscall that stores an output and then fails, and prints
   what it finds in the output. Replay must store the output too. */

#ifndef AT_HANDLE_MNT_ID_UNIQUE
#define AT_HANDLE_MNT_ID_UNIQUE 0x001
#endif
#ifndef FS_IOC_GETVERSION
#define FS_IOC_GETVERSION _IOR('v', 1, long)
#endif

#define RR_P_PIDFD 3
#define RR_BPF_PROG_LOAD 5
#define RR_BPF_BTF_LOAD 18

static size_t page_size;

static int count_bytes(const char* p, size_t size, char c) {
  int count = 0;
  size_t i;
  for (i = 0; i < size; ++i) {
    count += p[i] == c;
  }
  return count;
}

static void run_in_child(void (*f)(void)) {
  int status;
  pid_t child = fork();
  test_assert(child >= 0);
  if (child == 0) {
    f();
    exit(0);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void timer_create_case(void) {
  /* The CPU clock of a process that doesn't exist (pid 0x0ffffff0 is above
     the kernel's PID_MAX_LIMIT), encoded as MAKE_PROCESS_CPUCLOCK does */
  clockid_t clock = (clockid_t)(~0x0ffffff0u << 3) | 2;
  int timer_id = -1;

  /* timer_create() stores the timer id before the clock fails to create the
     timer. */
  test_assert(-1 == syscall(RR_timer_create, clock, NULL, &timer_id));
  test_assert(errno == EINVAL);
  test_assert(timer_id >= 0);
  atomic_printf("timer_create: timer id %d\n", timer_id);
}

static void mincore_case(void) {
  unsigned char vec[2] = { 0, 0 };
  char* p = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  *p = 1;

  /* mincore() stores the state of the pages before an unmapped one, then
     fails with ENOMEM. */
  test_assert(-1 == mincore(p, 2 * page_size, vec));
  test_assert(errno == ENOMEM);
  test_assert(vec[0] & 1);
  atomic_printf("mincore: vec %d %d\n", vec[0], vec[1]);
  test_assert(0 == munmap(p, page_size));
}

static void get_mempolicy_case(void) {
  /* A nodemask larger than a page */
  unsigned long maxnode = 8 * page_size + 2;
  int mode = -1;
  long ret;
  unsigned long* nodemask = (unsigned long*)mmap(
      NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
      -1, 0);
  test_assert(nodemask != MAP_FAILED);

  /* get_mempolicy() stores the mode before it fails to copy the nodemask. */
  ret = syscall(RR_get_mempolicy, &mode, nodemask, maxnode, NULL, 0);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("get_mempolicy: not supported");
    return;
  }
  test_assert(ret == -1 && errno == EINVAL);
  test_assert(mode >= 0);
  atomic_printf("get_mempolicy: mode %d\n", mode);
}

static void adjtimex_case(void) {
  struct timex tx;
  int ret;
  memset(&tx, 0xaa, sizeof(tx));
  /* The kernel's ADJ_ADJTIME without ADJ_OFFSET is invalid */
  tx.modes = ADJ_OFFSET_SINGLESHOT & ~ADJ_OFFSET;

  /* For 32-bit tracees, adjtimex() writes the structure back when it
     fails, with the fields it doesn't read zeroed. */
  ret = syscall(RR_adjtimex, &tx);
  test_assert(ret == -1 && errno == EINVAL);
  atomic_printf("adjtimex: %d bytes still 0xaa\n",
                count_bytes((char*)&tx, sizeof(tx), (char)0xaa));
}

static void socketpair_case(void) {
  int sv[2] = { -1, -1 };

  /* socketpair() stores the fds before it creates the sockets, which fails
     for AF_INET. */
  test_assert(-1 == socketpair(AF_INET, SOCK_STREAM, 0, sv));
  test_assert(errno == EOPNOTSUPP);
  atomic_printf("socketpair: fds %d %d\n", sv[0], sv[1]);

#if defined(__i386__)
  {
    unsigned long args[4] = { AF_INET, SOCK_STREAM, 0, (unsigned long)sv };
    sv[0] = sv[1] = -1;
    test_assert(-1 == syscall(RR_socketcall, SYS_SOCKETPAIR, args));
    test_assert(errno == EOPNOTSUPP);
    atomic_printf("socketcall(SYS_SOCKETPAIR): fds %d %d\n", sv[0], sv[1]);
  }
#endif
}

static void waitid_case(void) {
  siginfo_t info;
  int pidfd = syscall(RR_pidfd_open, getppid(), 0);
  if (pidfd < 0) {
    test_assert(errno == ENOSYS);
    atomic_puts("waitid: pidfd_open not supported");
    return;
  }
  memset(&info, 0xaa, sizeof(info));

  /* waitid() stores some fields of *infop whatever the result. Our parent
     isn't our child, so this fails with ECHILD. */
  test_assert(-1 == syscall(RR_waitid, RR_P_PIDFD, pidfd, &info, WEXITED,
                            NULL));
  test_assert(errno == ECHILD);
  test_assert(info.si_signo == 0 && info.si_pid == 0);
  atomic_printf("waitid: si_signo %d si_code %d si_pid %d\n", info.si_signo,
                info.si_code, info.si_pid);
  test_assert(0 == close(pidfd));
}

static void perf_event_open_case(void) {
  struct perf_event_attr attr;
  long ret;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = 1;

  /* perf_event_open() stores the size of its perf_event_attr in attr->size
     and fails with E2BIG. */
  ret = syscall(RR_perf_event_open, &attr, 0, -1, -1, 0);
  if (ret == -1 && (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
    atomic_puts("perf_event_open: not permitted");
    return;
  }
  test_assert(ret == -1 && errno == E2BIG);
  test_assert(attr.size > 1);
  atomic_printf("perf_event_open: size %u\n", attr.size);
}

struct sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

static void sched_setattr_case(void) {
  struct sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = 1;

  /* sched_setattr() stores the size of its sched_attr in attr->size and
     fails with E2BIG. */
  test_assert(-1 == syscall(RR_sched_setattr, 0, &attr, 0));
  test_assert(errno == E2BIG);
  test_assert(attr.size > 1);
  atomic_printf("sched_setattr: size %u\n", attr.size);
}

static void name_to_handle_at_case(void) {
  struct file_handle handle;
  int mount_id = -1;
  uint64_t unique_mount_id = UINT64_MAX;
  long ret;

  /* name_to_handle_at() reads handle_bytes. When the handle doesn't fit, it
     stores the mount id and the size the handle needs, and fails with
     EOVERFLOW. */
  handle.handle_bytes = 0;
  handle.handle_type = -1;
  ret = syscall(RR_name_to_handle_at, AT_FDCWD, ".", &handle, &mount_id, 0);
  if (ret == -1 && errno == EOPNOTSUPP) {
    atomic_puts("name_to_handle_at: not supported");
    return;
  }
  test_assert(ret == -1 && errno == EOVERFLOW);
  test_assert(handle.handle_bytes > 0);
  test_assert(mount_id >= 0);
  atomic_printf("name_to_handle_at: handle_bytes %u mount id %d\n",
                handle.handle_bytes, mount_id);

  handle.handle_bytes = 0;
  ret = syscall(RR_name_to_handle_at, AT_FDCWD, ".", &handle,
                &unique_mount_id, AT_HANDLE_MNT_ID_UNIQUE);
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("name_to_handle_at: AT_HANDLE_MNT_ID_UNIQUE not supported");
    return;
  }
  test_assert(ret == -1 && errno == EOVERFLOW);
  /* The kernel stored all 8 bytes. */
  test_assert((uint32_t)(unique_mount_id >> 32) != UINT32_MAX);
  atomic_printf("name_to_handle_at: unique mount id %llx\n",
                (unsigned long long)unique_mount_id);
}

struct bpf_insn_raw {
  uint8_t code;
  uint8_t regs;
  int16_t off;
  int32_t imm;
};

/* The BPF_PROG_LOAD part of union bpf_attr, up to log_true_size */
struct prog_load_attr {
  uint32_t prog_type;
  uint32_t insn_cnt;
  uint64_t insns __attribute__((aligned(8)));
  uint64_t license __attribute__((aligned(8)));
  uint32_t log_level;
  uint32_t log_size;
  uint64_t log_buf __attribute__((aligned(8)));
  uint32_t kern_version;
  uint32_t prog_flags;
  char prog_name[16];
  uint32_t prog_ifindex;
  uint32_t expected_attach_type;
  uint32_t prog_btf_fd;
  uint32_t func_info_rec_size;
  uint64_t func_info __attribute__((aligned(8)));
  uint32_t func_info_cnt;
  uint32_t line_info_rec_size;
  uint64_t line_info __attribute__((aligned(8)));
  uint32_t line_info_cnt;
  uint32_t attach_btf_id;
  uint32_t attach_prog_fd;
  uint32_t core_relo_cnt;
  uint64_t fd_array __attribute__((aligned(8)));
  uint64_t core_relos __attribute__((aligned(8)));
  uint32_t core_relo_rec_size;
  uint32_t log_true_size;
};

/* The BPF_BTF_LOAD part of union bpf_attr */
struct btf_load_attr {
  uint64_t btf __attribute__((aligned(8)));
  uint64_t btf_log_buf __attribute__((aligned(8)));
  uint32_t btf_size;
  uint32_t btf_log_size;
  uint32_t btf_log_level;
  uint32_t btf_log_true_size;
};

static void bpf_case(void) {
  /* A program that returns without setting r0 */
  struct bpf_insn_raw insn = { 0x95 /* BPF_JMP | BPF_EXIT */, 0, 0, 0 };
  struct prog_load_attr attr;
  struct btf_load_attr btf_attr;
  char btf[24];
  char* log = (char*)malloc(4096);
  long ret;
  test_assert(log != NULL);

  memset(&attr, 0, sizeof(attr));
  attr.prog_type = 1; /* BPF_PROG_TYPE_SOCKET_FILTER */
  attr.insn_cnt = 1;
  attr.insns = (uintptr_t)&insn;
  attr.license = (uintptr_t) "GPL";
  attr.log_level = 1;
  attr.log_size = 4096;
  attr.log_buf = (uintptr_t)log;
  memset(log, 0, 4096);

  /* The verifier writes its log as it goes, and the kernel stores
     log_true_size whatever the result. */
  ret = syscall(RR_bpf, RR_BPF_PROG_LOAD, &attr, sizeof(attr));
  if (ret == -1 && (errno == EPERM || errno == ENOSYS)) {
    atomic_puts("bpf: not permitted");
    free(log);
    return;
  }
  test_assert(ret == -1 && errno == EACCES);
  test_assert(strlen(log) > 0);
  atomic_printf("bpf(BPF_PROG_LOAD): log_true_size %u log %d bytes\n",
                attr.log_true_size, (int)strlen(log));

  /* So does BPF_BTF_LOAD, for BTF with a bad header. */
  memset(btf, 0, sizeof(btf));
  memset(&btf_attr, 0, sizeof(btf_attr));
  btf_attr.btf = (uintptr_t)btf;
  btf_attr.btf_size = sizeof(btf);
  btf_attr.btf_log_buf = (uintptr_t)log;
  btf_attr.btf_log_size = 4096;
  btf_attr.btf_log_level = 1;
  memset(log, 0, 4096);
  test_assert(-1 == syscall(RR_bpf, RR_BPF_BTF_LOAD, &btf_attr,
                            sizeof(btf_attr)));
  test_assert(errno == EINVAL);
  test_assert(strlen(log) > 0);
  atomic_printf("bpf(BPF_BTF_LOAD): btf_log_true_size %u log %d bytes\n",
                btf_attr.btf_log_true_size, (int)strlen(log));
  free(log);
}

#define FUSE_FILE_NODEID 2
#define FUSE_IOCTL_DATA 0x55667788

static void fuse_reply(int dev, uint64_t unique, int error, const void* data,
                       size_t size) {
  char buf[sizeof(struct fuse_out_header) + 256];
  struct fuse_out_header* header = (struct fuse_out_header*)buf;
  test_assert(size <= 256);
  header->len = sizeof(*header) + size;
  header->error = error;
  header->unique = unique;
  memcpy(buf + sizeof(*header), data, size);
  test_assert((ssize_t)header->len == write(dev, buf, header->len));
}

static void fuse_fill_attr(struct fuse_attr* attr, uint64_t nodeid) {
  memset(attr, 0, sizeof(*attr));
  attr->ino = nodeid;
  attr->mode = nodeid == FUSE_FILE_NODEID ? S_IFREG | 0644 : S_IFDIR | 0755;
  attr->nlink = 1;
  attr->blksize = 4096;
}

/* A FUSE server for a filesystem with one file, whose ioctls send output
   data and fail with EPERM. Returns when the file is released. */
static void fuse_serve(int dev) {
  static char buf[FUSE_MIN_READ_BUFFER];
  while (1) {
    ssize_t len = read(dev, buf, sizeof(buf));
    struct fuse_in_header* in = (struct fuse_in_header*)buf;
    if (len < 0 && (errno == ENODEV || errno == ECONNABORTED)) {
      /* The filesystem went away. */
      return;
    }
    test_assert(len >= (ssize_t)sizeof(*in));
    switch (in->opcode) {
      case FUSE_INIT: {
        struct fuse_init_out out;
        memset(&out, 0, sizeof(out));
        out.major = FUSE_KERNEL_VERSION;
        out.minor = 31;
        out.max_write = 4096;
        fuse_reply(dev, in->unique, 0, &out, sizeof(out));
        break;
      }
      case FUSE_LOOKUP: {
        struct fuse_entry_out out;
        memset(&out, 0, sizeof(out));
        out.nodeid = FUSE_FILE_NODEID;
        fuse_fill_attr(&out.attr, FUSE_FILE_NODEID);
        fuse_reply(dev, in->unique, 0, &out, sizeof(out));
        break;
      }
      case FUSE_GETATTR: {
        struct fuse_attr_out out;
        memset(&out, 0, sizeof(out));
        fuse_fill_attr(&out.attr, in->nodeid);
        fuse_reply(dev, in->unique, 0, &out, sizeof(out));
        break;
      }
      case FUSE_OPEN:
      case FUSE_OPENDIR: {
        struct fuse_open_out out;
        memset(&out, 0, sizeof(out));
        fuse_reply(dev, in->unique, 0, &out, sizeof(out));
        break;
      }
      case FUSE_IOCTL: {
        struct fuse_ioctl_in* ioctl_in = (struct fuse_ioctl_in*)(in + 1);
        struct {
          struct fuse_ioctl_out out;
          uint32_t data;
        } reply;
        memset(&reply, 0, sizeof(reply));
        reply.out.result = -EPERM;
        reply.data = FUSE_IOCTL_DATA;
        test_assert(ioctl_in->out_size >= sizeof(reply.data));
        fuse_reply(dev, in->unique, 0, &reply, sizeof(reply));
        break;
      }
      case FUSE_FORGET:
      case FUSE_BATCH_FORGET:
      case FUSE_INTERRUPT:
        break;
      case FUSE_RELEASE: {
        /* The filesystem may have gone away. */
        struct fuse_out_header out = { sizeof(out), 0, in->unique };
        test_assert((ssize_t)sizeof(out) == write(dev, &out, sizeof(out)) ||
                    errno == ENOENT || errno == ENODEV);
        return;
      }
      default:
        fuse_reply(dev, in->unique, -ENOSYS, NULL, 0);
        break;
    }
  }
}

/* rr finds files on FUSE filesystems that aren't in the task's mounts
   through the FUSE control filesystem. */
static int fusectl_mounted(void) {
  struct statfs buf;
  return 0 == statfs("/sys/fs/fuse/connections", &buf) &&
         buf.f_type == 0x65735543;
}

static void fuse_case(void) {
  char mount_point[] = "fuse-XXXXXX";
  char path[PATH_MAX];
  char options[128];
  int ready[2];
  int status;
  long version;
  pid_t server;
  int dev;
  int fd;
  char ch;

  if (-1 == try_setup_ns(CLONE_NEWNS)) {
    return;
  }
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
    test_assert(errno == EPERM || errno == EACCES);
    atomic_puts("FUSE: mount not permitted");
    return;
  }
  dev = open("/dev/fuse", O_RDWR);
  if (dev < 0) {
    atomic_puts("FUSE: can't open /dev/fuse");
    return;
  }
  test_assert(NULL != mkdtemp(mount_point));
  sprintf(options, "fd=%d,rootmode=40000,user_id=0,group_id=0", dev);
  if (mount("failed_syscall_outputs", mount_point, "fuse", MS_NOSUID | MS_NODEV,
            options)) {
    test_assert(errno == EPERM || errno == EACCES);
    atomic_puts("FUSE: mount not permitted");
    test_assert(0 == rmdir(mount_point));
    return;
  }

  /* The server must not be a tracee: rr waits for an ioctl() to finish
     before it runs other tracees. */
  test_assert(0 == pipe(ready));
  server = fork();
  test_assert(server >= 0);
  if (server == 0) {
    if (running_under_rr()) {
      rr_detach_teleport();
    }
    test_assert(1 == write(ready[1], "r", 1));
    fuse_serve(dev);
    exit(0);
  }
  test_assert(1 == read(ready[0], &ch, 1));

  sprintf(path, "%s/file", mount_point);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  version = -1;

  /* The kernel stores the output data that the server sent, then returns
     the server's error. */
  test_assert(-1 == ioctl(fd, FS_IOC_GETVERSION, &version));
  test_assert(errno == EPERM);
  test_assert((uint32_t)version == FUSE_IOCTL_DATA);
  atomic_printf("FUSE: ioctl data %x\n", (uint32_t)version);

  /* The same after the filesystem was unmounted while the file is open */
  test_assert(0 == umount2(mount_point, MNT_DETACH));
  if (fusectl_mounted()) {
    version = -1;
    test_assert(-1 == ioctl(fd, FS_IOC_GETVERSION, &version));
    test_assert(errno == EPERM);
    test_assert((uint32_t)version == FUSE_IOCTL_DATA);
    atomic_printf("FUSE: ioctl data after unmount %x\n", (uint32_t)version);
  } else {
    atomic_puts("FUSE: no FUSE control filesystem");
  }
  test_assert(0 == close(fd));

  test_assert(server == waitpid(server, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  test_assert(0 == rmdir(mount_point));
}

int main(void) {
  page_size = sysconf(_SC_PAGESIZE);

  timer_create_case();
  mincore_case();
  get_mempolicy_case();
  adjtimex_case();
  socketpair_case();
  waitid_case();
  perf_event_open_case();
  sched_setattr_case();
  name_to_handle_at_case();
  bpf_case();
  run_in_child(fuse_case);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
