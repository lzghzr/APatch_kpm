/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/current.h>
#include <kpmodule.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <syscall.h>
#include <uapi/linux/magic.h>
#include <uapi/linux/stat.h>

// The KP SDK has asm-generic fcntl.h but not the ARM64 overrides.
#define O_DIRECTORY 040000
#define O_NOFOLLOW 0100000
#include <uapi/asm-generic/fcntl.h>

#include "cfv2_utils.h"

#define CFV2_TARGET "/sys/fs/cgroup"
#define CFV2_V2 "/dev/cg2_bpf"
#define CFV2_V1 "/acct"
#define CFV2_SYSTEM 1000
#define CFV2_LOOKUP_FOLLOW 1
#define CFV2_LOOKUP_DIRECTORY 2
#define CFV2_ST_RDONLY 1
#define CFV2_MS_BIND 4096
#define CFV2_AT_REMOVEDIR 0x200
#define CFV2_PROT_RW 3
#define CFV2_MAP_PRIVATE_ANONYMOUS 0x22
#define CFV2_FOLL_WRITE 1

// Common VFS layouts and native AArch64 syscall output formats.
struct path {
  struct vfsmount* mnt;
  struct dentry* dentry;
};

struct cfv2_kstatfs {
  long type;
  long block_size;
  uint64_t counts[5];
  int32_t fsid[2];
  long name_len;
  long fragment_size;
  long flags;
  long spare[4];
};

struct cfv2_stat {
  uint64_t device;
  uint64_t inode;
  uint32_t mode;
  uint32_t links;
  uint32_t uid;
  uint32_t gid;
};

struct cfv2_dirent {
  uint64_t inode;
  int64_t off;
  uint16_t len;
  uint8_t type;
  char name[];
};

struct cfv2_uid_args {
  char target[sizeof(CFV2_TARGET)];
  char v1[sizeof(CFV2_V1)];
  char v2[sizeof(CFV2_V2)];
  char frozen[sizeof("frozen")];
  char unfrozen[sizeof("unfrozen")];
  char freeze[sizeof("cgroup.freeze")];
  char procs[sizeof("cgroup.procs")];
  char tasks[sizeof("tasks")];
  char one[2];
  uint64_t output[16];
};

static int (*task_work_add)(struct task_struct*, struct callback_head*, bool);
static struct mm_struct* (*get_task_mm)(struct task_struct*);
static void (*mmput)(struct mm_struct*);
static int (*access_process_vm)(struct task_struct*, unsigned long, void*, int, unsigned int);
static int (*kern_path)(const char*, unsigned int, struct path*);
static void (*path_put)(const struct path*);
static int (*vfs_statfs)(const struct path*, struct cfv2_kstatfs*);
static char* (*dentry_path_raw)(struct dentry*, char*, int);
static struct file* (*dentry_open)(const struct path*, int, const struct cred*);
static int (*get_unused_fd_flags)(unsigned int);
static void (*fd_install)(unsigned int, struct file*);
static void (*fput)(struct file*);

static bool mount_armed;
static unsigned int mount_queued;

static int check_namespace(void) {
  struct path self, init;
  int rc = kern_path("/proc/self/ns/mnt", CFV2_LOOKUP_FOLLOW, &self);
  if (rc)
    return rc;
  rc = kern_path("/proc/1/ns/mnt", CFV2_LOOKUP_FOLLOW, &init);
  if (!rc) {
    rc = self.mnt == init.mnt && self.dentry == init.dentry ? 0 : -EXDEV;
    path_put(&init);
  }
  path_put(&self);
  return rc;
}

static int check_source(struct path* src, const char* name, const char* uid0, const char* marker, long type) {
  struct path child;
  int rc = kern_path(uid0, CFV2_LOOKUP_DIRECTORY, &child);
  if (rc)
    return rc;
  rc = kern_path(name, CFV2_LOOKUP_DIRECTORY, src);
  if (rc) {
    path_put(&child);
    return rc == -ENOENT ? -EXDEV : rc;
  }
  bool same = child.mnt == src->mnt;
  path_put(&child);
  if (!same) {
    rc = -EXDEV;
    goto fail;
  }
  struct cfv2_kstatfs fs;
  rc = vfs_statfs(src, &fs);
  if (rc)
    goto fail;
  char path[4];
  char* root = dentry_path_raw(src->dentry, path, sizeof(path));
  // Early cgroup2 backports may report the old cgroup magic; the marker
  // below must still be cgroup.controllers on this exact mount.
  bool cgroup_type = fs.type == type || (type == CGROUP2_SUPER_MAGIC && fs.type == CGROUP_SUPER_MAGIC);
  if (!cgroup_type || IS_ERR(root) || strcmp(root, "/")) {
    rc = -EINVAL;
    goto fail;
  }
  if (fs.flags & CFV2_ST_RDONLY) {
    rc = -EROFS;
    goto fail;
  }
  rc = kern_path(marker, 0, &child);
  if (!rc) {
    same = child.mnt == src->mnt;
    path_put(&child);
    if (same)
      return 0;
    rc = -EXDEV;
  } else if (rc == -ENOENT) {
    rc = -ENODEV;
  }
fail:
  path_put(src);
  return rc;
}

static int open_dir(const struct path* path) {
  int offset = task_struct_offset.cred_offset;
  if (offset <= 0 || offset % sizeof(void*))
    return -EINVAL;
  const struct cred* cred = *(const struct cred**)((uintptr_t)current + offset);
  if (!cred)
    return -EINVAL;
  struct file* file = dentry_open(path, O_RDONLY, cred);
  if (IS_ERR(file))
    return PTR_ERR(file);
  int fd = get_unused_fd_flags(O_CLOEXEC);
  if (fd < 0)
    fput(file);
  else
    fd_install(fd, file);
  return fd;
}

static int check_empty_sysfs(const struct path* target, unsigned long output) {
  struct cfv2_kstatfs fs;
  int rc = vfs_statfs(target, &fs);
  if (rc || fs.type != SYSFS_MAGIC)
    return rc ? rc : -EBUSY;

  int fd = open_dir(target);
  if (fd < 0)
    return fd;
  uint64_t data[16];
  long len = raw_syscall3(__NR_getdents64, fd, output, sizeof(data));
  rc = len <= 0 ? len : -EIO;
  if (len > 0 && len <= sizeof(data) && access_process_vm(current, output, data, len, 0) == len) {
    size_t off = 0;
    size_t name_offset = offsetof(struct cfv2_dirent, name);
    while (off + name_offset < len) {
      const struct cfv2_dirent* d = (const void*)((const char*)data + off);
      size_t size = d->len;
      if (size <= name_offset + 1 || size % sizeof(uint64_t) || size > len - off)
        break;
      size_t room = size - name_offset;
      if (d->name[0] != '.'
          || (d->name[1] != '\0' && (room < 3 || d->name[1] != '.' || d->name[2] != '\0'))) {
        rc = -ENOTEMPTY;
        break;
      }
      off += size;
    }
    if (off == len) {
      long more = raw_syscall3(__NR_getdents64, fd, output, sizeof(data));
      rc = more > 0 ? -ENOTEMPTY : more;
    }
  }
  raw_syscall1(__NR_close, fd);
  return rc;
}

static int read_stat(int fd, unsigned long output, struct cfv2_stat* st) {
  int rc = raw_syscall2(__NR3264_fstat, fd, output);
  if (rc)
    return rc;
  return access_process_vm(current, output, st, sizeof(*st), 0) == sizeof(*st) ? 0 : -EFAULT;
}

static int group_access(int fd, unsigned long output, uint32_t type, bool created) {
  struct cfv2_stat st;
  int rc = read_stat(fd, output, &st);
  if (rc)
    return rc;
  if ((st.mode & S_IFMT) != type)
    return -EINVAL;
  unsigned int owner_bits = type == S_IFDIR ? 0700 : 0600;
  // Keep the native group/other bits on control files; only add owner access.
  unsigned int mode = type == S_IFDIR ? 0775 : (st.mode & 0777) | owner_bits;
  if (created) {
    if (st.uid != CFV2_SYSTEM || st.gid != CFV2_SYSTEM) {
      rc = raw_syscall3(__NR_fchown, fd, CFV2_SYSTEM, CFV2_SYSTEM);
      if (rc)
        return rc;
    }
    if ((st.mode & 07777) != mode) {
      rc = raw_syscall2(__NR_fchmod, fd, mode);
      if (rc)
        return rc;
    }
    rc = read_stat(fd, output, &st);
    if (rc)
      return rc;
    if ((st.mode & 07777) != mode)
      return -EIO;
  }
  return st.uid == CFV2_SYSTEM && st.gid == CFV2_SYSTEM && (st.mode & owner_bits) == owner_bits ? 0 : -EACCES;
}

static int prepare_group(int root, const struct cfv2_uid_args* args, bool v1, bool frozen, bool* created,
                         const char** stage) {
  const char* group = frozen ? args->frozen : args->unfrozen;
  unsigned long output = (unsigned long)args->output;
  int dir_flags = O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
  int file_flags = O_NOFOLLOW | O_CLOEXEC;
  *stage = frozen ? "mkdir frozen" : "mkdir unfrozen";
  int rc = raw_syscall3(__NR_mkdirat, root, (long)group, 0775);
  if (rc && rc != -EEXIST)
    return rc;
  *created = rc == 0;
  *stage = frozen ? "open frozen" : "open unfrozen";
  int fd = raw_syscall4(__NR_openat, root, (long)group, dir_flags, 0);
  if (fd < 0)
    return fd;

  // Grant Unix access only to the two reserved groups and their control files.
  // The existing UID groups, source root, and SELinux policy are left alone.
  *stage = frozen ? "frozen directory DAC" : "unfrozen directory DAC";
  rc = group_access(fd, output, S_IFDIR, *created);
  const char* controls[] = {args->freeze, args->procs, args->tasks};
  for (unsigned int i = 0; !rc && i < (v1 ? 3 : 2); ++i) {
    int flags = file_flags | (!i && *created && frozen ? O_RDWR : O_RDONLY);
    *stage = !i ? "open cgroup.freeze" : i == 1 ? "open cgroup.procs" : "open tasks";
    int file = raw_syscall4(__NR_openat, fd, (long)controls[i], flags, 0);
    if (file < 0) {
      rc = file;
      break;
    }
    *stage = !i ? "cgroup.freeze DAC" : i == 1 ? "cgroup.procs DAC" : "tasks DAC";
    rc = group_access(file, output, S_IFREG, *created);
    if (!rc && !i && *created && frozen) {
      *stage = "write frozen/cgroup.freeze";
      long written = raw_syscall3(__NR_write, file, (long)args->one, 2);
      rc = written == 2 ? 0 : written < 0 ? written : -EIO;
    }
    raw_syscall1(__NR_close, file);
    if (!rc && !i) {
      *stage = frozen ? "read frozen/cgroup.freeze" : "read unfrozen/cgroup.freeze";
      file = raw_syscall4(__NR_openat, fd, (long)args->freeze, file_flags, 0);
      if (file < 0) {
        rc = file;
        break;
      }
      char state[2];
      long count = raw_syscall3(__NR_read, file, output, sizeof(state));
      if (count != sizeof(state) || access_process_vm(current, output, state, sizeof(state), 0) != sizeof(state))
        rc = count < 0 ? count : -EIO;
      else if (state[0] != (frozen ? '1' : '0') || state[1] != '\n')
        rc = -EIO;
      raw_syscall1(__NR_close, file);
    }
  }
  raw_syscall1(__NR_close, fd);
  return rc;
}

static void discard_group(int root, const char* name, const char* label) {
  int rc = raw_syscall3(__NR_unlinkat, root, (long)name, CFV2_AT_REMOVEDIR);
  if (rc)
    logkm("UID setup: could not remove newly created %s: %d\n", label, rc);
}

static int setup_uid_tree(const struct cfv2_uid_args* args, const char** stage) {
  struct path src, target, parent;
  *stage = "UID source";
  int rc = check_source(&src, CFV2_V2, CFV2_V2 "/uid_0", CFV2_V2 "/cgroup.controllers", CGROUP2_SUPER_MAGIC);
  bool v1 = rc == -ENOENT;
  if (v1)
    rc = check_source(&src, CFV2_V1, CFV2_V1 "/uid_0", CFV2_V1 "/cpuacct.usage", CGROUP_SUPER_MAGIC);
  if (rc)
    return rc;

  bool frozen = false, unfrozen = false, published = false;
  *stage = "target mountpoint";
  rc = kern_path(CFV2_TARGET, CFV2_LOOKUP_DIRECTORY, &target);
  if (rc)
    goto put_src;
  rc = kern_path("/sys/fs", CFV2_LOOKUP_DIRECTORY, &parent);
  if (rc)
    goto put_target;
  bool mounted = target.mnt != parent.mnt;
  path_put(&parent);
  rc = mounted ? (target.dentry == src.dentry ? 0 : -EBUSY)
               : check_empty_sysfs(&target, (unsigned long)args->output);
  if (rc)
    goto put_target;

  *stage = "source open";
  int root = open_dir(&src);
  if (root < 0) {
    rc = root;
    goto put_target;
  }
  rc = prepare_group(root, args, v1, true, &frozen, stage);
  if (rc)
    goto close_root;
  rc = prepare_group(root, args, v1, false, &unfrozen, stage);
  if (rc)
    goto close_root;

  if (!mounted) {
    *stage = "bind";
    rc = raw_syscall5(__NR_mount, (long)(v1 ? args->v1 : args->v2), (long)args->target, 0, CFV2_MS_BIND, 0);
    if (!rc) {
      struct path alias;
      published = true;
      *stage = "bind readback";
      rc = kern_path(CFV2_TARGET, CFV2_LOOKUP_DIRECTORY, &alias);
      if (!rc) {
        rc = alias.dentry == src.dentry && alias.mnt != target.mnt ? 0 : -EXDEV;
        path_put(&alias);
      }
    }
  }
  if (!rc)
    logkm("UID tree ready at %s, source=%s (consumer access follows ROM policy)\n", CFV2_TARGET, v1 ? CFV2_V1 : CFV2_V2);

close_root:
  // Once mount succeeds, retain the prepared groups even if readback fails.
  if (rc && !published && unfrozen)
    discard_group(root, args->unfrozen, "unfrozen");
  if (rc && !published && frozen)
    discard_group(root, args->frozen, "frozen");
  raw_syscall1(__NR_close, root);
put_target:
  path_put(&target);
put_src:
  path_put(&src);
  return rc;
}

static void uid_mount_on_resume(struct callback_head* work) {
  struct mm_struct* mm = get_task_mm(current);
  if (!mm) {
    logkm("UID setup: event task has no userspace memory\n");
    return;
  }
  const char* stage = "event identity/namespace";
  int rc = raw_syscall0(__NR_geteuid) == 0 ? check_namespace() : -EPERM;
  if (rc)
    goto done;

  // Use the authorized event reporter's existing credentials. The native syscall
  // ABI needs user pointers, so use a non-executable scratch page in that task.
  static const struct cfv2_uid_args args = {
      .target = CFV2_TARGET, .v1 = CFV2_V1, .v2 = CFV2_V2, .frozen = "frozen", .unfrozen = "unfrozen",
      .freeze = "cgroup.freeze", .procs = "cgroup.procs", .tasks = "tasks", .one = "1\n",
  };
  stage = "syscall scratch buffer";
  long user = raw_syscall6(__NR3264_mmap, 0, sizeof(args), CFV2_PROT_RW, CFV2_MAP_PRIVATE_ANONYMOUS, -1, 0);
  if (user < 0) {
    rc = user;
    goto done;
  }
  rc = access_process_vm(current, user, (void*)&args, sizeof(args), CFV2_FOLL_WRITE) == sizeof(args)
           ? setup_uid_tree((const void*)user, &stage)
           : -EFAULT;
  long unmap = raw_syscall2(__NR_munmap, user, sizeof(args));
  if (unmap)
    logkm("UID setup: failed to release syscall buffer: %ld\n", unmap);
done:
  mmput(mm);
  if (rc)
    logkm("UID setup failed at %s: %d\n", stage, rc);
}

static struct callback_head mount_work = {.func = uid_mount_on_resume};

static long uid_mount_event(const char* event, const char* args, void* reserved) {
  if (!mount_armed || !event || !args || strcmp(event, "post-fs-data") || strcmp(args, "after"))
    return 0;
  unsigned int expected = 0;
  if (!__atomic_compare_exchange_n(&mount_queued, &expected, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    return 0;
  // The event dispatcher holds an RCU read lock. Sleeping VFS work is deferred.
  return task_work_add(current, &mount_work, true);
}

void cfv2_arm_uid_mount(const char* event) {
  if (!event || strcmp(event, "pre-kernel-init"))
    return;
#define RESOLVE(symbol)                                                         \
  do {                                                                          \
    symbol = (typeof(symbol))kallsyms_lookup_name_by_suffix(#symbol);            \
    if (!symbol) {                                                              \
      logkm("UID setup API unavailable: %s\n", #symbol);                         \
      return;                                                                   \
    }                                                                           \
  } while (0)
  RESOLVE(task_work_add);
  RESOLVE(get_task_mm);
  RESOLVE(mmput);
  RESOLVE(access_process_vm);
  RESOLVE(kern_path);
  RESOLVE(path_put);
  RESOLVE(vfs_statfs);
  RESOLVE(dentry_path_raw);
  RESOLVE(dentry_open);
  RESOLVE(get_unused_fd_flags);
  RESOLVE(fd_install);
  RESOLVE(fput);
#undef RESOLVE
  const unsigned int syscalls[] = {
      __NR_mount, __NR_geteuid, __NR_getdents64, __NR_close, __NR3264_fstat, __NR_mkdirat,
      __NR_openat, __NR_unlinkat, __NR_read, __NR_write, __NR_fchmod, __NR_fchown,
      __NR3264_mmap, __NR_munmap,
  };
  for (size_t i = 0; i < sizeof(syscalls) / sizeof(*syscalls); ++i) {
    if (!syscalln_addr(syscalls[i], 0)) {
      logkm("UID setup syscall unavailable: %u\n", syscalls[i]);
      return;
    }
  }
  mount_armed = true;
}

KPM_EVENT(uid_mount_event);
