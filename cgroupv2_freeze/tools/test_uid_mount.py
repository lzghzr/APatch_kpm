#!/usr/bin/env python3
"""Exercise the single-KPM UID mount transaction against host VFS/syscall stubs."""

import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define CGROUP2_SUPER_MAGIC 0x63677270
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define SYSFS_MAGIC 0x62656572
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define KPM_EVENT(fn)
static void logkm(const char* fmt, ...) { (void)fmt; }
enum {
  __NR_getdents64, __NR_close, __NR3264_fstat, __NR_fchown, __NR_fchmod, __NR_mkdirat,
  __NR_openat, __NR_read, __NR_write, __NR_unlinkat, __NR_mount, __NR_geteuid, __NR3264_mmap, __NR_munmap
};
struct task_struct { int flags; const struct cred* cred; };
struct mm_struct { int unused; };
struct cred { int unused; };
struct callback_head { void (*func)(struct callback_head*); };
struct vfsmount { long magic; };
struct dentry { const char* name; };
struct file { int fd; };
static struct task_struct task;
static struct { int cred_offset; } task_struct_offset = {offsetof(struct task_struct, cred)};
#define current (&task)
static long raw_syscall0(int);
static long raw_syscall1(int, long);
static long raw_syscall2(int, long, long);
static long raw_syscall3(int, long, long, long);
static long raw_syscall4(int, long, long, long, long);
static long raw_syscall5(int, long, long, long, long, long);
static long raw_syscall6(int, long, long, long, long, long, long);
static void* kallsyms_lookup_name_by_suffix(const char*);
static uintptr_t syscalln_addr(int, int);
'''

FIXTURE = r'''
static struct vfsmount sysfs = {SYSFS_MAGIC}, v1 = {CGROUP_SUPER_MAGIC}, v2 = {CGROUP2_SUPER_MAGIC}, alias;
static struct dentry v1root = {"/"}, v2root = {"/"}, sysroot = {"/fs/cgroup"}, nested = {"/uid_0"};
static struct file dir;
static struct cfv2_uid_args args = {
    .target = CFV2_TARGET, .v1 = CFV2_V1, .v2 = CFV2_V2, .frozen = "frozen", .unfrozen = "unfrozen",
    .freeze = "cgroup.freeze", .procs = "cgroup.procs", .tasks = "tasks", .one = "1\n",
};
static struct {
  bool exists;
  char state;
  struct cfv2_stat files[4];
} groups[2];
static int v2_lookup, v1_lookup, freeze_error, mount_error, refs, alias_lookups;
static bool occupied, unexpected_alias, root_readonly, target_nonempty;
static struct dentry* published_root;
static unsigned int mount_calls, task_files, mutations, dir_reads;
static unsigned int event_queues;
static int event_error;
static const struct cred cred;

static int lookup(const char* s, unsigned int flags, struct path* out) {
  (void)flags;
  if (!strcmp(s, "/sys/fs") || !strcmp(s, CFV2_TARGET)) {
    if (!strcmp(s, CFV2_TARGET) && (published_root || occupied)) {
      if (++alias_lookups && unexpected_alias)
        return -EACCES;
      *out = (struct path){&alias, published_root ? published_root : &nested};
    } else {
      *out = (struct path){&sysfs, &sysroot};
    }
  } else {
    bool legacy = !strncmp(s, CFV2_V1, strlen(CFV2_V1));
    assert(legacy || !strncmp(s, CFV2_V2, strlen(CFV2_V2)));
    const char* suffix = s + strlen(legacy ? CFV2_V1 : CFV2_V2);
    if (!strcmp(suffix, "/uid_0")) {
      int rc = legacy ? v1_lookup : v2_lookup;
      if (rc)
        return rc;
    }
    *out = (struct path){legacy ? &v1 : &v2, *suffix ? &nested : legacy ? &v1root : &v2root};
  }
  refs++;
  return 0;
}
static void put(const struct path* path) { assert(path->dentry && refs-- > 0); }
static int statfs_stub(const struct path* p, struct cfv2_kstatfs* out) {
  *out = (struct cfv2_kstatfs){.type = p->mnt->magic, .flags = root_readonly ? 1 : 0};
  return 0;
}
static char* path_stub(struct dentry* d, char* buf, int len) {
  assert(strlen(d->name) < (unsigned int)len);
  return strcpy(buf, d->name);
}
static int copy_stub(struct task_struct* t, unsigned long addr, void* out, int len, unsigned int flags) {
  assert(t == current && !flags);
  memcpy(out, (void*)addr, len);
  return len;
}
static struct file* open_stub(const struct path* p, int flags, const struct cred* c) {
  assert(c == &cred && flags == O_RDONLY);
  dir.fd = p->mnt == &sysfs ? 3 : 4;
  return &dir;
}
static int getfd_stub(unsigned int flags) { assert(flags == O_CLOEXEC); return dir.fd; }
static void install_stub(unsigned int fd, struct file* fp) { assert((int)fd == fp->fd); }
static int queue_stub(struct task_struct* t, struct callback_head* work, bool notify) {
  assert(t == current && work == &mount_work && notify);
  event_queues++;
  return event_error;
}
static long raw_syscall0(int nr) { assert(nr == __NR_geteuid); return -EPERM; }
static long raw_syscall1(int nr, long fd) { assert(nr == __NR_close && fd >= 3); return 0; }
static struct cfv2_stat* st(long fd) {
  assert(fd >= 8 && fd < 16 && groups[(fd - 8) / 4].exists);
  return &groups[(fd - 8) / 4].files[(fd - 8) % 4];
}
static long raw_syscall2(int nr, long fd, long value) {
  if (nr == __NR3264_fstat) {
    memcpy((void*)value, st(fd), sizeof(*st(fd)));
  } else {
    assert(nr == __NR_fchmod);
    struct cfv2_stat* f = st(fd);
    f->mode = (f->mode & S_IFMT) | value;
    mutations++;
  }
  return 0;
}
static unsigned int group_num(const char* s) {
  assert(!strcmp(s, "frozen") || !strcmp(s, "unfrozen"));
  return !strcmp(s, "unfrozen");
}
static void group_init(unsigned int i, bool old) {
  groups[i].exists = true;
  groups[i].state = old && i == 0 ? '1' : '0';
  for (unsigned int j = 0; j < 4; j++)
    groups[i].files[j] = (struct cfv2_stat){
        .uid = old ? 1000 : 0, .gid = old ? 1000 : 0, .mode = j ? S_IFREG | (j == 2 ? 0600 : 0644) : S_IFDIR | 0755,
    };
}
static long raw_syscall3(int nr, long fd, long ptr, long value) {
  if (nr == __NR_getdents64) {
    assert(fd == 3);
    if (!target_nonempty || dir_reads++)
      return 0;
    struct cfv2_dirent* entry = (void*)ptr;
    entry->len = 24;
    strcpy(entry->name, "busy");
    return 24;
  }
  if (nr == __NR_mkdirat || nr == __NR_unlinkat) {
    assert(fd == 4);
    unsigned int g = group_num((const char*)ptr);
    if (nr == __NR_mkdirat) {
      assert(value == 0775);
      if (groups[g].exists)
        return -EEXIST;
      group_init(g, false);
    } else {
      assert(groups[g].exists && value == CFV2_AT_REMOVEDIR);
      groups[g].exists = false;
    }
    mutations++;
    return 0;
  }
  if (nr == __NR_fchown) {
    assert(ptr == 1000 && value == 1000);
    st(fd)->uid = st(fd)->gid = 1000;
    mutations++;
    return 0;
  }
  assert(value == 2 && (fd == 9 || fd == 13));
  if (nr == __NR_write) {
    assert(fd == 9 && !memcmp((void*)ptr, "1\n", 2));
    if (freeze_error)
      return freeze_error;
    groups[0].state = '1';
    mutations++;
  } else {
    assert(nr == __NR_read);
    ((char*)ptr)[0] = groups[(fd - 9) / 4].state;
    ((char*)ptr)[1] = '\n';
  }
  return 2;
}
static long raw_syscall4(int nr, long fd, long ptr, long flags, long mode) {
  const char* name = (void*)ptr;
  assert(nr == __NR_openat && mode == 0 && (flags & O_NOFOLLOW));
  if (fd == 4) {
    unsigned int n = group_num(name);
    assert(groups[n].exists && (flags & O_DIRECTORY));
    return 8 + 4 * n;
  }
  assert(fd == 8 || fd == 12);
  if (!strcmp(name, "cgroup.freeze"))
    return fd + 1;
  if (!strcmp(name, "cgroup.procs"))
    return fd + 2;
  assert(!strcmp(name, "tasks"));
  task_files++;
  return fd + 3;
}
static long raw_syscall5(int nr, long source, long target, long type, long flags, long data) {
  assert(nr == __NR_mount && flags == CFV2_MS_BIND && !type && !data && !strcmp((char*)target, CFV2_TARGET));
  assert(groups[0].exists && groups[0].state == '1' && groups[1].exists && groups[1].state == '0');
  mount_calls++;
  if (mount_error)
    return mount_error;
  if (!strcmp((char*)source, CFV2_V1))
    published_root = &v1root;
  else {
    assert(!strcmp((char*)source, CFV2_V2));
    published_root = &v2root;
  }
  return 0;
}
static long raw_syscall6(int nr, long a, long b, long c, long d, long e, long f) {
  (void)nr; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
  assert(0);
  return -ENOSYS;
}
static uintptr_t syscalln_addr(int nr, int compat) { assert(!compat); return nr + 1; }
static void* kallsyms_lookup_name_by_suffix(const char* name) { (void)name; return NULL; }
static void reset(void) {
  memset(groups, 0, sizeof(groups));
  v2_lookup = -ENOENT;
  v2.magic = CGROUP2_SUPER_MAGIC;
  v1_lookup = freeze_error = mount_error = 0;
  root_readonly = target_nonempty = occupied = unexpected_alias = false;
  alias_lookups = mount_calls = task_files = mutations = dir_reads = 0;
  published_root = NULL;
}
int main(void) {
  task.cred = &cred;
  kern_path = lookup; path_put = put; vfs_statfs = statfs_stub; dentry_path_raw = path_stub;
  access_process_vm = copy_stub; dentry_open = open_stub; get_unused_fd_flags = getfd_stub; fd_install = install_stub;
  task_work_add = queue_stub;
  mount_armed = true;
  assert(!uid_mount_event("post-fs-data", "before", NULL) && event_queues == 0);
  assert(!uid_mount_event("post-fs-data", "after", NULL) && event_queues == 1);
  assert(!uid_mount_event("post-fs-data", "after", NULL) && event_queues == 1);

  const char* stage;
  reset();
  assert(!setup_uid_tree(&args, &stage) && published_root == &v1root && mount_calls == 1 && task_files == 2);
  assert(groups[0].files[0].uid == 1000 && groups[0].files[1].uid == 1000 && !refs);
  assert((groups[0].files[2].mode & 0777) == 0600);

  reset(); v2_lookup = 0;
  assert(!setup_uid_tree(&args, &stage) && published_root == &v2root && mount_calls == 1 && task_files == 0 && !refs);

  reset(); v2_lookup = 0; v2.magic = CGROUP_SUPER_MAGIC;
  assert(!setup_uid_tree(&args, &stage) && published_root == &v2root && task_files == 0 && !refs);

  reset(); v2_lookup = -EACCES;
  assert(setup_uid_tree(&args, &stage) == -EACCES && !mount_calls && !mutations && !refs);

  reset(); v1_lookup = -ENOENT;
  assert(setup_uid_tree(&args, &stage) == -ENOENT && !mount_calls && !mutations && !refs);

  reset(); root_readonly = true;
  assert(setup_uid_tree(&args, &stage) == -EROFS && !mount_calls && !mutations && !refs);

  reset(); target_nonempty = true;
  assert(setup_uid_tree(&args, &stage) == -ENOTEMPTY && !mount_calls && !mutations && !refs);

  reset(); occupied = true;
  assert(setup_uid_tree(&args, &stage) == -EBUSY && !mount_calls && !mutations && !refs);

  reset(); published_root = &v1root;
  group_init(0, true); group_init(1, true);
  assert(!setup_uid_tree(&args, &stage) && !mount_calls && !mutations && !refs);

  reset(); freeze_error = -EACCES;
  assert(setup_uid_tree(&args, &stage) == -EACCES && !strcmp(stage, "write frozen/cgroup.freeze"));
  assert(!mount_calls && !groups[0].exists && !groups[1].exists && !refs);

  reset(); mount_error = -EACCES; group_init(0, true);
  assert(setup_uid_tree(&args, &stage) == -EACCES && !strcmp(stage, "bind"));
  assert(!published_root && mount_calls == 1 && groups[0].exists && !groups[1].exists && !refs);

  reset(); unexpected_alias = true;
  assert(setup_uid_tree(&args, &stage) == -EACCES && !strcmp(stage, "bind readback"));
  assert(published_root && groups[0].exists && groups[1].exists && !refs);

  puts("UID mount: 13 scenarios passed");
  return 0;
}
'''


def main():
    source = (Path(__file__).resolve().parents[1] / "cfv2_uid_mount.c").read_text()
    source = re.sub(r"^#include .+\n", "", source, flags=re.M)
    source = re.sub(r"^#define O_(DIRECTORY|NOFOLLOW) .+\n", "", source, flags=re.M)
    with TemporaryDirectory(prefix="cfv2-uid-mount-test-") as directory:
        src, exe = Path(directory) / "test.c", Path(directory) / "test"
        src.write_text(PRELUDE + source + FIXTURE)
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Werror", "-Wno-unused-function", str(src), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    main()
