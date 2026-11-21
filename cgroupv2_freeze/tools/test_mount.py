#!/usr/bin/env python3
"""Run the KPM mount control flow against host stubs for VFS and task_work."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CGROUP2_SUPER_MAGIC 0x63677270
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define SYSFS_MAGIC 0x62656572
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define KPM_EVENT(fn)
#define logkm(...) ((void)0)

enum {
  __NR_mount, __NR_geteuid, __NR_getdents64, __NR_close, __NR3264_fstat,
  __NR_fchmod, __NR_fchown, __NR3264_mmap, __NR_munmap,
};
struct cred { int unused; };
struct task_struct { long unused; const struct cred* cred; };
struct mm_struct { int unused; };
struct file { int unused; };
struct vfsmount { long magic; };
struct dentry { const char* name; };
struct callback_head {
  struct callback_head* next;
  void (*func)(struct callback_head*);
};
static const struct cred credentials;
static struct task_struct task = {.cred = &credentials};
#define current (&task)
static struct {
  int cred_offset;
} task_struct_offset = {offsetof(struct task_struct, cred)};

static long raw_syscall0(long nr);
static long raw_syscall1(long nr, long a0);
static long raw_syscall2(long nr, long a0, long a1);
static long raw_syscall3(long nr, long a0, long a1, long a2);
static long raw_syscall5(long nr, long a0, long a1, long a2, long a3, long a4);
static long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
static void* kallsyms_lookup_name_by_suffix(const char*);
static uintptr_t syscalln_addr(int nr, int compat);
'''

FIXTURE = r'''
static struct vfsmount sysfs = {SYSFS_MAGIC}, cg = {CGROUP2_SUPER_MAGIC},
    v1 = {CGROUP_SUPER_MAGIC}, nsfs, wrong_nsfs;
static struct dentry root_entry = {"/"}, sysfs_entry = {"/fs/cgroup"},
    sub_entry = {"/subgroup"}, ns_entry = {"/"}, controllers_entry = {"/cgroup.controllers"};
static struct path target;
static struct mm_struct mm;
static struct file opened;
static struct callback_head* pending;
static struct cfv2_mount_args scratch;
static struct cfv2_stat stats;
static bool resume, is_root, shared_ns, has_mm, has_source, has_child, read_only, bad_copy, fail_chmod, wrong_bind;
static unsigned int mapped, unmapped, mount_calls, chown_calls, chmod_calls, refs, mm_refs, fds, dent_calls;
static long mount_flags, mount_error;

static int queue(struct task_struct* t, struct callback_head* work, bool notify) {
  assert(t == current && notify && !pending && !resume);
  assert(mapped == 0 && mount_calls == 0);
  pending = work;
  return 0;
}
static struct mm_struct* get_mm(struct task_struct* t) {
  assert(t == current && resume);
  if (!has_mm)
    return NULL;
  mm_refs++;
  return &mm;
}
static void put_mm(struct mm_struct* value) {
  assert(value == &mm && mm_refs == 1);
  mm_refs--;
}
static int copy_vm(struct task_struct* t, unsigned long addr, void* buf, int len, unsigned int flags) {
  assert(t == current && resume && mapped > unmapped);
  assert(addr >= (unsigned long)&scratch && addr + len <= (unsigned long)(&scratch + 1));
  if (flags == CFV2_FOLL_WRITE && bad_copy)
    return len - 1;
  if (flags == CFV2_FOLL_WRITE)
    memcpy((void*)addr, buf, len);
  else
    memcpy(buf, (void*)addr, len);
  return len;
}
static int lookup(const char* name, unsigned int flags, struct path* path) {
  assert(resume);
  if (!strcmp(name, "/proc/1/ns/mnt") || !strcmp(name, "/proc/self/ns/mnt")) {
    assert(flags == CFV2_LOOKUP_FOLLOW);
    *path = (struct path){!shared_ns && !strcmp(name, "/proc/1/ns/mnt") ? &wrong_nsfs : &nsfs, &ns_entry};
  } else if (!strcmp(name, CFV2_TARGET)) {
    *path = target;
  } else if (!strcmp(name, "/sys/fs")) {
    *path = (struct path){&sysfs, &sysfs_entry};
  } else if ((!strcmp(name, CFV2_SOURCE) || !strcmp(name, CFV2_SOURCE "/cgroup.controllers")) && has_source) {
    *path = (struct path){&cg, &root_entry};
  } else if (!strcmp(name, CFV2_TARGET "/cgroup.controllers") && target.mnt == &cg) {
    *path = (struct path){&cg, &controllers_entry};
  } else {
    return -ENOENT;
  }
  refs++;
  return 0;
}
static void put_path(const struct path* path) {
  assert(path->mnt && refs);
  refs--;
}
static int stat_fs(const struct path* path, struct cfv2_kstatfs* stat) {
  stat->type = path->mnt->magic;
  stat->flags = read_only && path->mnt == &cg ? CFV2_ST_RDONLY : 0;
  return 0;
}
static char* raw_path(struct dentry* dentry, char* out, int len) {
  size_t size = strlen(dentry->name) + 1;
  if (size > (size_t)len)
    return (void*)-ENAMETOOLONG;
  return memcpy(out, dentry->name, size);
}
static struct file* open_path(const struct path* path, int flags, const struct cred* cred) {
  assert(path->mnt == target.mnt && flags == 0 && cred == &credentials);
  return &opened;
}
static int alloc_fd(unsigned int flags) {
  assert(flags == CFV2_O_CLOEXEC && fds == 0);
  return 19;
}
static void install_fd(unsigned int fd, struct file* file) {
  assert(fd == 19 && file == &opened);
  fds++;
}
static void put_file(struct file* file) {
  assert(file == &opened);
}
static void* kallsyms_lookup_name_by_suffix(const char* name) {
  if (!strcmp(name, "task_work_add")) return queue;
  if (!strcmp(name, "get_task_mm")) return get_mm;
  if (!strcmp(name, "mmput")) return put_mm;
  if (!strcmp(name, "access_process_vm")) return copy_vm;
  if (!strcmp(name, "kern_path")) return lookup;
  if (!strcmp(name, "path_put")) return put_path;
  if (!strcmp(name, "vfs_statfs")) return stat_fs;
  if (!strcmp(name, "dentry_path_raw")) return raw_path;
  if (!strcmp(name, "dentry_open")) return open_path;
  if (!strcmp(name, "get_unused_fd_flags")) return alloc_fd;
  if (!strcmp(name, "fd_install")) return install_fd;
  if (!strcmp(name, "fput")) return put_file;
  return NULL;
}
static uintptr_t syscalln_addr(int nr, int compat) {
  assert(!compat);
  return 1;
}
static long raw_syscall0(long nr) {
  assert(resume && nr == __NR_geteuid);
  return is_root ? 0 : 1000;
}
static long raw_syscall1(long nr, long fd) {
  assert(resume && nr == __NR_close && fd == 19 && fds == 1);
  fds--;
  return 0;
}
static long raw_syscall2(long nr, long a0, long a1) {
  assert(resume);
  if (nr == __NR_munmap) {
    assert(a0 == (long)&scratch && a1 == sizeof(scratch));
    unmapped++;
    return 0;
  }
  assert(a0 == 19 && fds == 1);
  if (nr == __NR3264_fstat) {
    memcpy((void*)a1, &stats, sizeof(stats));
    return 0;
  }
  assert(nr == __NR_fchmod && a1 == CFV2_ROOT_MODE);
  chmod_calls++;
  if (fail_chmod)
    return -EPERM;
  stats.mode = a1;
  return 0;
}
static long raw_syscall3(long nr, long fd, long a1, long a2) {
  assert(resume && fd == 19 && fds == 1);
  if (nr == __NR_getdents64) {
    assert(a1 == (long)&scratch.output && a2 == sizeof(scratch.output));
    if (dent_calls++ != 0)
      return 0;
    struct cfv2_dirent* dot = (void*)a1;
    dot->len = 24;
    memcpy(dot->name, ".", 2);
    struct cfv2_dirent* dotdot = (void*)(a1 + dot->len);
    dotdot->len = 24;
    memcpy(dotdot->name, has_child ? "uid" : "..", has_child ? 4 : 3);
    return 48;
  }
  assert(nr == __NR_fchown);
  chown_calls++;
  stats.uid = a1;
  stats.gid = a2;
  return 0;
}
static long raw_syscall5(long nr, long source, long path, long type, long flags, long data) {
  assert(resume && nr == __NR_mount && !strcmp((void*)path, CFV2_TARGET) && data == 0);
  mount_calls++;
  mount_flags = flags;
  if (flags == CFV2_MS_BIND) {
    assert(!strcmp((void*)source, CFV2_SOURCE) && type == 0);
  } else {
    assert(!strcmp((void*)source, "none") && !strcmp((void*)type, "cgroup2") && flags == CFV2_MOUNT_FLAGS);
  }
  if (mount_error)
    return mount_error;
  target = (struct path){&cg, wrong_bind ? &sub_entry : &root_entry};
  return 0;
}
static long raw_syscall6(long nr, long a0, long len, long prot, long flags, long fd, long off) {
  assert(resume && nr == __NR3264_mmap && a0 == 0 && len == sizeof(scratch) &&
         prot == CFV2_PROT_RW && flags == CFV2_MAP_PRIVATE_ANONYMOUS && fd == -1 && off == 0);
  mapped++;
  return (long)&scratch;
}
static void reset(void) {
  assert(refs == 0 && mm_refs == 0 && fds == 0 && mapped == unmapped);
  mount_armed = resume = false;
  mount_queued = 0;
  pending = NULL;
  is_root = shared_ns = has_mm = has_source = true;
  has_child = read_only = bad_copy = fail_chmod = wrong_bind = false;
  mapped = unmapped = mount_calls = chown_calls = chmod_calls = dent_calls = 0;
  mount_flags = mount_error = 0;
  target = (struct path){&sysfs, &sysfs_entry};
  stats = (struct cfv2_stat){.mode = 0600};
}
static void simulate_resume(void) {
  assert(cfv2_prepare_mount("pre-kernel-init") == 0);
  assert(mount_event("post-fs-data", "before", NULL) == 0 && !pending);
  assert(mount_event("post-fs-data", "after", NULL) == 0);
  assert(pending && mapped == 0 && mount_calls == 0 && chown_calls == 0 && chmod_calls == 0);
  assert(mount_event("post-fs-data", "after", NULL) == 0);
  resume = true;
  pending->func(pending);
  resume = false;
}
static void untouched(void) {
  assert(chown_calls == 0 && chmod_calls == 0 && stats.uid == 0 && stats.gid == 0 && stats.mode == 0600);
}
int main(void) {
  reset();
  assert(cfv2_prepare_mount("load-file") == 0);
  assert(mount_event("post-fs-data", "after", NULL) == 0 && !pending);

  reset(); simulate_resume();
  assert(mount_calls == 1 && mount_flags == CFV2_MS_BIND && dent_calls == 2);
  assert(chown_calls == 1 && chmod_calls == 1 && stats.uid == 1000 && stats.gid == 1000 && stats.mode == 0775);
  reset(); has_source = false; simulate_resume();
  assert(mount_calls == 1 && mount_flags == CFV2_MOUNT_FLAGS && stats.mode == 0775);
  reset(); target = (struct path){&cg, &root_entry}; simulate_resume();
  assert(mount_calls == 0 && chown_calls == 1 && chmod_calls == 1);
  reset(); target = (struct path){&cg, &root_entry};
  stats = (struct cfv2_stat){.uid = 1000, .gid = 1000, .mode = 0775}; simulate_resume();
  assert(mount_calls == 0 && chown_calls == 0 && chmod_calls == 0);

  reset(); has_child = true; simulate_resume(); assert(mount_calls == 0); untouched();
  reset(); target = (struct path){&v1, &root_entry}; simulate_resume(); assert(mount_calls == 0); untouched();
  reset(); target = (struct path){&cg, &sub_entry}; simulate_resume(); assert(mount_calls == 0); untouched();
  reset(); target = (struct path){&cg, &root_entry}; read_only = true;
  simulate_resume(); assert(mount_calls == 0); untouched();
  reset(); shared_ns = false; simulate_resume(); assert(mapped == 0); untouched();
  reset(); is_root = false; simulate_resume(); assert(mapped == 0); untouched();
  reset(); has_mm = false; simulate_resume(); assert(mapped == 0); untouched();
  reset(); bad_copy = true; simulate_resume(); assert(mapped == 1 && mount_calls == 0); untouched();
  reset(); mount_error = -ENODEV; simulate_resume(); assert(mount_calls == 1); untouched();
  reset(); wrong_bind = true; simulate_resume(); assert(mount_calls == 1); untouched();
  reset(); fail_chmod = true; simulate_resume();
  assert(chown_calls == 2 && chmod_calls == 1 && stats.uid == 0 && stats.gid == 0 && stats.mode == 0600);
  reset();
  puts("16 KPM event, mount, permissions and cleanup cases passed");
}
'''


def main():
    code = (Path(__file__).resolve().parents[1] / "cfv2_mount.c").read_text()
    implementation = code[code.index("#define CFV2_TARGET"):]
    with TemporaryDirectory(prefix="cfv2-kpm-mount-") as directory:
        source = Path(directory) / "test.c"
        executable = source.with_suffix("")
        source.write_text(PRELUDE + implementation + FIXTURE)
        subprocess.run(
            ["clang", "-Wall", "-Werror", "-O1", "-fsanitize=address,undefined", str(source), "-o", str(executable)],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
