/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <uapi/linux/limits.h>

#include  "hosts_redirect.h"
#include "hr_utils.h"

KPM_NAME("hosts_redirect");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("redirect /system/etc/hosts to /data/adb/hosts/{n}");

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

struct open_flags;
struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);

char* kfunc_def(d_path)(const struct path* path, char* buf, int buflen);
int kfunc_def(kern_path)(const char* name, unsigned int flags, struct path* path);
void kfunc_def(_raw_spin_lock)(raw_spinlock_t* lock);
void kfunc_def(_raw_spin_unlock)(raw_spinlock_t* lock);

static uint64_t task_struct_fs_offset = UZERO, task_struct_alloc_lock_offset = UZERO,
fs_struct_pwd_offset = UZERO, fs_struct_lock_offset = UZERO;

char hosts_source[] = "/system/etc/hosts";
char hosts_target[] = "/data/adb/hosts/0";

static uid_t current_uid() {
  struct cred* cred = *(struct cred**)((uintptr_t)current + task_struct_offset.cred_offset);
  uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
  return uid;
}

static inline void set_priv_selinx_allow(struct task_struct* task, int val) {
  struct task_ext* ext = get_task_ext(task);
  if (likely(task_ext_valid(ext))) {
    ext->priv_selinux_allow = val;
    dsb(ish);
  }
}

static bool endWith(const char* str, const char* suffix) {
  if (!str || !suffix)
    return false;
  size_t lenstr = strlen(str);
  size_t lensuffix = strlen(suffix);
  if (lensuffix > lenstr)
    return false;
  return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

static void do_filp_open_before(hook_fargs3_t* args, void* udata) {
  args->local.data0 = 0;
  if (unlikely(hosts_target[16] == '0'))
    return;
  if (current_uid() != 0)
    return;

  struct filename* pathname = (struct filename*)args->arg1;

  if (unlikely(!strcmp(pathname->name, hosts_source))) {
    args->local.data0 = (uint64_t)pathname->name;
    pathname->name = hosts_target;
    set_priv_selinx_allow(current, true);
  } else if (unlikely(endWith(pathname->name, "hosts"))) {
    struct task_struct* task = current;
    spinlock_t task_lock = *(spinlock_t*)((uintptr_t)task + task_struct_alloc_lock_offset);
    spin_lock(&task_lock);

    struct fs_struct* fs = *(struct fs_struct**)((uintptr_t)task + task_struct_fs_offset);
    if (likely(fs)) {
    // spinlock_t fs_lock = *(spinlock_t*)((uintptr_t)fs + fs_struct_lock_offset);
    // spin_lock(&fs_lock);
      spin_lock(&fs->lock);
      struct path* pwd = (struct path*)((uintptr_t)fs + fs_struct_pwd_offset);
      if (likely(pwd)) {
        char buf[PATH_MAX];
        memset(&buf, 0, PATH_MAX);
        char* pwd_path = d_path(pwd, buf, PATH_MAX);
#ifdef DEBUG
        logkm("pwd_path=%s\n", pwd_path);
#endif /* DEBUG */

        * buf = '\0';
        if (pathname->name[0] != '/') {
          strncat(buf, pwd_path, strlen(pwd_path));
          strncat(buf, "/", strlen("/"));
        }
        strncat(buf, pathname->name, strlen(pathname->name));
#ifdef DEBUG
        logkm("full_path=%s\n", buf);
#endif /* DEBUG */

        struct path path;
        int err = kern_path(buf, LOOKUP_FOLLOW, &path);
        if (likely(!err)) {
          memset(&buf, 0, PATH_MAX);
          char* hosts_name = d_path(&path, buf, PATH_MAX);
#ifdef DEBUG
          logkm("hosts_name=%s\n", hosts_name);
#endif /* DEBUG */
          if (likely(!IS_ERR(hosts_name) && !strcmp(hosts_name, hosts_source))) {
            args->local.data0 = (uint64_t)pathname->name;
            pathname->name = hosts_target;
            set_priv_selinx_allow(task, true);
          }
        }
      }
      spin_unlock(&fs->lock);
    }
    spin_unlock(&task_lock);
  }
}

static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  if (unlikely(args->local.data0)) {
    set_priv_selinx_allow(current, false);
    struct filename* pathname = (struct filename*)args->arg1;
    pathname->name = (char*)args->local.data0;
  }
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  char num = ctl_args ? *ctl_args : '1';
  if (unlikely(num < '0' || num > '9')) {
    return -11;
  }
  hosts_target[16] = num;

  char msg[64];
  snprintf(msg, sizeof(msg), "_(._.)_");
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static long calculate_offsets() {
  // 获取 pwd 相关偏移
  // task->fs
  // fs->pwd
  int (*proc_cwd_link)(struct dentry* dentry, struct path* path);
  lookup_name(proc_cwd_link);

  uint32_t* proc_cwd_link_src = (uint32_t*)proc_cwd_link;
  for (u32 i = 0; i < 0x30; i++) {
#ifdef CONFIG_DEBUG
    logkm("proc_cwd_link %x %llx\n", i, proc_cwd_link[i]);
#endif /* CONFIG_DEBUG */
    if (proc_cwd_link_src[i] == ARM64_RET) {
      break;
    } else if ((proc_cwd_link_src[i] & MASK_LDP_64_) == INST_LDP_64_) {
      uint64_t imm7 = bits32(proc_cwd_link_src[i], 21, 15);
      fs_struct_pwd_offset = sign64_extend((imm7 << 0b11u), 16u);
      break;
    } else if (task_struct_alloc_lock_offset != UZERO && (proc_cwd_link_src[i] & MASK_ADD_64) == INST_ADD_64) {
      uint32_t sh = bit(proc_cwd_link_src[i], 22);
      uint64_t imm12 = imm12 = bits32(proc_cwd_link_src[i], 21, 10);
      if (sh) {
        fs_struct_lock_offset = sign64_extend((imm12 << 12u), 16u);
      } else {
        fs_struct_lock_offset = sign64_extend((imm12), 16u);
      }
    } else if (task_struct_alloc_lock_offset != UZERO && (proc_cwd_link_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
      uint64_t imm12 = bits32(proc_cwd_link_src[i], 21, 10);
      task_struct_fs_offset = sign64_extend((imm12 << 0b11u), 16u);
    } else if (task_struct_alloc_lock_offset == UZERO && (proc_cwd_link_src[i] & MASK_ADD_64) == INST_ADD_64) {
      uint32_t sh = bit(proc_cwd_link_src[i], 22);
      uint64_t imm12 = imm12 = bits32(proc_cwd_link_src[i], 21, 10);
      if (sh) {
        task_struct_alloc_lock_offset = sign64_extend((imm12 << 12u), 16u);
      } else {
        task_struct_alloc_lock_offset = sign64_extend((imm12), 16u);
      }
      // MOV (to/from SP) is an alias of ADD <Xd|SP>, <Xn|SP>, #0
      if (task_struct_alloc_lock_offset == 0) {
        task_struct_alloc_lock_offset = UZERO;
      }
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_fs_offset=0x%llx\n", task_struct_fs_offset);
  logkm("task_struct_alloc_lock_offset=0x%llx\n", task_struct_alloc_lock_offset);
  logkm("fs_struct_pwd_offset=0x%llx\n", fs_struct_pwd_offset);
  logkm("fs_struct_lock_offset=0x%llx\n", fs_struct_lock_offset);
#endif /* CONFIG_DEBUG */
  if (task_struct_fs_offset == UZERO || task_struct_alloc_lock_offset == UZERO || fs_struct_pwd_offset == UZERO || fs_struct_lock_offset == UZERO) {
    return -11;
  }
  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  int rc = inline_hook_control0(args, NULL, NULL);
  if (rc < 0) {
    return rc;
  }

  kfunc_lookup_name(d_path);
  kfunc_lookup_name(kern_path);
  kfunc_lookup_name(_raw_spin_lock);
  kfunc_lookup_name(_raw_spin_unlock);
  rc = calculate_offsets();
  if (rc < 0) {
    return rc;
  }

  lookup_name(do_filp_open);
  hook_func(do_filp_open, 3, do_filp_open_before, do_filp_open_after, 0);
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  unhook_func(do_filp_open);
  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
