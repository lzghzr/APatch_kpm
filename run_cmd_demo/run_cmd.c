/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include "run_cmd.h"

#include <kpmodule.h>
#include <kputils.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/umh.h>
#include <uapi/asm-generic/errno.h>

#include "../kpm_utils.h"
#include "rc_utils.h"

KPM_NAME("run_cmd_demo");
KPM_VERSION(MYKPM_VERSION);
#ifdef CONFIG_KPM_BASELINES
KPM_INFO(offset_mode, "static", 16);
#else
KPM_INFO(offset_mode, "dynamic", 16);
#endif
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("Run shell commands with a usermode helper; DO NOT UNLOAD");

#define logkm(fmt, ...) printk("run_cmd_demo: " fmt, ##__VA_ARGS__)

static char* envp[] = {"HOME=/", "PATH=/system/bin:/system/xbin:/vendor/bin", NULL};
static char sh[] = "/system/bin/sh";
static struct cred* cmd_cred;
static struct kthread_worker* cmd_worker;
static struct kthread_work cmd_work;
static unsigned int cmd_guard;
static char cmd_buffer[RUN_CMD_MAX_SIZE];
static enum run_cmd_status cmd_status;
static int cmd_result;

struct subprocess_info* kfunc_def(call_usermodehelper_setup)(const char* path, char** argv, char** envp, gfp_t gfp_mask,
                                                             int (*init)(struct subprocess_info* info,
                                                                         struct cred* new),
                                                             void (*cleanup)(struct subprocess_info* info), void* data);
int kfunc_def(call_usermodehelper_exec)(struct subprocess_info* info, int wait);
struct cred* kfunc_def(prepare_kernel_cred)(struct task_struct* daemon);
void kfunc_def(abort_creds)(struct cred* cred);
void kfunc_def(security_transfer_creds)(struct cred* new, const struct cred* old);
int kfunc_def(security_secctx_to_secid)(const char* secdata, u32 seclen, u32* secid);
void kfunc_def(selinux_cred_getsecid)(const struct cred* cred, u32* secid);
void kfunc_def(selinux_task_getsecid)(struct task_struct* task, u32* secid);
const struct cred* kfunc_def(override_creds)(const struct cred* new);
void kfunc_def(revert_creds)(const struct cred* old);
struct kthread_worker* kfunc_def(kthread_create_worker)(unsigned int flags, const char* namefmt, ...);
bool kfunc_def(kthread_queue_work)(struct kthread_worker* worker, struct kthread_work* work);
void kfunc_def(__init_kthread_worker)(struct kthread_worker* worker, const char* name, struct lock_class_key* key);
bool kfunc_def(queue_kthread_work)(struct kthread_worker* worker, struct kthread_work* work);
int kfunc_def(kthread_worker_fn)(void* worker);
struct task_struct* kfunc_def(kthread_create_on_node)(int (*threadfn)(void*), void* data, int node, const char* namefmt,
                                                      ...);
int kfunc_def(wake_up_process)(struct task_struct* task);
void* kfunc_def(__kmalloc)(size_t size, gfp_t flags);
void kfunc_def(kfree)(const void* ptr);
#ifndef CONFIG_KPM_BASELINES
struct btf* kfunc_def(bpf_get_btf_vmlinux)(void);
int kfunc_def(btf_find_by_name_kind)(const struct btf* btf, const char* name, unsigned char kind);
const struct btf_type* kfunc_def(btf_type_by_id)(const struct btf* btf, u32 id);
const char* kfunc_def(btf_name_by_offset)(const struct btf* btf, u32 offset);
const struct btf_type* kfunc_def(btf_resolve_size)(const struct btf* btf, const struct btf_type* type, u32* size);
#endif
struct file* kfunc_def(filp_open)(const char* filename, int flags, umode_t mode);
int kfunc_def(replace_fd)(unsigned int fd, struct file* file, unsigned int flags);
int kfunc_def(filp_close)(struct file* file, fl_owner_t id);

#ifndef CONFIG_KPM_BASELINES
static const struct btf* cmd_btf;
#endif
static u32 cmd_sid;
struct task_struct kvar_def(init_task);
int kvar_def(selinux_blob_sizes);
struct lock_class_key kvar_def(__lockdep_no_validate__);
#include "rc_offsets.c"

static struct kthread_worker* create_cmd_worker() {
  if (kfunc(kthread_create_worker))
    return kfunc(kthread_create_worker)(0, "run_cmd_demo");
  struct kthread_worker* worker = kfunc(__kmalloc)(legacy_worker_size, 0);
  if (!worker)
    return ERR_PTR(-ENOMEM);
  memset(worker, 0, legacy_worker_size);
  kfunc(__init_kthread_worker)(worker, "run_cmd_demo", kvar(__lockdep_no_validate__));
  struct task_struct* task = kfunc(kthread_create_on_node)(kfunc(kthread_worker_fn), worker, -1, "run_cmd_demo");
  if (IS_ERR(task)) {
    kfunc(kfree)(worker);
    return (struct kthread_worker*)task;
  }
  kfunc(wake_up_process)(task);
  return worker;
}

static int run_cmd_prepare(struct subprocess_info* info, struct cred* new) {
  // 复制模块专用的 root 执行凭据。
  kfunc(security_transfer_creds)(new, cmd_cred);
  const struct cred* old = kfunc(override_creds)(new);
  logkm("helper uid=%u euid=%u\n", *(uid_t*)((uintptr_t)new + cred_offset.uid_offset),
        *(uid_t*)((uintptr_t)new + cred_offset.euid_offset));
  struct file* file = kfunc(filp_open)("/dev/null", O_RDWR, 0);
  kfunc(revert_creds)(old);
  if (IS_ERR(file))
    return PTR_ERR(file);
  int ret = 0;
  for (unsigned int fd = 0; fd < 3; fd++) {
    ret = kfunc(replace_fd)(fd, file, 0);
    if (ret < 0)
      break;
  }
  kfunc(filp_close)(file, NULL);
  return ret < 0 ? ret : 0;
}

static int run_cmd(const char* cmd) {
  char* argv[] = {sh, "-c", (char*)cmd, NULL};
  struct subprocess_info* info = kfunc(call_usermodehelper_setup)(sh, argv, envp, 0, run_cmd_prepare, NULL, NULL);
  if (!info)
    return -ENOMEM;

  // 恢复 helper 路径，适配 CONFIG_STATIC_USERMODEHELPER。
  *(char**)((uintptr_t)info + subprocess_info_path_offset) = sh;
  return kfunc(call_usermodehelper_exec)(info, UMH_WAIT_PROC);
}

static void run_cmd_work(struct kthread_work* work) {
  int ret = run_cmd(cmd_buffer);
  unsigned long flags = run_cmd_lock(&cmd_guard);
  cmd_result = ret;
  cmd_status = CMD_DONE;
  run_cmd_unlock(&cmd_guard, flags);
  logkm("helper result=%d\n", ret);
}

static int submit_cmd(const char* cmd) {
  size_t len = strnlen(cmd, sizeof(cmd_buffer));
  if (!len)
    return -EINVAL;
  if (len == sizeof(cmd_buffer))
    return -E2BIG;

  unsigned long flags = run_cmd_lock(&cmd_guard);
  if (cmd_status == CMD_PENDING) {
    run_cmd_unlock(&cmd_guard, flags);
    return -EBUSY;
  }
  memcpy(cmd_buffer, cmd, len + 1);
  cmd_status = CMD_PENDING;
  run_cmd_unlock(&cmd_guard, flags);

  if (!kfunc(kthread_queue_work)(cmd_worker, &cmd_work)) {
    flags = run_cmd_lock(&cmd_guard);
    cmd_result = -EAGAIN;
    cmd_status = CMD_DONE;
    run_cmd_unlock(&cmd_guard, flags);
    return -EAGAIN;
  }
  return 0;
}

static long prepare_run_cmd() {
  kfunc_lookup_name(call_usermodehelper_setup);
  kfunc_lookup_name(call_usermodehelper_exec);
  kfunc_lookup_name(prepare_kernel_cred);
  kfunc_lookup_name(abort_creds);
  kfunc_lookup_name(security_transfer_creds);
  kfunc_lookup_name(security_secctx_to_secid);
  kfunc_lookup_name(selinux_cred_getsecid);
  kfunc_lookup_name(selinux_task_getsecid);
  kvar_lookup_name(init_task);
  kvar_lookup_name(selinux_blob_sizes);
  kfunc_lookup_name(override_creds);
  kfunc_lookup_name(revert_creds);
  kfunc_lookup_name(kthread_create_worker);
  kfunc_lookup_name(kthread_queue_work);
  if (!kfunc(kthread_create_worker)) {
    kfunc_lookup_name(__init_kthread_worker);
    kfunc_lookup_name(kthread_worker_fn);
    kfunc_lookup_name(kthread_create_on_node);
    kfunc_lookup_name(wake_up_process);
    kfunc_lookup_name(__kmalloc);
    kfunc_lookup_name(kfree);
    kvar_lookup_name(__lockdep_no_validate__);
    if (!kfunc(__init_kthread_worker) || !kfunc(kthread_worker_fn) || !kfunc(kthread_create_on_node)
        || !kfunc(wake_up_process) || !kfunc(__kmalloc) || !kfunc(kfree))
      return -ENOENT;
    // lockdep 开启时使用内核的持久 key，仅跳过本 worker 锁的依赖验证。
    if (!kvar(__lockdep_no_validate__) && kallsyms_lookup_name_by_suffix("lockdep_init_map"))
      return -ENOENT;
  }
  if (!kfunc(kthread_queue_work)) {
    kfunc_lookup_name(queue_kthread_work);
    kfunc(kthread_queue_work) = kfunc(queue_kthread_work);
  }
#ifndef CONFIG_KPM_BASELINES
  kfunc_lookup_name(bpf_get_btf_vmlinux);
  kfunc_lookup_name(btf_find_by_name_kind);
  kfunc_lookup_name(btf_type_by_id);
  kfunc_lookup_name(btf_name_by_offset);
  kfunc_lookup_name(btf_resolve_size);
  if (kfunc(bpf_get_btf_vmlinux) && kfunc(btf_find_by_name_kind) && kfunc(btf_type_by_id) && kfunc(btf_name_by_offset)
      && kfunc(btf_resolve_size)) {
    const struct btf* btf = kfunc(bpf_get_btf_vmlinux)();
    if (btf && !IS_ERR(btf))
      cmd_btf = btf;
  }
#endif
  kfunc_lookup_name(filp_open);
  kfunc_lookup_name(replace_fd);
  kfunc_lookup_name(filp_close);
  if (!kfunc(call_usermodehelper_setup) || !kfunc(call_usermodehelper_exec) || !kfunc(prepare_kernel_cred)
      || !kfunc(abort_creds) || !kfunc(security_transfer_creds) || !kfunc(override_creds) || !kfunc(revert_creds)
      || !kfunc(security_secctx_to_secid) || (!kfunc(selinux_cred_getsecid) && !kfunc(selinux_task_getsecid))
      || !kvar(init_task) || !kfunc(kthread_queue_work) || !kfunc(filp_open) || !kfunc(replace_fd)
      || !kfunc(filp_close))
    return -ENOENT;
  return calculate_offsets();
}

static long run_cmd_init(const char* args, const char* event, void* __user reserved) {
  long ret = prepare_run_cmd();
  if (ret)
    return ret;
  if (args && strnlen(args, sizeof(cmd_buffer)) == sizeof(cmd_buffer))
    return -E2BIG;

  ret = kfunc(security_secctx_to_secid)(RUN_CMD_CONTEXT, sizeof(RUN_CMD_CONTEXT) - 1, &cmd_sid);
  if (ret)
    return ret;
  if (!cmd_sid)
    return -EINVAL;
  cmd_cred = kfunc(prepare_kernel_cred)(kvar(init_task));
  if (!cmd_cred)
    return -ENOMEM;
  // 凭据与 LSM blob 均由内核独立分配；只修改当前 SID。
  void* security = *(void**)((uintptr_t)cmd_cred + cred_security_offset);
  if (!security)
    return -EINVAL;
  u32 sid = 0;
  if (!kfunc(selinux_cred_getsecid)) {
    // 旧内核通过原生 task getter 核对私有副本的初始 SID。
    kfunc(selinux_task_getsecid)(kvar(init_task), &sid);
    if (*(u32*)((uintptr_t)security + cred_sid_offset) != sid)
      return -EINVAL;
  }
  *(u32*)((uintptr_t)security + cred_sid_offset) = cmd_sid;
  if (kfunc(selinux_cred_getsecid)) {
    kfunc(selinux_cred_getsecid)(cmd_cred, &sid);
    if (sid != cmd_sid)
      return -EINVAL;
  }
  logkm("helper context=%s sid=%u\n", RUN_CMD_CONTEXT, cmd_sid);
  INIT_LIST_HEAD(&cmd_work.node);
  cmd_work.func = run_cmd_work;
  struct kthread_worker* worker = create_cmd_worker();
  if (IS_ERR(worker))
    return PTR_ERR(worker);
  cmd_worker = worker;
  logkm("WARNING: do not unload this module; reboot to remove it\n");
  // worker 建立后不得令 init 失败，加载器会立即调用 exit 并释放模块。
  if (args && args[0])
    submit_cmd(args);
  return 0;
}

static long run_cmd_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  if (!ctl_args || !ctl_args[0] || !out_msg || outlen < RUN_CMD_REPLY_SIZE)
    return -EINVAL;

  char msg[RUN_CMD_REPLY_SIZE];
  int ret = 0;
  if (strcmp(ctl_args, "result")) {
    ret = submit_cmd(ctl_args);
    if (ret)
      return ret;
    snprintf(msg, sizeof(msg), "queued\n");
  } else {
    unsigned long flags = run_cmd_lock(&cmd_guard);
    enum run_cmd_status status = cmd_status;
    ret = cmd_result;
    run_cmd_unlock(&cmd_guard, flags);
    if (status == CMD_IDLE) {
      ret = 0;
      snprintf(msg, sizeof(msg), "idle\n");
    } else if (status == CMD_PENDING) {
      ret = -EINPROGRESS;
      snprintf(msg, sizeof(msg), "pending\n");
    } else {
      snprintf(msg, sizeof(msg), "ret=%d\n", ret);
    }
  }
  int len = strlen(msg) + 1;
  if (compat_copy_to_user(out_msg, msg, len) != len)
    return -EFAULT;
  return ret;
}

static long run_cmd_exit(void* __user reserved) {
  if (cmd_worker) {
    logkm("WARNING: unloading is unsupported; KP will free live worker callbacks\n");
    return -EBUSY;
  }
  if (cmd_cred) {
    kfunc(abort_creds)(cmd_cred);
    cmd_cred = NULL;
  }
  return 0;
}

KPM_INIT(run_cmd_init);
KPM_CTL0(run_cmd_control0);
KPM_EXIT(run_cmd_exit);
