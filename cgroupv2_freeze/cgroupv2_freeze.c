/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include "cgroupv2_freeze.h"

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "../kpm_utils.h"
#include "cfv2_utils.h"

KPM_NAME("cgroupv2_freeze");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("add cgroup.freeze, support 4.4 ~ 4.19");
#ifdef CONFIG_KPM_BASELINES
KPM_INFO(offset_mode, "static", 16);
#else
KPM_INFO(offset_mode, "dynamic", 16);
#endif

#define GLOBAL_SYSTEM_UID KUIDT_INIT(1000)
#define GLOBAL_SYSTEM_GID KGIDT_INIT(1000)

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// do_freezer_trap
static int (*proc_pid_wchan)(struct seq_file* m, struct pid_namespace* ns, struct pid* pid, struct task_struct* task);
void kfunc_def(schedule)(void);
// cgroup_freeze_task
static void (*signal_wake_up_state)(struct task_struct* t, unsigned int state);
int kfunc_def(wake_up_process)(struct task_struct* p);
// cgroup_do_freeze
static void (*css_task_iter_start)(struct cgroup_subsys_state* css, unsigned int flags, struct css_task_iter* it);
static void (*css_task_iter_start_v4)(struct cgroup_subsys_state* css, struct css_task_iter* it);
static struct task_struct* (*css_task_iter_next)(struct css_task_iter* it);
static void (*css_task_iter_end)(struct css_task_iter* it);
// cgroup_freeze
static struct cgroup_subsys_state* (*css_next_descendant_pre)(struct cgroup_subsys_state* pos,
                                                              struct cgroup_subsys_state* root);
// cgroup_freeze_show
struct cgroup_subsys_state* kfunc_def(of_css)(struct kernfs_open_file* of);
void kfunc_def(seq_printf)(struct seq_file* m, const char* f, ...);
// cgroup_freeze_write
static struct cgroup* (*cgroup_kn_lock_live)(struct kernfs_node* kn, bool drain_offline);
static struct cgroup* (*cgroup_kn_lock_live_v4)(struct kernfs_node* kn);
static void (*cgroup_kn_unlock)(struct kernfs_node* kn);
int kfunc_def(kstrtoint)(const char* s, unsigned int base, int* res);
char* kfunc_def(strim)(char* s);
// hook cgroup_addrm_files
static int (*cgroup_addrm_files)(struct cgroup_subsys_state* css, struct cgroup* cgrp, struct cftype cfts[],
                                 bool is_add);
static int (*cgroup_init_cftypes)(struct cgroup_subsys* ss, struct cftype* cfts);
// hook cgroup_procs_write
static ssize_t (*cgroup_procs_write)(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off);
// hook css_set_move_task
static void (*css_set_move_task)(struct task_struct* task, struct css_set* from_cset, struct css_set* to_cset,
                                 bool use_mg_tasks);
// hook __kernfs_create_file
static ssize_t (*__kernfs_create_file)(struct kernfs_node* parent, const char* name, umode_t mode, loff_t size,
                                       const struct kernfs_ops* ops, void* priv, const void* ns,
                                       struct lock_class_key* key);
static ssize_t (*kernfs_setattr)(struct kernfs_node* kn, const struct iattr* iattr);
// hook get_signal
static bool (*get_signal)(struct ksignal* ksig);

static uint64_t css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO,
                cgroup_base_files_ver5 = UZERO;
#include "cfv2_offsets.c"

// 为待冻结的 task 以及 cgroup 添加必要的标志
static void cgroup_freeze_task(struct task_struct* task, bool freeze) {
  if (!task)
    return;

  unsigned long* jobctl = task_jobctl_ptr(task);
  if (freeze) {
    *jobctl |= JOBCTL_TRAP_FREEZE;
    signal_wake_up_state(task, 0);
  } else {
    *jobctl &= ~JOBCTL_TRAP_FREEZE;
    kfunc(wake_up_process)(task);
  }
}

static void cgroup_do_freeze(struct cgroup* cgrp, bool freeze) {
  struct css_task_iter it;
  struct task_struct* task;

  unsigned long* flags = cgroup_flags_ptr(cgrp);
  if (freeze) {
    set_bit(CGRP_FREEZE, flags);
  } else {
    clear_bit(CGRP_FREEZE, flags);
  }

  if (css_task_iter_start_ver5 == IZERO) {
    css_task_iter_start(&cgrp->self, 0, &it);
  } else {
    css_task_iter_start_v4(&cgrp->self, &it);
  }
  while ((task = css_task_iter_next(&it))) {
    unsigned int flags = task_flags(task);
    if (flags & PF_KTHREAD)
      continue;
    cgroup_freeze_task(task, freeze);
  }
  css_task_iter_end(&it);
}

static void cgroup_freeze(struct cgroup* cgrp, bool freeze) {
  struct cgroup_subsys_state* css;
  struct cgroup* dsct;

  css_for_each_descendant_pre(css, &cgrp->self) {
    dsct = css->cgroup;
    cgroup_do_freeze(dsct, freeze);
  }
}

static ssize_t kernfs_node_freeze(struct kernfs_node* kn, bool freeze, bool force) {
  struct cgroup* cgrp;
  if (cgroup_kn_lock_live_ver5 == IZERO) {
    cgrp = cgroup_kn_lock_live(kn, false);
  } else {
    cgrp = cgroup_kn_lock_live_v4(kn);
  }

  if (!cgrp)
    return -ENOENT;

  if (!force) {
    unsigned long* flags = cgroup_flags_ptr(cgrp);
    freeze = test_bit(CGRP_FREEZE, flags);
  }

  cgroup_freeze(cgrp, freeze);

  cgroup_kn_unlock(kn);

  return 0;
}

static int cgroup_freeze_show(struct seq_file* seq, void* v) {
  struct kernfs_open_file* private = seq_file_private(seq);
  struct cgroup_subsys_state* css = kfunc(of_css)(private);
  struct cgroup* cgrp = css->cgroup;

  unsigned long* flags = cgroup_flags_ptr(cgrp);

  kfunc(seq_printf)(seq, "%d\n", test_bit(CGRP_FREEZE, flags));

  return 0;
}

static ssize_t cgroup_freeze_write(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off) {
  int freeze;

  ssize_t ret = kfunc(kstrtoint)(kfunc(strim)(buf), 0, &freeze);
  if (ret)
    return ret;

  if (freeze < 0 || freeze > 1)
    return -ERANGE;

  ssize_t rc = kernfs_node_freeze(of->kn, freeze, true);
  if (rc)
    return rc;
  else
    return nbytes;
}

static struct cftype cgroup_freeze_files[] = {
    {
        .name = "cgroup.freeze",
#ifndef CONFIG_KPM_BASELINES
        .flags = CFTYPE_NOT_ON_ROOT,
#endif
    },
    {},
};

static void cfv2_prepare_freeze_files(void) {
#ifdef CONFIG_KPM_BASELINES
  // calculate_offsets() 已确认各槽对齐，且完全落在目标表项内。
  char* entry = (char*)cgroup_freeze_files;
  unsigned int flags = CFTYPE_NOT_ON_ROOT;
  typeof(&cgroup_freeze_show) show = cgroup_freeze_show;
  typeof(&cgroup_freeze_write) write = cgroup_freeze_write;
  __builtin_memcpy(entry + struct_offset.cftype_flags_offset, &flags, sizeof(flags));
  __builtin_memcpy(entry + struct_offset.cftype_show_offset, &show, sizeof(show));
  __builtin_memcpy(entry + struct_offset.cftype_write_offset, &write, sizeof(write));
#else
  if (cftype_ver5 == IZERO) {
    cgroup_freeze_files->seq_show = cgroup_freeze_show;
    cgroup_freeze_files->write = cgroup_freeze_write;
  } else {
    cgroup_freeze_files->seq_show_v4 = cgroup_freeze_show;
    cgroup_freeze_files->write_v4 = cgroup_freeze_write;
  }
#endif
}

static bool cfv2_hooks_ready;

static bool cfv2_active(void) {
  return __atomic_load_n(&cfv2_hooks_ready, __ATOMIC_ACQUIRE);
}

static void cgroup_addrm_files_after(hook_fargs4_t* args, void* udata) {
  if (!cfv2_active())
    return;
  int ret = (int)args->ret;
  if (ret)
    return;

  ((typeof(cgroup_addrm_files))wrap_get_origin_func(args))(
      (struct cgroup_subsys_state*)args->arg0, (struct cgroup*)args->arg1, cgroup_freeze_files, (bool)args->arg3);
}

static const char uid_[] = "uid_";
static const char uid_0[] = "uid_0";
static const char pid_[] = "pid_";
// v1 模式并不会附加到 dfl_cgrp, 需要特殊处理
static void cgroup_procs_write_after(hook_fargs4_t* args, void* udata) {
  if (!cfv2_active())
    return;
  size_t nbytes = (size_t)args->arg2;
  size_t ret = (size_t)args->ret;
  if (ret != nbytes)
    return;

  struct kernfs_open_file* of = (struct kernfs_open_file*)args->arg0;
  struct kernfs_node* kn = NULL;

  // 处理 v1 frozen 模式
  if (!strcmp(of->kn->parent->name, "frozen") || !strcmp(of->kn->parent->name, "unfrozen")) {
    kn = of->kn->parent;
  }
  // 处理 v1 uid 模式
  if (!memcmp(of->kn->parent->name, pid_, sizeof(pid_) - 1)
      && (memcmp(of->kn->parent->parent->name, uid_0, sizeof(uid_0)))
      && !memcmp(of->kn->parent->parent->name, uid_, sizeof(uid_) - 1)) {
    kn = of->kn->parent->parent;
  }
  if (!kn)
    return;

  kernfs_node_freeze(kn, false, false);
}
// 处理 v2 uid 模式
static void css_set_move_task_after(hook_fargs4_t* args, void* udata) {
  if (!cfv2_active())
    return;
  struct task_struct* task = (struct task_struct*)args->arg0;
  if (!task)
    return;

  struct css_set* from_cset = (struct css_set*)args->arg1;
  struct cgroup* from_cgrp = NULL;
  unsigned long* from_flags = NULL;

  struct css_set* to_cset = (struct css_set*)args->arg2;
  struct cgroup* to_cgrp = NULL;
  unsigned long* to_flags = NULL;

  if (from_cset) {
    from_cgrp = css_set_dfl_cgrp(from_cset);
    from_flags = cgroup_flags_ptr(from_cgrp);
  }
  if (to_cset) {
    to_cgrp = css_set_dfl_cgrp(to_cset);
    to_flags = cgroup_flags_ptr(to_cgrp);
  }

  if (!from_cset && to_cset) {
    if (test_bit(CGRP_FREEZE, to_flags)) {
      unsigned long* jobctl = task_jobctl_ptr(task);
      *jobctl |= JOBCTL_TRAP_FREEZE;
    }
  } else if (from_cset && to_cset) {
    if (test_bit(CGRP_FREEZE, from_flags) != test_bit(CGRP_FREEZE, to_flags)) {
      cgroup_freeze_task(task, test_bit(CGRP_FREEZE, to_flags));
    }
  }
}
// 修改 cgroup.freeze 所有者为 system:system
static void __kernfs_create_file_after(hook_fargs8_t* args, void* udata) {
  if (!cfv2_active())
    return;
  struct kernfs_node* kn = (struct kernfs_node*)args->ret;

  if (IS_ERR(kn))
    return;

  if (!strcmp(kn->name, "cgroup.freeze")) {
    struct iattr iattr = {
        .ia_valid = ATTR_UID | ATTR_GID,
        .ia_uid = GLOBAL_SYSTEM_UID,
        .ia_gid = GLOBAL_SYSTEM_GID,
    };

    kernfs_setattr(kn, &iattr);
  }
}

static inline int signal_group_exit(struct signal_struct* sig) {
  unsigned int flags = signal_flags(sig);
  struct task_struct* group_exit_task = signal_group_exit_task(sig);
  return (flags & SIGNAL_GROUP_EXIT) || (group_exit_task != NULL);
}

static void do_freezer_trap(void) {
  unsigned long jobctl = task_jobctl(current);
  if ((jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) != JOBCTL_TRAP_FREEZE)
    return;

  volatile long* state = task_state_ptr(current);
  unsigned int* flags = task_flags_ptr(current);

  *state = TASK_INTERRUPTIBLE;
  clear_thread_flag(TIF_SIGPENDING);
  *flags |= PF_FREEZER_SKIP;
  kfunc(schedule)();
  *flags &= ~PF_FREEZER_SKIP;
}

static void get_signal_before(hook_fargs1_t* args, void* udata) {
  if (!cfv2_active())
    return;
  struct signal_struct* signal = task_signal(current);
  unsigned long* jobctl = task_jobctl_ptr(current);
  for (;;) {
    if (signal_group_exit(signal))
      return;

    if (unlikely(*jobctl & JOBCTL_TRAP_FREEZE)) {
      do_freezer_trap();
    } else {
      return;
    }
  }
}
// kpm 模块 wchan 函数名总为0, 需要手动修改
static void proc_pid_wchan_before(hook_fargs4_t* args, void* udata) {
  if (!cfv2_active())
    return;
  struct seq_file* m = (struct seq_file*)args->arg0;
  struct task_struct* task = (struct task_struct*)args->arg3;

  unsigned long jobctl = task_jobctl(task);
  // 用 lookup_symbol_name 判断一下会更好
  if (unlikely(jobctl & JOBCTL_TRAP_FREEZE)) {
    kfunc(seq_printf)(m, "%s", "do_freezer_trap");
    args->ret = 0;
    args->skip_origin = true;
  }
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  if (!kfunc(memset))
    return -ENOENT;

  // 有 cgroup_freeze_write 函数说明本身就支持cgroupv2 freezer
  void (*kf_cgroup_freeze_write)(void);
  kf_cgroup_freeze_write = (typeof(kf_cgroup_freeze_write))kallsyms_lookup_name("cgroup_freeze_write");
  if (kf_cgroup_freeze_write)
    return -EOPNOTSUPP;

  lookup_name(proc_pid_wchan);
  kfunc_lookup_name(schedule);

  lookup_name(signal_wake_up_state);
  kfunc_lookup_name(wake_up_process);

  lookup_name(css_task_iter_start);
  css_task_iter_start_v4 = (typeof(css_task_iter_start_v4))css_task_iter_start;
  lookup_name(css_task_iter_next);
  lookup_name(css_task_iter_end);

  lookup_name(css_next_descendant_pre);

  kfunc_lookup_name(of_css);
  kfunc_lookup_name(seq_printf);

  lookup_name(cgroup_kn_lock_live);
  cgroup_kn_lock_live_v4 = (typeof(cgroup_kn_lock_live_v4))cgroup_kn_lock_live;
  lookup_name(cgroup_kn_unlock);
  kfunc_lookup_name(kstrtoint);
  kfunc_lookup_name(strim);
  if (!kfunc(schedule) || !kfunc(wake_up_process) || !kfunc(of_css) || !kfunc(seq_printf) || !kfunc(kstrtoint)
      || !kfunc(strim)) {
    logkm("Required freezer helper missing\n");
    return -ENOENT;
  }

  lookup_name(cgroup_addrm_files);
  lookup_name(cgroup_init_cftypes);

  lookup_name(cgroup_procs_write);
  lookup_name(css_set_move_task);
  lookup_name(__kernfs_create_file);
  lookup_name(kernfs_setattr);

  lookup_name(get_signal);

  int rc = 0;
  rc = calculate_offsets();
  if (rc < 0)
    return rc;
  cfv2_prepare_freeze_files();
  rc = cgroup_init_cftypes(NULL, cgroup_freeze_files);
  if (rc < 0)
    return rc;

  const struct {
    const char* name;
    void* target;
    int arity;
    void* before;
    void* after;
  } hooks[] = {
      {"get_signal", get_signal, 1, get_signal_before, NULL},
      {"proc_pid_wchan", proc_pid_wchan, 4, proc_pid_wchan_before, NULL},
      {"cgroup_addrm_files", cgroup_addrm_files, 4, NULL, cgroup_addrm_files_after},
      {"cgroup_procs_write", cgroup_procs_write, 4, NULL, cgroup_procs_write_after},
      {"css_set_move_task", css_set_move_task, 4, NULL, css_set_move_task_after},
      {"__kernfs_create_file", __kernfs_create_file, 8, NULL, __kernfs_create_file_after},
  };
  // 新内核原生处理属主；最后一项仅在需要旧内核修正时安装。
  unsigned int count = (sizeof(hooks) / sizeof(hooks[0])) - (cgroup_base_files_ver5 == IZERO);
  for (unsigned int i = 0; i < count; ++i) {
    hook_err_t error = hook_wrap(hooks[i].target, hooks[i].arity, hooks[i].before, hooks[i].after, NULL);
    if (error) {
      logkm("hook %s error: %d\n", hooks[i].name, error);
      if (!i)
        return -23;
      // KP 不保证摘钩等待在途回调。已发布的入口保持惰性，
      // 必须保留 KPM 代码，不能返回失败让加载器释放它。
      logkm("freezer inactive: partial hook installation; reboot before retry\n");
      return 0;
    }
    logkm("hook %s success\n", hooks[i].name);
  }

  __atomic_store_n(&cfv2_hooks_ready, true, __ATOMIC_RELEASE);
  cfv2_arm_uid_mount(event);
  return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  if (!cfv2_active())
    return -ENODEV;
  char msg[64];
  snprintf(msg, sizeof(msg), "_(._.)_");
  int size = strlen(msg) + 1;
  if (!out_msg || outlen < size)
    return -EINVAL;
  return compat_copy_to_user(out_msg, msg, size) == size ? 0 : -EFAULT;
}

static long inline_hook_exit(void* __user reserved) {
  // 政策（docs/records/2026-11-18-load-event-and-unload-policy.md）：卸载一律禁止，恒返回 -EBUSY。
  // 注意 KP 加载器当前仍会释放模块内存，已装钩子会悬空；运行端修复前必须重启移除。
  logkm("cgroup callbacks are persistent; do not unload; reboot to remove\n");
  return -EBUSY;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
