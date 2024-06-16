/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <vdso/limits.h>

#include "cgroupv2_freeze.h"
#include "cfv2_utils.h"

KPM_NAME("cgroupv2_freeze");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("add cgroup.freeze, support 4.4, 4.9 4.19");

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
struct cgroup_subsys_state* (*css_next_descendant_pre)(struct cgroup_subsys_state* pos, struct cgroup_subsys_state* root);
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
static int (*cgroup_addrm_files)(struct cgroup_subsys_state* css, struct cgroup* cgrp, struct cftype cfts[], bool is_add);
static int (*cgroup_init_cftypes)(struct cgroup_subsys* ss, struct cftype* cfts);
// hook cgroup_procs_write
ssize_t(*cgroup_procs_write)(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off);
// hook __kernfs_create_file
ssize_t(*__kernfs_create_file)(struct kernfs_node* parent, const char* name, umode_t mode, loff_t size, const struct kernfs_ops* ops, void* priv, const void* ns, struct lock_class_key* key);
ssize_t(*kernfs_setattr)(struct kernfs_node* kn, const struct iattr* iattr);
// hook get_signal
static bool(*get_signal)(struct ksignal* ksig);

static uint64_t task_struct_state_offset = UZERO, task_struct_flags_offset = UZERO, task_struct_jobctl_offset = UZERO, task_struct_signal_offset = UZERO,
signal_struct_group_exit_task_offset = UZERO, signal_struct_flags_offset = UZERO,
seq_file_private_offset = UZERO,
freezer_state_offset = UZERO, cgroup_flags_offset = UZERO,
css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO, cftype_ver5 = UZERO, cgroup_base_files_ver5 = UZERO;

// 为待冻结的 task 以及 cgroup 添加必要的标志
static void cgroup_freeze_task(struct task_struct* task, bool freeze) {
  if (!task)
    return;

  unsigned long* jobctl = (unsigned long*)((uintptr_t)task + task_struct_jobctl_offset);
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

  unsigned long* flags = (unsigned long*)((uintptr_t)cgrp + cgroup_flags_offset);
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
    unsigned int flags = *(unsigned int*)((uintptr_t)task + task_struct_flags_offset);
    if (flags & PF_KTHREAD)
      continue;
    cgroup_freeze_task(task, freeze);
  }
  css_task_iter_end(&it);
}

void cgroup_freeze(struct cgroup* cgrp, bool freeze) {
  struct cgroup_subsys_state* css;
  struct cgroup* dsct;

  css_for_each_descendant_pre(css, &cgrp->self) {
    dsct = css->cgroup;
    cgroup_do_freeze(dsct, freeze);
  }
}
// 处理 v2 uid 模式
static int cgroup_freeze_show(struct seq_file* seq, void* v) {
  struct kernfs_open_file* private = *(struct kernfs_open_file**)((uintptr_t)seq + seq_file_private_offset);
  struct cgroup_subsys_state* css = kfunc(of_css)(private);
  struct cgroup* cgrp = css->cgroup;

  unsigned long* flags = (unsigned long*)((uintptr_t)cgrp + cgroup_flags_offset);

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

  struct cgroup* cgrp;
  if (cgroup_kn_lock_live_ver5 == IZERO) {
    cgrp = cgroup_kn_lock_live(of->kn, false);
  } else {
    cgrp = cgroup_kn_lock_live_v4(of->kn);
  }

  if (!cgrp)
    return -ENOENT;

  cgroup_freeze(cgrp, freeze);

  cgroup_kn_unlock(of->kn);

  return nbytes;
}

static struct cftype cgroup_freeze_files[] = {
  {
    .name = "cgroup.freeze",
    .flags = CFTYPE_NOT_ON_ROOT,
    .seq_show = cgroup_freeze_show,
    .write = cgroup_freeze_write,
  },
  { },
};
static struct cftype_v4 cgroup_freeze_files_v4[] = {
  {
    .name = "cgroup.freeze",
    .flags = CFTYPE_NOT_ON_ROOT,
    .seq_show = cgroup_freeze_show,
    .write = cgroup_freeze_write,
  },
  { },
};

static void cgroup_addrm_files_after(hook_fargs4_t* args, void* udata) {
  struct cftype* cfts;
  if (cftype_ver5 == IZERO) {
    cfts = cgroup_freeze_files;
  } else {
    cfts = (struct cftype*)cgroup_freeze_files_v4;
  }
  ((typeof(cgroup_addrm_files))
    hook_chain_origin_func(args))((struct cgroup_subsys_state*)args->arg0, (struct cgroup*)args->arg1, cfts, (bool)args->arg3);
}
// 处理 v2 frozen 模式
static void cgroup_procs_write_after(hook_fargs4_t* args, void* udata) {
  struct kernfs_open_file* of = (struct kernfs_open_file*)args->arg0;
  int freeze;

  if (!strcmp(of->kn->parent->name, "frozen")) {
    freeze = 1;
  } else if (!strcmp(of->kn->parent->name, "unfrozen")) {
    freeze = 0;
  } else {
    return;
  }

  struct cgroup* cgrp;
  if (cgroup_kn_lock_live_ver5 == IZERO) {
    cgrp = cgroup_kn_lock_live(of->kn, false);
  } else {
    cgrp = cgroup_kn_lock_live_v4(of->kn);
  }

  if (!cgrp)
    return;

  cgroup_freeze(cgrp, freeze);

  cgroup_kn_unlock(of->kn);
}
// 修改 cgroup.freeze 所有者为 system:system
static void __kernfs_create_file_after(hook_fargs8_t* args, void* udata) {
  struct kernfs_node* kn = (struct kernfs_node*)args->ret;

  if (IS_ERR(kn))
    return;

  if (!strcmp(kn->name, "cgroup.freeze")) {
    struct iattr iattr = { .ia_valid = ATTR_UID | ATTR_GID,
                          .ia_uid = GLOBAL_SYSTEM_UID,
                          .ia_gid = GLOBAL_SYSTEM_GID, };

    kernfs_setattr(kn, &iattr);
  }
}

static inline int signal_group_exit(struct signal_struct* sig) {
  unsigned int flags = *(unsigned int*)((uintptr_t)sig + signal_struct_flags_offset);
  struct task_struct* group_exit_task = *(struct task_struct**)((uintptr_t)sig + signal_struct_group_exit_task_offset);
  return (flags & SIGNAL_GROUP_EXIT) || (group_exit_task != NULL);
}

static void do_freezer_trap(void) {
  unsigned long jobctl = *(unsigned long*)((uintptr_t)current + task_struct_jobctl_offset);
  if ((jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) != JOBCTL_TRAP_FREEZE) {
    return;
  }
  volatile long* state = (volatile long*)((uintptr_t)current + task_struct_state_offset);
  unsigned int* flags = (unsigned int*)((uintptr_t)current + task_struct_flags_offset);

  *state = TASK_INTERRUPTIBLE;
  clear_thread_flag(TIF_SIGPENDING);
  *flags |= PF_FREEZER_SKIP;
  kfunc(schedule)();
  *flags &= ~PF_FREEZER_SKIP;
}

static void get_signal_before(hook_fargs1_t* args, void* udata) {
  struct signal_struct* signal = *(struct signal_struct**)((uintptr_t)current + task_struct_signal_offset);
  unsigned long* jobctl = (unsigned long*)((uintptr_t)current + task_struct_jobctl_offset);
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
  struct seq_file* m = (struct seq_file*)args->arg0;
  struct task_struct* task = (struct task_struct*)args->arg3;

  unsigned long jobctl = *(unsigned long*)((uintptr_t)task + task_struct_jobctl_offset);
  // 用 lookup_symbol_name 判断一下会更好
  if (unlikely(jobctl & JOBCTL_TRAP_FREEZE)) {
    kfunc(seq_printf)(m, "%s", "do_freezer_trap");
    args->ret = 0;
    args->skip_origin = true;
  }
}

static long calculate_offsets() {
  // 获取 css_task_iter_start 版本, 以参数数量做判断
  uint32_t* css_task_iter_start_src = (uint32_t*)css_task_iter_start;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: css_task_iter_start %x %llx\n", i, css_task_iter_start_src[i]);
#endif /* CONFIG_DEBUG */
    if (css_task_iter_start_src[i] == ARM64_RET) {
      break;
    } else if ((css_task_iter_start_src[i] & MASK_MOV_Rm_2_Rn_WZR) == INST_MOV_Rm_2_Rn_WZR) {
      css_task_iter_start_ver5 = IZERO;
      break;
    }
  }
  // 获取 cgroup_kn_lock_live 版本, 以参数数量做判断
  uint32_t* cgroup_kn_lock_live_src = (uint32_t*)cgroup_kn_lock_live;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: cgroup_kn_lock_live %x %llx\n", i, cgroup_kn_lock_live_src[i]);
#endif /* CONFIG_DEBUG */
    if (cgroup_kn_lock_live_src[i] == ARM64_RET) {
      break;
    } else if ((cgroup_kn_lock_live_src[i] & MASK_MOV_Rm_1_Rn_WZR) == INST_MOV_Rm_1_Rn_WZR || (cgroup_kn_lock_live_src[i] & MASK_UXTB_Rn_1) == INST_UXTB_Rn_1) {
      cgroup_kn_lock_live_ver5 = IZERO;
      break;
    }
  }
  // 获取 cftype 版本, 以绑定函数做判断
  int (*cgroup_file_open)(struct kernfs_open_file* of) = NULL;
  cgroup_file_open = (typeof(cgroup_file_open))kallsyms_lookup_name("cgroup_file_open");

#ifdef CONFIG_DEBUG
  printk("cgroupv2_freeze: cgroup_file_open %llx\n", cgroup_file_open);
#endif /* CONFIG_DEBUG */
  if (cgroup_file_open) {
    cftype_ver5 = IZERO;
  }
  // 获取 cgroup_base_files 版本, 以变量名做判断
  struct cftype* cgroup_base_files = NULL;
  cgroup_base_files = (typeof(cgroup_base_files))kallsyms_lookup_name("cgroup_base_files");

#ifdef CONFIG_DEBUG
  printk("cgroupv2_freeze: cgroup_base_files %llx\n", cgroup_base_files);
#endif /* CONFIG_DEBUG */
  if (cgroup_base_files) {
    cgroup_base_files_ver5 = IZERO;
  }
  // 获取 task_struct->jobctl
  void (*do_signal_stop)(struct task_struct* t);
  lookup_name(do_signal_stop);

  uint32_t* do_signal_stop_src = (uint32_t*)do_signal_stop;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: do_signal_stop %x %llx\n", i, do_signal_stop_src[i]);
#endif /* CONFIG_DEBUG */
    if (do_signal_stop_src[i] == ARM64_RET) {
      break;
    } else if ((do_signal_stop_src[i] & MASK_LDR_64_) == INST_LDR_64_ && (do_signal_stop_src[i - 1] & MASK_MRS_SP_EL0) == INST_MRS_SP_EL0) {
      uint64_t imm12 = bits32(do_signal_stop_src[i], 21, 10);
      task_struct_jobctl_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (task_struct_jobctl_offset == UZERO) {
    return -11;
  }
  // 获取 task_struct->signal
  void (*tty_audit_fork)(struct signal_struct* sig);
  lookup_name(tty_audit_fork);

  uint32_t* tty_audit_fork_src = (uint32_t*)tty_audit_fork;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: tty_audit_fork %x %llx\n", i, tty_audit_fork_src[i]);
#endif /* CONFIG_DEBUG */
    if (tty_audit_fork_src[i] == ARM64_RET) {
      break;
    } else if ((tty_audit_fork_src[i] & MASK_LDR_64_) == INST_LDR_64_ && (tty_audit_fork_src[i - 1] & MASK_MRS_SP_EL0) == INST_MRS_SP_EL0) {
      uint64_t imm12 = bits32(tty_audit_fork_src[i], 21, 10);
      task_struct_signal_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (task_struct_signal_offset == UZERO) {
    return -11;
  }
  // 获取 signal_struct->flags, signal_struct->group_exit_task
  void (*zap_other_threads)(struct task_struct* t);
  lookup_name(zap_other_threads);

  uint32_t* zap_other_threads_src = (uint32_t*)zap_other_threads;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: zap_other_threads %x %llx\n", i, zap_other_threads_src[i]);
#endif /* CONFIG_DEBUG */
    if (zap_other_threads_src[i] == ARM64_RET) {
      break;
    } else if ((zap_other_threads_src[i] & MASK_STR_Rt_WZR) == INST_STR_Rt_WZR) {
      uint64_t imm12 = bits32(zap_other_threads_src[i], 21, 10);
      signal_struct_group_exit_task_offset = sign64_extend((imm12 << 0b10u), 16u) - 0x8; // signal_struct->group_stop_count
      signal_struct_flags_offset = signal_struct_group_exit_task_offset + 0xC;
      break;
    }
  }
  if (signal_struct_flags_offset == UZERO || signal_struct_group_exit_task_offset == UZERO) {
    return -11;
  }
  // 获取 task_struct->flags
  bool (*freezing_slow_path)(struct task_struct* p);
  lookup_name(freezing_slow_path);

  uint32_t* freezing_slow_path_src = (uint32_t*)freezing_slow_path;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: freezing_slow_path %x %llx\n", i, freezing_slow_path_src[i]);
#endif /* CONFIG_DEBUG */
    if (freezing_slow_path_src[i] == ARM64_RET) {
      break;
    } else if ((freezing_slow_path_src[i] & MASK_LDR_32_X0) == INST_LDR_32_X0) {
      uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
      task_struct_flags_offset = sign64_extend((imm12 << 0b10u), 16u);
      break;
    } else if ((freezing_slow_path_src[i] & MASK_LDR_64_X0) == INST_LDR_64_X0) {
      uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
      task_struct_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (task_struct_flags_offset == UZERO) {
    return -11;
  }
  // 获取 task_struct->state
  bool (*schedule_timeout_interruptible)(struct task_struct* p);
  lookup_name(schedule_timeout_interruptible);

  uint32_t* schedule_timeout_interruptible_src = (uint32_t*)schedule_timeout_interruptible;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: schedule_timeout_interruptible %x %llx\n", i, schedule_timeout_interruptible_src[i]);
#endif /* CONFIG_DEBUG */
    if (schedule_timeout_interruptible_src[i] == ARM64_RET) {
      break;
    } else if ((schedule_timeout_interruptible_src[i] & MASK_STR_64) == INST_STR_64) {
      uint64_t imm12 = bits32(schedule_timeout_interruptible_src[i], 21, 10);
      task_struct_state_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (task_struct_state_offset == UZERO) {
    return -11;
  }
  // 获取 seq_file->private
  int (*cgroup_subtree_control_show)(struct seq_file* seq, void* v);
  lookup_name(cgroup_subtree_control_show);

  uint32_t* cgroup_subtree_control_show_src = (uint32_t*)cgroup_subtree_control_show;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: cgroup_subtree_control_show %x %llx\n", i, cgroup_subtree_control_show_src[i]);
#endif /* CONFIG_DEBUG */
    if (cgroup_subtree_control_show_src[i] == ARM64_RET) {
      break;
    } else if ((cgroup_subtree_control_show_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
      uint64_t imm12 = bits32(cgroup_subtree_control_show_src[i], 21, 10);
      seq_file_private_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (seq_file_private_offset == UZERO) {
    return -11;
  }
  // 获取 freezer->state
  void (*cgroup_freezing)(struct task_struct* task);
  lookup_name(cgroup_freezing);

  uint32_t* cgroup_freezing_src = (uint32_t*)cgroup_freezing;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    printk("cgroupv2_freeze: cgroup_freezing %x %llx\n", i, cgroup_freezing_src[i]);
#endif /* CONFIG_DEBUG */
    if (cgroup_freezing_src[i] == ARM64_RET) {
      break;
    } else if ((cgroup_freezing_src[i] & MASK_LDR_32_) == INST_LDR_32_ && (cgroup_freezing_src[i + 1] & MASK_TST_32_6) == INST_TST_32_6) {
      uint64_t imm12 = bits32(cgroup_freezing_src[i], 21, 10);
      freezer_state_offset = sign64_extend((imm12 << 0b10u), 16u);
      cgroup_flags_offset = freezer_state_offset;
      break;
    }
  }
  if (freezer_state_offset == UZERO) {
    return -11;
  }

  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  // 有 do_freezer_trap 函数说明本身就是支持cgroupv2 freezer的
  void (*do_freezer_trap)(void);
  do_freezer_trap = (typeof(do_freezer_trap))kallsyms_lookup_name("do_freezer_trap");
  if (do_freezer_trap)
    return -24;

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

  lookup_name(cgroup_addrm_files);
  lookup_name(cgroup_init_cftypes);

  lookup_name(cgroup_procs_write);
  lookup_name(__kernfs_create_file);
  lookup_name(kernfs_setattr);

  lookup_name(get_signal);

  int rc = 0;
  rc = calculate_offsets();
  if (rc < 0)
    return rc;
  // 配置文件需要初始化一下
  if (cftype_ver5 == IZERO) {
    rc = cgroup_init_cftypes(NULL, cgroup_freeze_files);
  } else {
    rc = cgroup_init_cftypes(NULL, (struct cftype*)cgroup_freeze_files_v4);
  }
  if (rc < 0)
    return rc;

  hook_func(get_signal, 1, get_signal_before, NULL, NULL);
  hook_func(proc_pid_wchan, 4, proc_pid_wchan_before, NULL, NULL);
  hook_func(cgroup_addrm_files, 4, NULL, cgroup_addrm_files_after, NULL);
  hook_func(cgroup_procs_write, 4, NULL, cgroup_procs_write_after, NULL);
  // 高版本内核会自动处理所有者, 不再需要手动更改
  if (cgroup_base_files_ver5 != IZERO) {
    hook_func(__kernfs_create_file, 8, NULL, __kernfs_create_file_after, NULL);
  }

  return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  printk("\
cgroupv2_freeze: task_struct_state_offset=0x%llx\n\
cgroupv2_freeze: task_struct_flags_offset=0x%llx\n\
cgroupv2_freeze: task_struct_jobctl_offset=0x%llx\n\
cgroupv2_freeze: task_struct_signal_offset=0x%llx\n",
task_struct_state_offset,
task_struct_flags_offset,
task_struct_jobctl_offset,
task_struct_signal_offset);
  printk("\
cgroupv2_freeze: signal_struct_group_exit_task_offset=0x%llx\n\
cgroupv2_freeze: signal_struct_flags_offset=0x%llx\n\
cgroupv2_freeze: seq_file_private_offset=0x%llx\n\
cgroupv2_freeze: freezer_state_offset=0x%llx\n\
cgroupv2_freeze: cgroup_flags_offset=0x%llx\n",
signal_struct_group_exit_task_offset,
signal_struct_flags_offset,
seq_file_private_offset,
freezer_state_offset,
cgroup_flags_offset);
  char msg[64];
  snprintf(msg, sizeof(msg), "_(._.)_");
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  unhook_func(get_signal);
  unhook_func(proc_pid_wchan);
  unhook_func(cgroup_addrm_files);
  unhook_func(cgroup_procs_write);
  unhook_func(__kernfs_create_file);

  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
