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
#include <linux/umh.h>

#include "../kpm_utils.h"
#include "cfv2_utils.h"

KPM_NAME("cgroupv2_freeze");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("add cgroup.freeze, support 4.4 ~ 4.19");

#define GLOBAL_SYSTEM_UID KUIDT_INIT(1000)
#define GLOBAL_SYSTEM_GID KGIDT_INIT(1000)

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// 延迟加载, KernelPatch支持 事件加载 后弃用
static struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);

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
// run_cmd
int kfunc_def(call_usermodehelper)(const char* path, char** argv, char** envp, int wait);
int kfunc_def(call_usermodehelper_exec)(struct subprocess_info* info, int wait);
static int* selinux_enforcing;
struct selinux_state* selinux_state;

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

struct struct_offset struct_offset = {};
static uint64_t css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO, cftype_ver5 = UZERO,
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
        .flags = CFTYPE_NOT_ON_ROOT,
    },
    {},
};

static void cgroup_addrm_files_after(hook_fargs4_t* args, void* udata) {
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

static void call_usermodehelper_exec_before(hook_fargs2_t* args, void* udata) {
  struct subprocess_info* sub_info = (struct subprocess_info*)args->arg0;
  if (!sub_info)
    return;

  char** argv = subprocess_info_argv(sub_info);
  *(char**)((uintptr_t)sub_info + struct_offset.subprocess_info_path) = argv[0];
}

static void run_cmd(char* cmd[]) {
  char* envp[] = {"HOME=/", "PATH=/sbin:/bin", NULL};
  bool sel = true;
  hook_err_t err = 0;

  if (selinux_enforcing) {
    sel = *selinux_enforcing;
    *selinux_enforcing = false;
  } else {
    err = hook_wrap2(kf_call_usermodehelper_exec, call_usermodehelper_exec_before, NULL, NULL);
    sel = selinux_state->enforcing;
    selinux_state->enforcing = false;
  }

  for (int i = 0; cmd[i]; i++) {
    char* argv[] = {"/bin/sh", "-c", cmd[i], NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  }

  if (selinux_enforcing) {
    *selinux_enforcing = sel;
  } else {
    if (!err) {
      unhook(kf_call_usermodehelper_exec);
    }
    selinux_state->enforcing = sel;
  }
}

static const char apm[] = "/data/adb/modules/";
static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  struct filename* pathname = (struct filename*)args->arg1;
  if (!memcmp(pathname->name, apm, sizeof(apm) - 1)) {
    char* cmd[] = {
        "if [ ! -d \"/sys/fs/cgroup/uid_0\" ]; then\
  umount /sys/fs/cgroup/freezer;\
  umount /sys/fs/cgroup;\
\
  chown system:system /sys/fs/cgroup/;\
\
  if [ -d \"/dev/cg2_bpf/uid_0\" ]; then\
    mount -t cgroup2 none /sys/fs/cgroup/;\
  elif [ -d \"/acct/uid_0\" ]; then\
    mount -t cgroup -o cpuacct none /sys/fs/cgroup/;\
  else\
    exit;\
  fi;\
fi;\
\
if [ ! -d \"/sys/fs/cgroup/frozen\" ]; then\
  mkdir /sys/fs/cgroup/frozen/;\
  chown -R system:system /sys/fs/cgroup/frozen/;\
  echo 1 > /sys/fs/cgroup/frozen/cgroup.freeze;\
\
  mkdir /sys/fs/cgroup/unfrozen/;\
  chown -R system:system /sys/fs/cgroup/unfrozen/;\
fi",
        NULL};
    run_cmd(cmd);
    unhook_func(do_filp_open);
  }
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  // 有 cgroup_freeze_write 函数说明本身就支持cgroupv2 freezer
  void (*kf_cgroup_freeze_write)(void);
  kf_cgroup_freeze_write = (typeof(kf_cgroup_freeze_write))kallsyms_lookup_name("cgroup_freeze_write");
  if (kf_cgroup_freeze_write)
    return -24;

  lookup_name(do_filp_open);
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

  kfunc_lookup_name(call_usermodehelper);
  kfunc_lookup_name(call_usermodehelper_exec);

  selinux_enforcing = (typeof(selinux_enforcing))kallsyms_lookup_name("selinux_enforcing");
  selinux_state = (typeof(selinux_state))kallsyms_lookup_name("selinux_state");
  if (!selinux_enforcing && !selinux_state)
    return -21;

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
  // 配置文件需要初始化一下
  if (cftype_ver5 == IZERO) {
    cgroup_freeze_files->seq_show = cgroup_freeze_show;
    cgroup_freeze_files->write = cgroup_freeze_write;
  } else {
    cgroup_freeze_files->seq_show_v4 = cgroup_freeze_show;
    cgroup_freeze_files->write_v4 = cgroup_freeze_write;
  }
  rc = cgroup_init_cftypes(NULL, cgroup_freeze_files);
  if (rc < 0)
    return rc;

  hook_func(get_signal, 1, get_signal_before, NULL, NULL);
  hook_func(proc_pid_wchan, 4, proc_pid_wchan_before, NULL, NULL);
  hook_func(cgroup_addrm_files, 4, NULL, cgroup_addrm_files_after, NULL);
  hook_func(cgroup_procs_write, 4, NULL, cgroup_procs_write_after, NULL);
  hook_func(css_set_move_task, 4, NULL, css_set_move_task_after, NULL);
  // 高版本内核会自动处理所有者, 不再需要手动更改
  if (cgroup_base_files_ver5 != IZERO) {
    hook_func(__kernfs_create_file, 8, NULL, __kernfs_create_file_after, NULL);
  }

  if (!event || strcmp(event, "load-file")) {
    hook_func(do_filp_open, 3, NULL, do_filp_open_after, NULL);
  }

  return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
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
  unhook_func(css_set_move_task);
  unhook_func(__kernfs_create_file);
  unhook_func(do_filp_open);

  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
