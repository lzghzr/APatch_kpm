// task_state_ptr
static inline volatile long *task_state_ptr(struct task_struct *task) {
  volatile long *state = (volatile long *)((uintptr_t)task + struct_offset.task_struct_state);
  return state;
}
// task_flags
static inline unsigned int task_flags(struct task_struct *task) {
  unsigned int flags = *(unsigned int *)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_flags_ptr
static inline unsigned int *task_flags_ptr(struct task_struct *task) {
  unsigned int *flags = (unsigned int *)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_jobctl
static inline unsigned long task_jobctl(struct task_struct *task) {
  unsigned long jobctl = *(unsigned long *)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_jobctl_ptr
static inline unsigned long *task_jobctl_ptr(struct task_struct *task) {
  unsigned long *jobctl = (unsigned long *)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_signal
static inline struct signal_struct *task_signal(struct task_struct *task) {
  struct signal_struct *signal = *(struct signal_struct **)((uintptr_t)task + struct_offset.task_struct_signal);
  return signal;
}
// signal_group_exit_task
static inline struct task_struct *signal_group_exit_task(struct signal_struct *sig) {
  struct task_struct *group_exit_task =
      *(struct task_struct **)((uintptr_t)sig + struct_offset.signal_struct_group_exit_task);
  return group_exit_task;
}
// signal_flags
static inline unsigned int signal_flags(struct signal_struct *sig) {
  unsigned int flags = *(unsigned int *)((uintptr_t)sig + struct_offset.signal_struct_flags);
  return flags;
}
// seq_file_private
static inline struct kernfs_open_file *seq_file_private(struct seq_file *seq) {
  struct kernfs_open_file *private = *(struct kernfs_open_file **)((uintptr_t)seq + struct_offset.seq_file_private);
  return private;
}
// cgroup_flags_ptr
static inline unsigned long *cgroup_flags_ptr(struct cgroup *cgrp) {
  unsigned long *flags = (unsigned long *)((uintptr_t)cgrp + struct_offset.cgroup_flags);
  return flags;
}
// css_set_dfl_cgrp
static inline struct cgroup *css_set_dfl_cgrp(struct css_set *cset) {
  struct cgroup *cgrp = *(struct cgroup **)((uintptr_t)cset + struct_offset.css_set_dfl_cgrp);
  return cgrp;
}
// subprocess_info_argv
static inline char **subprocess_info_argv(struct subprocess_info *sub_info) {
  char **argv = *(char ***)((uintptr_t)sub_info + struct_offset.subprocess_info_argv);
  return argv;
}

static long calculate_offsets() {
  // 获取 css_task_iter_start 版本, 以参数数量做判断
  uint32_t *css_task_iter_start_src = (uint32_t *)css_task_iter_start;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("css_task_iter_start %x %llx\n", i, css_task_iter_start_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(css_task_iter_start_src[i])) {
      break;
    } else if (inst_get_mov_reg_rm(css_task_iter_start_src[i]) == 2) {
      css_task_iter_start_ver5 = IZERO;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("css_task_iter_start_ver5=0x%llx\n", css_task_iter_start_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cgroup_kn_lock_live 版本, 以参数数量做判断
  uint32_t *cgroup_kn_lock_live_src = (uint32_t *)cgroup_kn_lock_live;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("cgroup_kn_lock_live %x %llx\n", i, cgroup_kn_lock_live_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(cgroup_kn_lock_live_src[i])) {
      break;
    } else if (inst_get_mov_reg_rm(cgroup_kn_lock_live_src[i]) == 1
               || inst_get_uxtb_rn(cgroup_kn_lock_live_src[i]) == 1) {
      cgroup_kn_lock_live_ver5 = IZERO;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("cgroup_kn_lock_live_ver5=0x%llx\n", cgroup_kn_lock_live_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cftype 版本, 以绑定函数做判断
  int (*cgroup_file_open)(struct kernfs_open_file *of) = NULL;
  cgroup_file_open = (typeof(cgroup_file_open))kallsyms_lookup_name("cgroup_file_open");

#ifdef CONFIG_DEBUG
  logkm("cgroup_file_open %llx\n", cgroup_file_open);
#endif /* CONFIG_DEBUG */
  if (cgroup_file_open) {
    cftype_ver5 = IZERO;
  }
#ifdef CONFIG_DEBUG
  logkm("cftype_ver5=0x%llx\n", cftype_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cgroup_base_files 版本, 以变量名做判断
  struct cftype *cgroup_base_files = NULL;
  cgroup_base_files = (typeof(cgroup_base_files))kallsyms_lookup_name("cgroup_base_files");

#ifdef CONFIG_DEBUG
  logkm("cgroup_base_files %llx\n", cgroup_base_files);
#endif /* CONFIG_DEBUG */
  if (cgroup_base_files) {
    cgroup_base_files_ver5 = IZERO;
  }
#ifdef CONFIG_DEBUG
  logkm("cgroup_base_files_ver5=0x%llx\n", cgroup_base_files_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 task_struct->jobctl
  void (*task_clear_jobctl_trapping)(struct task_struct *t);
  lookup_name(task_clear_jobctl_trapping);

  uint32_t *task_clear_jobctl_trapping_src = (uint32_t *)task_clear_jobctl_trapping;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("task_clear_jobctl_trapping %x %llx\n", i, task_clear_jobctl_trapping_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(task_clear_jobctl_trapping_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(task_clear_jobctl_trapping_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(task_clear_jobctl_trapping_src[i]) == 0) {
      struct_offset.task_struct_jobctl = inst_get_ldr_imm_uint_imm(task_clear_jobctl_trapping_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_jobctl=0x%llx\n", struct_offset.task_struct_jobctl);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_jobctl <= 0)
    return -11;

  // 获取 task_struct->signal
  void (*tty_audit_fork)(struct signal_struct *sig);
  lookup_name(tty_audit_fork);

  uint32_t *tty_audit_fork_src = (uint32_t *)tty_audit_fork;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("tty_audit_fork %x %llx\n", i, tty_audit_fork_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(tty_audit_fork_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(tty_audit_fork_src[i]) == 0b11
               && inst_is_mrs_sp_el0(tty_audit_fork_src[i - 1])) {
      struct_offset.task_struct_signal = inst_get_ldr_imm_uint_imm(tty_audit_fork_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_signal=0x%llx\n", struct_offset.task_struct_signal);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_signal <= 0)
    return -11;

  // 获取 signal_struct->flags, signal_struct->group_exit_task
  void (*zap_other_threads)(struct task_struct *t);
  lookup_name(zap_other_threads);

  uint32_t *zap_other_threads_src = (uint32_t *)zap_other_threads;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("zap_other_threads %x %llx\n", i, zap_other_threads_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(zap_other_threads_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_rt(zap_other_threads_src[i]) == 31) {
      uint64_t offset = inst_get_str_imm_uint_imm(zap_other_threads_src[i]);  // signal_struct->group_stop_count
      struct_offset.signal_struct_group_exit_task = offset - 0x8;
      struct_offset.signal_struct_flags = offset + 0x4;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("signal_struct_group_exit_task=0x%llx\n", struct_offset.signal_struct_group_exit_task);
  logkm("signal_struct_flags=0x%llx\n", struct_offset.signal_struct_flags);
#endif /* CONFIG_DEBUG */
  if (struct_offset.signal_struct_group_exit_task <= 0)
    return -11;

  // 获取 task_struct->flags
  bool (*freezing_slow_path)(struct task_struct *p);
  lookup_name(freezing_slow_path);

  uint32_t *freezing_slow_path_src = (uint32_t *)freezing_slow_path;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("freezing_slow_path %x %llx\n", i, freezing_slow_path_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(freezing_slow_path_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_rn(freezing_slow_path_src[i]) == 0) {
      struct_offset.task_struct_flags = inst_get_ldr_imm_uint_imm(freezing_slow_path_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_flags=0x%llx\n", struct_offset.task_struct_flags);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_flags <= 0)
    return -11;

  // 获取 task_struct->state
  bool (*schedule_timeout_interruptible)(struct task_struct *p);
  lookup_name(schedule_timeout_interruptible);

  uint32_t *schedule_timeout_interruptible_src = (uint32_t *)schedule_timeout_interruptible;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("schedule_timeout_interruptible %x %llx\n", i, schedule_timeout_interruptible_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(schedule_timeout_interruptible_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_size(schedule_timeout_interruptible_src[i]) == 0b11) {
      struct_offset.task_struct_state = inst_get_str_imm_uint_imm(schedule_timeout_interruptible_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_state=0x%llx\n", struct_offset.task_struct_state);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_state <= 0)
    return -11;

  // 获取 seq_file->private
  int (*cgroup_subtree_control_show)(struct seq_file *seq, void *v);
  lookup_name(cgroup_subtree_control_show);

  uint32_t *cgroup_subtree_control_show_src = (uint32_t *)cgroup_subtree_control_show;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("cgroup_subtree_control_show %x %llx\n", i, cgroup_subtree_control_show_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(cgroup_subtree_control_show_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(cgroup_subtree_control_show_src[i]) == 0b11) {
      struct_offset.seq_file_private = inst_get_ldr_imm_uint_imm(cgroup_subtree_control_show_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("seq_file_private=0x%llx\n", struct_offset.seq_file_private);
#endif /* CONFIG_DEBUG */
  if (struct_offset.seq_file_private <= 0)
    return -11;

  // 获取 freezer->state
  void (*cgroup_freezing)(struct task_struct *task);
  lookup_name(cgroup_freezing);

  uint32_t *cgroup_freezing_src = (uint32_t *)cgroup_freezing;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("cgroup_freezing %x %llx\n", i, cgroup_freezing_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(cgroup_freezing_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(cgroup_freezing_src[i]) == 0b10
               && inst_get_tst_imm_sf(cgroup_freezing_src[i + 1]) == 0
               && inst_get_tst_imm_imm(cgroup_freezing_src[i + 1]) == 6) {
      struct_offset.freezer_state = inst_get_ldr_imm_uint_imm(cgroup_freezing_src[i]);
      struct_offset.cgroup_flags = struct_offset.freezer_state;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("freezer_state=0x%llx\n", struct_offset.freezer_state);
#endif /* CONFIG_DEBUG */
  if (struct_offset.freezer_state <= 0)
    return -11;

  // 获取 task_struct->css_set
  void (*cgroup_fork)(struct task_struct *child);
  lookup_name(cgroup_fork);

  uint32_t *cgroup_fork_src = (uint32_t *)cgroup_fork;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("cgroup_fork %x %llx\n", i, cgroup_fork_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(cgroup_fork_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_size(cgroup_fork_src[i]) == 0b11) {
      struct_offset.task_struct_css_set = inst_get_str_imm_uint_imm(cgroup_fork_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_css_set=0x%llx\n", struct_offset.task_struct_css_set);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_css_set <= 0)
    return -11;

  // 获取 css_set->dfl_cgrp
  struct css_set kvar_def(init_css_set);
  kvar_lookup_name(init_css_set);
  // 4.4 4.9 未发现 0x48 以外的偏移
  // 4.14 4.19 新增 init_css_set->dom_cset = &init_css_set ,可据此计算偏移
  struct_offset.css_set_dfl_cgrp = 0x48;
  uint64_t *init_css_set_src = (uint64_t *)kvar(init_css_set);
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("init_css_set %x %llx\n", i, init_css_set_src[i]);
#endif /* CONFIG_DEBUG */
    if (init_css_set_src[i] == (uint64_t)kvar(init_css_set)) {
      struct_offset.css_set_dfl_cgrp = (i + 1) * 8;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("init_css_set=0x%llx\n", kvar(init_css_set));
  logkm("css_set_dfl_cgrp=0x%llx\n", struct_offset.css_set_dfl_cgrp);
#endif /* CONFIG_DEBUG */
  if (struct_offset.css_set_dfl_cgrp <= 0)
    return -11;

  // 获取 subprocess_info->path, subprocess_info->argv
  uint32_t *call_usermodehelper_exec_src = (uint32_t *)kfunc(call_usermodehelper_exec);
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_DEBUG
    logkm("call_usermodehelper_exec %x %llx\n", i, call_usermodehelper_exec_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(call_usermodehelper_exec_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(call_usermodehelper_exec_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(call_usermodehelper_exec_src[i]) == 0) {
      struct_offset.subprocess_info_path = inst_get_ldr_imm_uint_imm(call_usermodehelper_exec_src[i]);
      struct_offset.subprocess_info_argv = struct_offset.subprocess_info_path + 0x8;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("subprocess_info_path=0x%llx\n", struct_offset.subprocess_info_path);
  logkm("subprocess_info_argv=0x%llx\n", struct_offset.subprocess_info_argv);
#endif /* CONFIG_DEBUG */
  if (struct_offset.subprocess_info_path <= 0)
    return -11;

  return 0;
}
