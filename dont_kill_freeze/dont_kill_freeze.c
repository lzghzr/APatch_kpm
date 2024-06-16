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
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#ifdef CONFIG_DEBUG
#include <uapi/linux/limits.h>
#endif /* CONFIG_DEBUG */

#include "dont_kill_freeze.h"

KPM_NAME("dont_kill_freeze");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("dont_kill_freeze");

#define MIN_SYSTEM_UID 1000
#define MAX_SYSTEM_UID 2000
#define MIN_USERAPP_UID 10000
#define MAX_USERAPP_UID 90000

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// cgroup_freezing
static bool (*cgroup_freezing)(struct task_struct* task);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);
#ifdef CONFIG_DEBUG
static int (*get_cmdline)(struct task_struct* task, char* buffer, int buflen);
#endif /* CONFIG_DEBUG */

static uint64_t task_struct_flags_offset = UZERO, task_struct_jobctl_offset = UZERO;
static uint64_t last_uid = UZERO;

// cgroupv2_freeze
static inline bool jobctl_frozen(struct task_struct* task) {
  unsigned long jobctl = *(unsigned long*)((uintptr_t)task + task_struct_jobctl_offset);
  return ((jobctl & JOBCTL_TRAP_FREEZE) != 0);
}
// cgroupv1_freeze
static inline bool frozen(struct task_struct* task) {
  unsigned int flags = *(unsigned int*)((uintptr_t)task + task_struct_flags_offset);
  return (flags & PF_FROZEN);
}
// 判断线程是否进入 frozen 状态
static inline bool frozen_task_group(struct task_struct* task) {
  return (jobctl_frozen(task) || frozen(task) || cgroup_freezing(task));
}

char ActivityManager[] = "ActivityManager";
char lmkd[] = "lmkd";
static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
  int sig = (int)args->arg0;
  struct kernel_siginfo* siginfo = (struct kernel_siginfo*)args->arg1;
  struct task_struct* dst = (struct task_struct*)args->arg2;

#ifdef CONFIG_DEBUG
  if (sig == SIGKILL
    && task_uid(dst).val >= MIN_USERAPP_UID) {
    char cmdline[PATH_MAX];
    memset(&cmdline, 0, PATH_MAX);
    int res = get_cmdline(current, cmdline, PATH_MAX - 1);
    cmdline[res] = '\0';
    printk("dont_kill_freeze: killer=%d,dst=%d,cmdline=%s,comm=%s\n", task_uid(current).val, task_uid(dst).val, cmdline, get_task_comm(current));
  }
#endif /* CONFIG_DEBUG */
  if (sig != SIGKILL || siginfo->si_code != 0)
    return;
  if (task_uid(current).val < MIN_SYSTEM_UID
    || task_uid(dst).val == last_uid
    || task_uid(dst).val < MIN_USERAPP_UID
    || task_uid(dst).val > MAX_USERAPP_UID)
    return;

  const char* comm = get_task_comm(current);
  if ((!memcmp(comm, lmkd, sizeof(lmkd) - 1) || !memcmp(comm, ActivityManager, sizeof(ActivityManager) - 1))
    && frozen_task_group(dst)) {
    args->ret = -EPERM;
    args->skip_origin = true;
#ifdef CONFIG_DEBUG
    printk("dont_kill_freeze: skip\n");
#endif /* CONFIG_DEBUG */
  } else {
    last_uid = task_uid(dst).val;
  }
}

static long calculate_offsets() {
  // 获取 task_struct->jobctl
  void (*do_signal_stop)(struct task_struct* t);
  lookup_name(do_signal_stop);

  uint32_t* do_signal_stop_src = (uint32_t*)do_signal_stop;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_CONFIG_DEBUG
    printk("dont_kill_freeze: do_signal_stop %x %llx\n", i, do_signal_stop_src[i]);
#endif /* CONFIG_CONFIG_DEBUG */
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
  // 获取 task_struct->flags
  bool (*freezing_slow_path)(struct task_struct* p);
  lookup_name(freezing_slow_path);

  uint32_t* freezing_slow_path_src = (uint32_t*)freezing_slow_path;
  for (u32 i = 0; i < 0x20; i++) {
#ifdef CONFIG_CONFIG_DEBUG
    printk("dont_kill_freeze: freezing_slow_path %x %llx\n", i, freezing_slow_path_src[i]);
#endif /* CONFIG_CONFIG_DEBUG */
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

  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  lookup_name(cgroup_freezing);
  lookup_name(do_send_sig_info);
#ifdef CONFIG_DEBUG
  lookup_name(get_cmdline);
#endif /* CONFIG_DEBUG */

  int rc = calculate_offsets();
  if (rc < 0) {
    return rc;
  }

  hook_func(do_send_sig_info, 4, do_send_sig_info_before, NULL, NULL);

  return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  char msg[64];
  snprintf(msg, sizeof(msg), "_(._.)_");
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  unhook_func(do_send_sig_info);

  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
