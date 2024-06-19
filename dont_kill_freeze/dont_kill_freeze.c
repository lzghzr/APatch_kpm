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

#ifdef CONFIG_DEBUG_CMDLINE
#include <uapi/linux/limits.h>
#endif /* CONFIG_DEBUG_CMDLINE */

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

int kfunc_def(kstrtoint)(const char* s, unsigned int base, int* res);
char* kfunc_def(strim)(char* s);
// cgroup_freezing
static bool (*cgroup_freezing)(struct task_struct* task);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);
#ifdef CONFIG_DEBUG_CMDLINE
static int (*get_cmdline)(struct task_struct* task, char* buffer, int buflen);
#endif /* CONFIG_DEBUG_CMDLINE */

static uint64_t task_struct_jobctl_offset = UZERO, task_struct_signal_offset = UZERO, signal_struct_oom_score_adj_offset = UZERO,
last_uid = UZERO, oom_score_adj_max = UZERO;

static char android_display[] = "android.display";
// 有些内核可能是 "Binder:"
static char binder[] = "binder:";

// cgroupv2_freeze
static inline bool jobctl_frozen(struct task_struct* task) {
  unsigned long jobctl = *(unsigned long*)((uintptr_t)task + task_struct_jobctl_offset);
  return ((jobctl & JOBCTL_TRAP_FREEZE) != 0);
}
// 判断线程是否进入 frozen 状态
static inline bool frozen_task_group(struct task_struct* task) {
  return (jobctl_frozen(task) || cgroup_freezing(task));
}

static inline short get_oom_score_adj(struct task_struct* task) {
  struct signal_struct* signal = *(struct signal_struct**)((uintptr_t)task + task_struct_signal_offset);
  short oom_score_adj = *(short*)((uintptr_t)signal + signal_struct_oom_score_adj_offset);
  return oom_score_adj;
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
  int sig = (int)args->arg0;
  struct kernel_siginfo* siginfo = (struct kernel_siginfo*)args->arg1;
  struct task_struct* dst = (struct task_struct*)args->arg2;
#ifdef CONFIG_DEBUG
  if (sig == SIGKILL
    && task_uid(dst).val > MIN_USERAPP_UID) {
    printk("dont_kill_freeze: killer=%d,comm=%s,dst=%d,oom_score_adj=%d,frozen=%d\n",
      task_uid(current).val, get_task_comm(current), task_uid(dst).val, get_oom_score_adj(dst), frozen_task_group(dst));
  }
#endif /* CONFIG_DEBUG */
// cmdline 速度非常非常慢
#ifdef CONFIG_DEBUG_CMDLINE
  if (sig == SIGKILL
    && task_uid(dst).val > MIN_USERAPP_UID) {
    char cmdline[PATH_MAX];
    memset(&cmdline, 0, PATH_MAX);
    int res = get_cmdline(current, cmdline, PATH_MAX - 1);
    cmdline[res] = '\0';
    printk("dont_kill_freeze: cmdline=%s\n", cmdline);
  }
#endif /* CONFIG_DEBUG_CMDLINE */
  if (sig != SIGKILL || siginfo->si_code != 0)
    return;
  if (task_uid(current).val < MIN_SYSTEM_UID || task_uid(current).val > MAX_SYSTEM_UID)
    return;
  if (task_uid(dst).val == last_uid
    || task_uid(dst).val < MIN_USERAPP_UID
    || get_oom_score_adj(dst) > oom_score_adj_max)
    return;

  const char* comm = get_task_comm(current);
  if (memcmp(comm + 1, binder + 1, sizeof(binder) - 2)
    && memcmp(comm, android_display, sizeof(android_display) - 1)
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
  void (*task_clear_jobctl_trapping)(struct task_struct* t);
  lookup_name(task_clear_jobctl_trapping);

  uint32_t* task_clear_jobctl_trapping_src = (uint32_t*)task_clear_jobctl_trapping;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    printk("dont_kill_freeze: task_clear_jobctl_trapping %x %llx\n", i, task_clear_jobctl_trapping_src[i]);
#endif /* CONFIG_DEBUG */
    if (task_clear_jobctl_trapping_src[i] == ARM64_RET) {
      break;
    } else if ((task_clear_jobctl_trapping_src[i] & MASK_LDR_64_Rn_X0) == INST_LDR_64_Rn_X0) {
      uint64_t imm12 = bits32(task_clear_jobctl_trapping_src[i], 21, 10);
      task_struct_jobctl_offset = sign64_extend((imm12 << 0b11u), 16u);
      break;
    }
  }
  if (task_struct_jobctl_offset == UZERO) {
    return -11;
  }
  // 获取 task_struct->signal, signal_struct->oom_score_adj
  void (*out_of_memory)(struct task_struct* p, unsigned long totalpages);
  lookup_name(out_of_memory);

  uint32_t* out_of_memory_src = (uint32_t*)out_of_memory;
  for (u32 i = 0; i < 0xa0; i++) {
#ifdef CONFIG_DEBUG
    printk("dont_kill_freeze: out_of_memory %x %llx\n", i, out_of_memory_src[i]);
#endif /* CONFIG_DEBUG */
    if ((out_of_memory_src[i] & MASK_LDR_64_) == INST_LDR_64_ && (out_of_memory_src[i + 1] & MASK_LDRSH) == INST_LDRSH) {
      uint64_t imm12 = 0;
      imm12 = bits32(out_of_memory_src[i], 21, 10);
      task_struct_signal_offset = sign64_extend((imm12 << 0b11u), 16u);

      imm12 = bits32(out_of_memory_src[i + 1], 21, 10);
      signal_struct_oom_score_adj_offset = sign64_extend((imm12 << 1u), 16u);
      break;
    }
  }
  if (task_struct_signal_offset == UZERO || signal_struct_oom_score_adj_offset == UZERO) {
    return -11;
  }

  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  kfunc_lookup_name(kstrtoint);
  kfunc_lookup_name(strim);

  lookup_name(cgroup_freezing);
  lookup_name(do_send_sig_info);
#ifdef CONFIG_DEBUG_CMDLINE
  lookup_name(get_cmdline);
#endif /* CONFIG_DEBUG_CMDLINE */

  int rc = calculate_offsets();
  if (rc < 0) {
    return rc;
  }

  if (args) {
    int oom_score_adj;
    rc = kfunc(kstrtoint)(kfunc(strim)((char*)args), 0, &oom_score_adj);
    if (!rc) {
      oom_score_adj_max = oom_score_adj;
    }
  }

  hook_func(do_send_sig_info, 4, do_send_sig_info_before, NULL, NULL);

  return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  char msg[64];

  int rc;
  int oom_score_adj;
  if (ctl_args) {
    rc = kfunc(kstrtoint)(kfunc(strim)((char*)ctl_args), 0, &oom_score_adj);
  } else {
    rc = -22;
  }
  if (rc) {
    snprintf(msg, sizeof(msg), "_(x_x)_");
  } else {
    oom_score_adj_max = oom_score_adj;
    snprintf(msg, sizeof(msg), "_(._.)_");
  }

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
