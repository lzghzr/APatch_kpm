/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __DONT_KILL_FREEZE_H
#define __DONT_KILL_FREEZE_H

#include <hook.h>
#include <ksyms.h>
#include <linux/cred.h>
#include <linux/sched.h>

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
  (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_Rn_X0 0xF9400000u
#define INST_LDRSH 0x79800000u

#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_Rn_X0 0xFFC003E0u
#define MASK_LDRSH 0xFF800000u

#define ARM64_RET 0xD65F03C0

#define logkm(fmt, ...) printk("dont_kill_freeze: " fmt, ##__VA_ARGS__)

#define lookup_name(func)                                  \
  func = 0;                                                \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
  {                                                        \
    return -21;                                            \
  }

#define hook_func(func, argv, before, after, udata)                         \
  if (!func)                                                                \
  {                                                                         \
    return -22;                                                             \
  }                                                                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func)                                                      \
  {                                                                         \
    func = 0;                                                               \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  }                                                                         \
  else                                                                      \
  {                                                                         \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)            \
  if (func && !is_bad_address(func)) \
  {                                  \
    unhook(func);                    \
    func = 0;                        \
  }

#define task_real_uid(task)                                                                       \
  ({                                                                                              \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                        \
    ___val;                                                                                       \
  })

#define task_uid(task) task_real_uid(task)
  // ({                                                                                         \
  //   struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
  //   kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                   \
  //   ___val;                                                                                  \
  // })

// linux/sched/jobctl.h
#define JOBCTL_TRAP_FREEZE_BIT 23
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)

// uapi/asm/signal.h
#define SIGKILL 9
struct siginfo;

// linux/signal_types.h
#define __SIGINFO \
struct {          \
	int si_signo; \
	int si_errno; \
	int si_code;  \
}
typedef struct kernel_siginfo {
  __SIGINFO;
} kernel_siginfo_t;

// linux/schde.h
#define PF_FROZEN 0x00010000

// include/linux/cgroup-defs.h
enum {
  CGRP_NOTIFY_ON_RELEASE,
  CGRP_CPUSET_CLONE_CHILDREN,
  CGRP_FREEZE,
  CGRP_FROZEN,
};
struct cgroup;

#endif /* __DONT_KILL_FREEZE_H */
