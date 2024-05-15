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

#define INST_ADD_64 0x91000000u
#define INST_ADD_64_Rn_X0 0x91000000u
#define INST_ADD_64_Rn_X19_Rd_X0 0x91000260u
#define INST_ADD_64_Rd_X0 0x91000000u
#define INST_ADD_64_Rd_X1 0x91000001u
#define INST_LDR_32_ 0xB9400000u
#define INST_LDR_32_X0 0xB9400000u
#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_X0 0xF9400000u
#define INST_LDR_64_SP 0xF94003E0u
#define INST_LDRB 0x39400000u
#define INST_LDRB_X0 0x39400000u
#define INST_LDRH 0x79400000u
#define INST_STR_32_x0 0xB9000000u
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000u
#define INST_TBNZ 0x37000000u
#define INST_TBNZ_5 0x37280000u

#define MASK_ADD_64 0xFF800000u
#define MASK_ADD_64_Rn_X0 0xFF8003E0u
#define MASK_ADD_64_Rn_X19_Rd_X0 0xFF8003FFu
#define MASK_ADD_64_Rd_X0 0xFF80001Fu
#define MASK_ADD_64_Rd_X1 0xFF80001Fu
#define MASK_LDR_32_ 0xFFC00000u
#define MASK_LDR_32_X0 0xFFC003E0u
#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_X0 0xFFC003E0u
#define MASK_LDR_64_SP 0xFFC003E0u
#define MASK_LDRB 0xFFC00000u
#define MASK_LDRB_X0 0xFFC003E0u
#define MASK_LDRH 0xFFC00000u
#define MASK_STR_32_x0 0xFFC003E0u
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_TBNZ_5 0xFFF80000u

#define ARM64_RET 0xD65F03C0

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

#define task_uid(task) task_real_uid(task)
  // ({                                                                                         \
  //   struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
  //   kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                   \
  //   ___val;                                                                                  \
  // })

#define task_real_uid(task)                                                                       \
  ({                                                                                              \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                        \
    ___val;                                                                                       \
  })


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

#endif /* __DONT_KILL_FREEZE_H */
