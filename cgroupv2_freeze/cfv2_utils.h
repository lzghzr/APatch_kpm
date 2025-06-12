/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __CF_UTILS_H
#define __CF_UTILS_H

#include <hook.h>
#include <ksyms.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/asm-generic/errno.h>

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
  (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_ADRP 0x90000000
#define INST_CMP_64_Xn_Xm 0xEB00001F
#define INST_MRS_SP_EL0 0xD5384100u
#define INST_LDR_32_ 0xB9400000u
#define INST_LDR_32_X0 0xB9400000u
#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_Rn_X0 0xF9400000u
#define INST_MOV_Rm_1_Rn_WZR 0x2A0103E0u
#define INST_MOV_Rm_2_Rn_WZR 0x2A0203E0u
#define INST_MOV_Rm_3_Rn_WZR 0x2A0303E0u
#define INST_MOV_Rm_4_Rn_WZR 0x2A0403E0u
#define INST_STR_64 0xF9000000u
#define INST_STR_Rt_WZR 0xB900001Fu
#define INST_TST_32_6 0x721F041Fu
#define INST_UXTB_Rn_1 0x53001C20u

#define MASK_ADRP 0x9F000000
#define MASK_CMP_64_Xn_Xm 0xFFE0FC1F
#define MASK_MRS_SP_EL0 0xFFFFFFE0u
#define MASK_LDR_32_ 0xFFC00000u
#define MASK_LDR_32_X0 0xFFC003E0u
#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_Rn_X0 0xFFC003E0u
#define MASK_MOV_Rm_1_Rn_WZR 0x7FFFFFE0u
#define MASK_MOV_Rm_2_Rn_WZR 0x7FFFFFE0u
#define MASK_MOV_Rm_3_Rn_WZR 0x7FFFFFE0u
#define MASK_MOV_Rm_4_Rn_WZR 0x7FFFFFE0u
#define MASK_STR_64 0xFFC00000u
#define MASK_STR_Rt_WZR 0xFFC0001Fu
#define MASK_TST_32_6 0xFFFFFC1Fu
#define MASK_UXTB_Rn_1 0xFFFFFFE0u

#define ARM64_RET 0xD65F03C0

#define logkm(fmt, ...) printk("cgroupv2_freeze: " fmt, ##__VA_ARGS__)

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

enum inst_type {
  ARM64_LDR_32,
  ARM64_LDR_64,
  ARM64_STR_32,
  ARM64_STR_64,
};
struct struct_offset {
  int16_t cgroup_flags;
  int16_t css_set_dfl_cgrp;
  int16_t freezer_state;
  int16_t seq_file_private;
  int16_t signal_struct_flags;
  int16_t signal_struct_group_exit_task;
  int16_t subprocess_info_argv;
  int16_t subprocess_info_path;
  int16_t task_struct_css_set;
  int16_t task_struct_flags;
  int16_t task_struct_jobctl;
  int16_t task_struct_signal;
  int16_t task_struct_state;
};

#endif /* __CF_UTILS_H */
