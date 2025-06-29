/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef _KPM_UTILS_H
#define _KPM_UTILS_H

#include <hook.h>
#include <linux/cred.h>
#include <linux/sched.h>

// hook
#define lookup_name(func)                                  \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
    return -21;

#define lookup_name_continue(func)                  \
  func = (typeof(func))kallsyms_lookup_name(#func); \
  pr_info("kernel function %s addr: %llx\n", #func, func);

#define hook_func(func, argv, before, after, udata)                         \
  if (!func)                                                                \
    return -22;                                                             \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func) {                                                    \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  } else {                                                                  \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)            \
  if (func && !is_bad_address(func)) \
    unhook(func);

// task id
#define __GET_CREDID(type, task)                                                             \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.type##_offset);                \
    ___val;                                                                                  \
  })

#define task_uid(task) __GET_CREDID(uid, task)
#define task_gid(task) __GET_CREDID(gid, task)
#define task_euid(task) __GET_CREDID(euid, task)
#define task_egid(task) __GET_CREDID(egid, task)
#define task_suid(task) __GET_CREDID(suid, task)
#define task_sgid(task) __GET_CREDID(sgid, task)

// instruction
#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
  (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
// https://github.com/llvm/llvm-project/blob/f280d3b705de7f94ef9756e3ef2842b415a7c038/llvm/lib/Target/AArch64/MCTargetDesc/AArch64AddressingModes.h#L293
#define ror(elt, size) (((elt) & 1) << ((size) - 1)) | ((elt) >> 1)

#define __INST_GET_IMM6(abbr) \
  static inline int inst_get_##abbr##_imm6(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 15, 10) : -1; }

#define __INST_GET_IMM12(abbr) \
  static inline int inst_get_##abbr##_imm12(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 21, 10) : -1; }
#define __INST_GET_SIZE_IMM12_IMM(abbr)                     \
  static inline long inst_get_##abbr##_imm(uint32_t code) { \
    if (!inst_is_##abbr(code))                              \
      return -1;                                            \
    int size = inst_get_##abbr##_size(code);                \
    int imm12 = inst_get_##abbr##_imm12(code);              \
    if (size == -1 || imm12 == -1)                          \
      return -1;                                            \
    return sign64_extend(((uint64_t)imm12 << size), 14u);   \
  }
#define __INST_GET_SH_IMM12_IMM(abbr)                                                                 \
  static inline long inst_get_##abbr##_imm(uint32_t code) {                                           \
    if (!inst_is_##abbr(code))                                                                        \
      return -1;                                                                                      \
    int sh = inst_get_##abbr##_sh(code);                                                              \
    int imm12 = inst_get_##abbr##_imm12(code);                                                        \
    if (sh == -1 || imm12 == -1)                                                                      \
      return -1;                                                                                      \
    return sh ? sign64_extend(((uint64_t)imm12 << 12u), 14u) : sign64_extend(((uint64_t)imm12), 14u); \
  }

#define __INST_GET_IMM14(abbr) \
  static inline int inst_get_##abbr##_imm14(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 18, 5) : -1; }
#define __INST_GET_IMM19(abbr) \
  static inline int inst_get_##abbr##_imm19(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 23, 5) : -1; }
#define __INST_GET_IMM26(abbr) \
  static inline int inst_get_##abbr##_imm26(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 25, 0) : -1; }

#define __INST_GET_N(abbr) \
  static inline int inst_get_##abbr##_n(uint32_t code) { return inst_is_##abbr(code) ? bit(code, 22) : -1; }
#define __INST_GET_IMMR(abbr) \
  static inline int inst_get_##abbr##_immr(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 21, 16) : -1; }
#define __INST_GET_IMMS(abbr) \
  static inline int inst_get_##abbr##_imms(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 15, 10) : -1; }
#define __INST_GET_IMMR_IMMS_IMM(abbr)                        \
  static inline long inst_get_##abbr##_imm(uint32_t code) {   \
    if (!inst_is_##abbr(code))                                \
      return -1;                                              \
    int sf = inst_get_##abbr##_sf(code);                      \
    int N = inst_get_##abbr##_n(code);                        \
    if (sf == 0 && N != 0)                                    \
      return -10;                                             \
    int immr = inst_get_##abbr##_immr(code);                  \
    int imms = inst_get_##abbr##_imms(code);                  \
    int len = 31 - __builtin_clz((N << 6) | (~imms & 0x3f));  \
    if (len < 0)                                              \
      return -11;                                             \
    int size = (1 << len);                                    \
    int R = immr & (size - 1);                                \
    int S = imms & (size - 1);                                \
    if (S == size - 1)                                        \
      return -12;                                             \
    long pattern = (1ULL << (S + 1)) - 1;                     \
    for (int i = 0; i < R; ++i) pattern = ror(pattern, size); \
    int regSize = (sf == 0) ? 32 : 64;                        \
    while (size != regSize) {                                 \
      pattern |= (pattern << size);                           \
      size *= 2;                                              \
    }                                                         \
    return pattern;                                           \
  }

#define __INST_GET_IMMLO(abbr) \
  static inline int inst_get_##abbr##_immlo(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 30, 29) : -1; }
#define __INST_GET_IMMHI(abbr) \
  static inline int inst_get_##abbr##_immhi(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 23, 5) : -1; }
#define __INST_GET_LABEL(abbr)                                  \
  static inline long inst_get_##abbr##_label(uint32_t code) {   \
    if (!inst_is_##abbr(code))                                  \
      return -1;                                                \
    int immlo = inst_get_##abbr##_immlo(code);                  \
    int immhi = inst_get_##abbr##_immhi(code);                  \
    if (immlo == -1 || immhi == -1)                             \
      return -1;                                                \
    return sign64_extend((immhi << 14u) | (immlo << 12u), 33u); \
  }

#define __INST_GET_SF(abbr) \
  static inline int inst_get_##abbr##_sf(uint32_t code) { return inst_is_##abbr(code) ? bit(code, 31) : -1; }
#define __INST_GET_SIZE(abbr) \
  static inline int inst_get_##abbr##_size(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 31, 30) : -1; }
#define __INST_GET_SH(abbr) \
  static inline int inst_get_##abbr##_sh(uint32_t code) { return inst_is_##abbr(code) ? bit(code, 22) : -1; }
#define __INST_GET_RM(abbr) \
  static inline int inst_get_##abbr##_rm(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 20, 16) : -1; }
#define __INST_GET_RN(abbr) \
  static inline int inst_get_##abbr##_rn(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 9, 5) : -1; }
#define __INST_GET_RD(abbr) \
  static inline int inst_get_##abbr##_rd(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 4, 0) : -1; }
#define __INST_GET_RT(abbr) \
  static inline int inst_get_##abbr##_rt(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 4, 0) : -1; }

#define __INST_FUNCS(abbr, mask, val)                                                   \
  static inline bool inst_is_##abbr(uint32_t code) { return (code & (mask)) == (val); } \
  static inline uint32_t inst_get_##abbr##_value(void) { return (val); }

#define __INST_SF_FUNCS(abbr, mask, val) \
  __INST_FUNCS(abbr, mask, val)          \
  __INST_GET_SF(abbr)
#define __INST_RN_FUNCS(abbr, mask, val) \
  __INST_FUNCS(abbr, mask, val)          \
  __INST_GET_RN(abbr)
#define __INST_RD_FUNCS(abbr, mask, val) \
  __INST_FUNCS(abbr, mask, val)          \
  __INST_GET_RD(abbr)

#define __INST_SF_RM_FUNCS(abbr, mask, val) \
  __INST_SF_FUNCS(abbr, mask, val)          \
  __INST_GET_RM(abbr)
#define __INST_SF_RM_RN_FUNCS(abbr, mask, val) \
  __INST_SF_RM_FUNCS(abbr, mask, val)          \
  __INST_GET_RN(abbr)
#define __INST_SF_RM_RD_FUNCS(abbr, mask, val) \
  __INST_SF_RM_FUNCS(abbr, mask, val)          \
  __INST_GET_RD(abbr)
#define __INST_SF_RM_RN_RD_FUNCS(abbr, mask, val) \
  __INST_SF_RM_RN_FUNCS(abbr, mask, val)          \
  __INST_GET_RD(abbr)

#define __INST_SF_RN_FUNCS(abbr, mask, val) \
  __INST_SF_FUNCS(abbr, mask, val)          \
  __INST_GET_RN(abbr)
#define __INST_SF_RN_RD_FUNCS(abbr, mask, val) \
  __INST_SF_RN_FUNCS(abbr, mask, val)          \
  __INST_GET_RD(abbr)
#define __INST_SF_RN_RD_SH_IMM12_FUNCS(abbr, mask, val) \
  __INST_SF_RN_RD_FUNCS(abbr, mask, val)                \
  __INST_GET_SH(abbr)                                   \
  __INST_GET_IMM12(abbr)                                \
  __INST_GET_SH_IMM12_IMM(abbr)

#define __INST_SF_RT_FUNCS(abbr, mask, val) \
  __INST_SF_FUNCS(abbr, mask, val)          \
  __INST_GET_RT(abbr)

#define __INST_SIZE_FUNCS(abbr, mask, val) \
  __INST_FUNCS(abbr, mask, val)            \
  __INST_GET_SIZE(abbr)
#define __INST_SIZE_RN_FUNCS(abbr, mask, val) \
  __INST_SIZE_FUNCS(abbr, mask, val)          \
  __INST_GET_RN(abbr)
#define __INST_SIZE_RN_RT_FUNCS(abbr, mask, val) \
  __INST_SIZE_RN_FUNCS(abbr, mask, val)          \
  __INST_GET_RT(abbr)
#define __INST_SIZE_RN_RT_IMM12_FUNCS(abbr, mask, val) \
  __INST_SIZE_RN_RT_FUNCS(abbr, mask, val)             \
  __INST_GET_IMM12(abbr)                               \
  __INST_GET_SIZE_IMM12_IMM(abbr)

#define __INST_SF_RN_RD_N_FUNCS(abbr, mask, val) \
  __INST_SF_RN_RD_FUNCS(abbr, mask, val)         \
  __INST_GET_N(abbr)                             \
  __INST_GET_IMMR(abbr)                          \
  __INST_GET_IMMS(abbr)                          \
  __INST_GET_IMMR_IMMS_IMM(abbr)
#define __INST_RD_IMMLO_IMMHI_FUNCS(abbr, mask, val) \
  __INST_RD_FUNCS(abbr, mask, val)                   \
  __INST_GET_IMMLO(abbr)                             \
  __INST_GET_IMMHI(abbr)                             \
  __INST_GET_LABEL(abbr)

__INST_SF_RN_RD_SH_IMM12_FUNCS(add_imm, 0x7F800000u, 0x11000000u)

__INST_SF_RN_RD_FUNCS(uxtb, 0xFFFFFC00u, 0x53001C00u)

__INST_RD_IMMLO_IMMHI_FUNCS(adrp, 0x9F000000u, 0x90000000u)

__INST_SF_RN_RD_N_FUNCS(and_imm, 0x7F800000u, 0x12000000u)
__INST_SF_RN_RD_N_FUNCS(tst_imm, 0x7F80001Fu, 0x7200001Fu)

__INST_FUNCS(bl, 0xFC000000u, 0x94000000u)
__INST_GET_IMM26(bl)

__INST_SF_RT_FUNCS(cbz, 0x7F000000u, 0x34000000u)
__INST_GET_IMM19(cbz)

__INST_SF_RT_FUNCS(tbnz, 0x7F000000u, 0x37000000u)
__INST_GET_IMM14(tbnz)

__INST_SIZE_RN_RT_IMM12_FUNCS(ldr_imm_uint, 0xBFC00000u, 0xB9400000u)
__INST_SIZE_RN_RT_IMM12_FUNCS(str_imm_uint, 0xBFC00000u, 0xB9000000u)
__INST_SIZE_RN_RT_IMM12_FUNCS(strb_imm_uint, 0xFFC00000u, 0x39000000u)

__INST_SF_RM_RD_FUNCS(mov_reg, 0x7FE0FFE0u, 0x2A0003E0u)

__INST_SF_RM_RN_RD_FUNCS(orr_reg, 0x7F200000u, 0x2A000000u)
__INST_GET_IMM6(orr_reg)

__INST_RN_FUNCS(ret, 0xFFFFFC1Fu, 0xD65F0000u)

// special
__INST_FUNCS(mrs_sp_el0, 0xFFFFFFE0u, 0xD5384100u)

#endif /* _KPM_UTILS_H */
