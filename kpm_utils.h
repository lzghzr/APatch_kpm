/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef _KPM_UTILS_H
#define _KPM_UTILS_H

#include <hook.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

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

// BTF
// BTF UAPI 的共同记录；查询与类型尺寸解析交给内核。
struct btf;
#ifndef _KPM_BTF_TYPES
#define _KPM_BTF_TYPES
struct btf_type {
  u32 name_off, info, size;
};
struct btf_member {
  u32 name_off, type, offset;
};
#endif
struct btf_param {
  u32 name_off, type;
};
struct btf_enum {
  u32 name_off;
  int value;
};

struct kpm_btf {
  const struct btf* data;
  int (*find_by_name_kind)(const struct btf* btf, const char* name, u8 kind);
  const struct btf_type* (*type_by_id)(const struct btf* btf, u32 id);
  const char* (*name_by_offset)(const struct btf* btf, u32 offset);
  const struct btf_type* (*resolve_size)(const struct btf* btf, const struct btf_type* type, u32* size);
};

struct kpm_btf_field {
  const struct btf_type* type;
  u32 offset, bits, size;
};

static inline const struct btf_type* kpm_btf_type(const struct kpm_btf* btf, const char* name, u8 kind) {
  int id = btf->find_by_name_kind(btf->data, name, kind);
  return id > 0 ? btf->type_by_id(btf->data, id) : NULL;
}

// 按名字遍历嵌套成员与匿名 struct/union；offset 和 bits 的单位为 bit。
static inline int kpm_btf_member(const struct kpm_btf* btf, const struct btf_type* type, const char* path,
                                 struct kpm_btf_field* field, unsigned int depth) {
  if (!type || depth == 32 || (((type->info >> 24) & 31) != 4 && ((type->info >> 24) & 31) != 5))
    return -EINVAL;
  unsigned int len = 0;
  while (path[len] && path[len] != '.') len++;
  const struct btf_member* members = (const struct btf_member*)(type + 1);
  for (u32 i = 0; i < (type->info & 0xffff); i++) {
    const char* name = btf->name_by_offset(btf->data, members[i].name_off);
    if (!name || (*name && (strncmp(name, path, len) || name[len])))
      continue;
    const struct btf_type* member = btf->type_by_id(btf->data, members[i].type);
    if (!member)
      return -EINVAL;
    u32 size = 0;
    member = btf->resolve_size(btf->data, member, &size);
    if (IS_ERR(member) || !member)
      return -EINVAL;
    u32 offset = members[i].offset;
    u32 bits = type->info >> 31 ? offset >> 24 : 0;
    if (type->info >> 31)
      offset &= 0xffffff;
    if ((u64)offset + (bits ? bits : (u64)size * 8) > (u64)type->size * 8)
      return -EINVAL;
    if (!*name || path[len] == '.') {
      if (bits)
        return -EINVAL;
      int rc = kpm_btf_member(btf, member, *name ? path + len + 1 : path, field, depth + 1);
      if (rc == -ENOENT && !*name)
        continue;
      if (rc)
        return rc;
      field->offset += offset;
    } else {
      *field = (struct kpm_btf_field){member, offset, bits, size};
    }
    return 0;
  }
  return -ENOENT;
}

static inline int kpm_btf_offset(const struct kpm_btf* btf, const struct btf_type* type, const char* name,
                                 unsigned int width) {
  struct kpm_btf_field field;
  int rc = kpm_btf_member(btf, type, name, &field, 0);
  if (rc)
    return rc;
  if (field.bits || field.offset % 8 || (width && field.size != width))
    return -EINVAL;
  return field.offset / 8;
}

static inline int kpm_btf_enum(const struct kpm_btf* btf, const struct btf_type* type, const char* name) {
  if (!type || ((type->info >> 24) & 31) != 6)
    return -EINVAL;
  const struct btf_enum* values = (const struct btf_enum*)(type + 1);
  for (u32 i = 0; i < (type->info & 0xffff); i++) {
    const char* member = btf->name_by_offset(btf->data, values[i].name_off);
    if (member && !strcmp(member, name))
      return values[i].value;
  }
  return -ENOENT;
}

// instruction
#define bits32(n, high, low) (((uint32_t)(n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
  ((((uint64_t)(n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
// https://github.com/llvm/llvm-project/blob/f280d3b705de7f94ef9756e3ef2842b415a7c038/llvm/lib/Target/AArch64/MCTargetDesc/AArch64AddressingModes.h#L293
#define ror(elt, size) (((elt) & 1) << ((size) - 1)) | ((elt) >> 1)

#define __INST_GET_IMM3(abbr) \
  static inline int inst_get_##abbr##_imm3(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 12, 10) : -1; }
#define __INST_GET_IMM6(abbr) \
  static inline int inst_get_##abbr##_imm6(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 15, 10) : -1; }

#define __INST_GET_IMM9(abbr)                                                       \
  static inline int inst_get_##abbr##_imm9(uint32_t code) {                         \
    return inst_is_##abbr(code) ? (int32_t)(bits32(code, 20, 12) << 23) >> 23 : -1; \
  }

#define __INST_GET_IMM12(abbr) \
  static inline int inst_get_##abbr##_imm12(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 21, 10) : -1; }
#define __INST_GET_SIZE_IMM12_IMM(abbr)                     \
  static inline long inst_get_##abbr##_imm(uint32_t code) { \
    if (!inst_is_##abbr(code))                              \
      return -1;                                            \
    int size = inst_get_##abbr##_size(code);                \
    int imm12 = inst_get_##abbr##_imm12(code);              \
    return (uint64_t)imm12 << size;                         \
  }
#define __INST_GET_SH_IMM12_IMM(abbr)                       \
  static inline long inst_get_##abbr##_imm(uint32_t code) { \
    if (!inst_is_##abbr(code))                              \
      return -1;                                            \
    int sh = inst_get_##abbr##_sh(code);                    \
    int imm12 = inst_get_##abbr##_imm12(code);              \
    return (uint64_t)imm12 << (sh ? 12u : 0u);              \
  }

#define __INST_GET_IMM14(abbr) \
  static inline int inst_get_##abbr##_imm14(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 18, 5) : -1; }
#define __INST_GET_IMM16(abbr) \
  static inline int inst_get_##abbr##_imm16(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 20, 5) : -1; }
#define __INST_GET_IMM19(abbr) \
  static inline int inst_get_##abbr##_imm19(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 23, 5) : -1; }
#define __INST_GET_IMM26(abbr) \
  static inline int inst_get_##abbr##_imm26(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 25, 0) : -1; }

#define __INST_GET_IMM26_LABEL(abbr)                                                                          \
  static inline long inst_get_##abbr##_label(uint32_t code) {                                                 \
    return inst_is_##abbr(code) ? (int64_t)(int32_t)((uint32_t)inst_get_##abbr##_imm26(code) << 6) >> 4 : -1; \
  }

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
    int encoded = (N << 6) | (~imms & 0x3f);                  \
    if (!encoded)                                             \
      return -11;                                             \
    int len = 31 - __builtin_clz(encoded);                    \
    int size = (1 << len);                                    \
    int R = immr & (size - 1);                                \
    int S = imms & (size - 1);                                \
    if (S == size - 1)                                        \
      return -12;                                             \
    uint64_t pattern = (1ULL << (S + 1)) - 1;                 \
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
    uint64_t immlo = inst_get_##abbr##_immlo(code);             \
    uint64_t immhi = inst_get_##abbr##_immhi(code);             \
    return sign64_extend((immhi << 14u) | (immlo << 12u), 33u); \
  }

#define __INST_GET_SF(abbr) \
  static inline int inst_get_##abbr##_sf(uint32_t code) { return inst_is_##abbr(code) ? bit(code, 31) : -1; }
#define __INST_GET_SIZE(abbr) \
  static inline int inst_get_##abbr##_size(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 31, 30) : -1; }
#define __INST_GET_OPC(abbr) \
  static inline int inst_get_##abbr##_opc(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 23, 22) : -1; }
#define __INST_GET_SH(abbr) \
  static inline int inst_get_##abbr##_sh(uint32_t code) { return inst_is_##abbr(code) ? bit(code, 22) : -1; }
#define __INST_GET_OPTION(abbr) \
  static inline int inst_get_##abbr##_option(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 15, 13) : -1; }
#define __INST_GET_SHIFT(abbr) \
  static inline int inst_get_##abbr##_shift(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 23, 22) : -1; }
#define __INST_GET_MODE(abbr) \
  static inline int inst_get_##abbr##_mode(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 11, 10) : -1; }
#define __INST_GET_HW(abbr) \
  static inline int inst_get_##abbr##_hw(uint32_t code) { return inst_is_##abbr(code) ? bits32(code, 22, 21) : -1; }
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

// 立即数读取含 LDR、LDRSB/LDRSH/LDRSW 及 LDUR/LDTR 编码；预取与保留编码单独排除。
#define __INST_LDR_FUNCS(abbr, mask, val)                                                           \
  static inline bool inst_is_##abbr(uint32_t code) {                                                \
    if ((code & (mask)) != ((val) & (mask)))                                                        \
      return false;                                                                                 \
    int size = bits32(code, 31, 30), opc = bits32(code, 23, 22);                                    \
    if (bit(code, 26))                                                                              \
      return (bit(code, 24) || bits32(code, 11, 10) != 2) && (opc == 1 || (opc == 3 && size == 0)); \
    return opc == 1 || (opc == 2 && size < 3) || (opc == 3 && size < 2);                            \
  }                                                                                                 \
  static inline uint32_t inst_get_##abbr##_value(void) { return (val); }
#define __INST_STR_FUNCS(abbr, mask, val)                                                           \
  static inline bool inst_is_##abbr(uint32_t code) {                                                \
    if ((code & (mask)) != ((val) & (mask)))                                                        \
      return false;                                                                                 \
    int size = bits32(code, 31, 30), opc = bits32(code, 23, 22);                                    \
    if (bit(code, 26))                                                                              \
      return (bit(code, 24) || bits32(code, 11, 10) != 2) && (opc == 0 || (opc == 2 && size == 0)); \
    return opc == 0;                                                                                \
  }                                                                                                 \
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
#define __INST_SIZE_RN_RT_LDR_FUNCS(abbr, mask, val) \
  __INST_LDR_FUNCS(abbr, mask, val)                  \
  __INST_GET_SIZE(abbr)                              \
  __INST_GET_RN(abbr)                                \
  __INST_GET_RT(abbr)                                \
  __INST_GET_OPC(abbr)
#define __INST_SIZE_RN_RT_STR_FUNCS(abbr, mask, val) \
  __INST_STR_FUNCS(abbr, mask, val)                  \
  __INST_GET_SIZE(abbr)                              \
  __INST_GET_RN(abbr)                                \
  __INST_GET_RT(abbr)                                \
  __INST_GET_OPC(abbr)
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
__INST_SF_RM_RN_RD_FUNCS(add_ext, 0x7FE00000u, 0x0B200000u)
__INST_GET_OPTION(add_ext)
__INST_GET_IMM3(add_ext)
__INST_SF_RM_RN_RD_FUNCS(add_reg, 0x7F200000u, 0x0B000000u)
__INST_GET_SHIFT(add_reg)
__INST_GET_IMM6(add_reg)

__INST_SF_RN_RD_FUNCS(uxtb, 0xFFFFFC00u, 0x53001C00u)

__INST_RD_IMMLO_IMMHI_FUNCS(adrp, 0x9F000000u, 0x90000000u)

__INST_SF_RN_RD_N_FUNCS(and_imm, 0x7F800000u, 0x12000000u)
__INST_SF_RN_RD_N_FUNCS(orr_imm, 0x7F800000u, 0x32000000u)
__INST_SF_RN_RD_N_FUNCS(tst_imm, 0x7F80001Fu, 0x7200001Fu)

__INST_FUNCS(b, 0xFC000000u, 0x14000000u)
__INST_GET_IMM26(b)
__INST_GET_IMM26_LABEL(b)

__INST_FUNCS(bl, 0xFC000000u, 0x94000000u)
__INST_GET_IMM26(bl)
__INST_GET_IMM26_LABEL(bl)
__INST_RN_FUNCS(blr, 0xFFFFFC1Fu, 0xD63F0000u)

__INST_SF_RT_FUNCS(cbz, 0x7F000000u, 0x34000000u)
__INST_GET_IMM19(cbz)
__INST_SF_RT_FUNCS(cbnz, 0x7F000000u, 0x35000000u)
__INST_GET_IMM19(cbnz)

__INST_SF_RT_FUNCS(tbnz, 0x7F000000u, 0x37000000u)
__INST_GET_IMM14(tbnz)

__INST_SIZE_RN_RT_LDR_FUNCS(ldr_imm, 0x3B000000u, 0x39400000u)
__INST_GET_IMM12(ldr_imm)
__INST_SIZE_RN_RT_LDR_FUNCS(ldr_imm9, 0x3B200000u, 0x38400000u)
__INST_GET_IMM9(ldr_imm9)
__INST_GET_MODE(ldr_imm9)
__INST_SIZE_RN_RT_IMM12_FUNCS(ldr_imm_uint, 0xBFC00000u, 0xB9400000u)
__INST_SIZE_RN_RT_IMM12_FUNCS(ldrb_imm_uint, 0xFFC00000u, 0x39400000u)
__INST_SIZE_RN_RT_IMM12_FUNCS(ldrh_imm_uint, 0xFFC00000u, 0x79400000u)

__INST_SIZE_RN_RT_STR_FUNCS(str_imm, 0x3B000000u, 0x39000000u)
__INST_GET_IMM12(str_imm)
__INST_SIZE_RN_RT_STR_FUNCS(str_imm9, 0x3B200000u, 0x38000000u)
__INST_GET_IMM9(str_imm9)
__INST_GET_MODE(str_imm9)
__INST_SIZE_RN_RT_IMM12_FUNCS(str_imm_uint, 0xBFC00000u, 0xB9000000u)
__INST_SIZE_RN_RT_IMM12_FUNCS(strb_imm_uint, 0xFFC00000u, 0x39000000u)

__INST_RN_FUNCS(stp_imm, 0x7FC00000u, 0x29000000u)

__INST_SF_RM_RD_FUNCS(mov_reg, 0x7FE0FFE0u, 0x2A0003E0u)
__INST_SF_FUNCS(movz_imm, 0x7F800000u, 0x52800000u)
__INST_GET_RD(movz_imm)
__INST_GET_IMM16(movz_imm)
__INST_GET_HW(movz_imm)

__INST_SF_RM_RN_RD_FUNCS(orr_reg, 0x7F200000u, 0x2A000000u)
__INST_GET_IMM6(orr_reg)

__INST_RN_FUNCS(ret, 0xFFFFFC1Fu, 0xD65F0000u)

// special
__INST_FUNCS(mrs_sp_el0, 0xFFFFFFE0u, 0xD5384100u)

#endif /* _KPM_UTILS_H */
