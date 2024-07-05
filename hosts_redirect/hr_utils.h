/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __HR_UTILS_H
#define __HR_UTILS_H

#include <hook.h>
#include <uapi/asm-generic/errno.h>

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_ADD_64 0x91000000u
#define INST_ADD_64_X0 0x91000000u
#define INST_LDP_64_ 0xA9400000u
#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_X0 0xF9400000u
#define INST_LDR_64_SP 0xF94003E0u
#define INST_LDRB 0x39400000u
#define INST_LDRH 0x79400000u
#define INST_TBZ 0x36000000u
#define INST_TBNZ 0x37000000u
#define INST_TBNZ_5 0x37280000u

#define MASK_ADD_64 0xFF800000u
#define MASK_ADD_64_X0 0xFF8003E0u
#define MASK_LDP_64_ 0xFFC00000u
#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_X0 0xFFC003E0u
#define MASK_LDR_64_SP 0xFFC003E0u
#define MASK_LDRB 0xFFC00000u
#define MASK_LDRH 0xFFC00000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_TBNZ_5 0xFFF80000u

#define ARM64_RET 0xD65F03C0

#define logkm(fmt, ...) printk("hosts_redirect: " fmt, ##__VA_ARGS__)

#define lookup_name(func)                                  \
  func = 0;                                                \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func) {                                             \
    return -21;                                            \
  }

#define hook_func(func, argv, before, after, udata)                         \
  if (!func) {                                                              \
    return -22;                                                             \
  }                                                                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func) {                                                    \
    func = 0;                                                               \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  } else {                                                                  \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)              \
  if (func && !is_bad_address(func)) { \
    unhook(func);                      \
    func = 0;                          \
  }

extern char* kfunc_def(d_path)(const struct path* path, char* buf, int buflen);
static inline char* d_path(const struct path* path, char* buf, int buflen) {
  kfunc_call(d_path, path, buf, buflen);
  kfunc_not_found();
  return NULL;
}

extern int kfunc_def(kern_path)(const char* name, unsigned int flags, struct path* path);
static inline int kern_path(const char* name, unsigned int flags, struct path* path) {
  kfunc_call(kern_path, name, flags, path);
  kfunc_not_found();
  return -ESRCH;
}

#endif /* __HR_UTILS_H */
