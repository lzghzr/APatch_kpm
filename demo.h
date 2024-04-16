/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <hook.h>

#define lookup_name(func)                                    \
  func = 0;                                                  \
  func = (typeof(func))kallsyms_lookup_name(#func);          \
  if (func)                                                  \
  {                                                          \
    pr_info("kernel function %s addr: %llx\n", #func, func); \
  }                                                          \
  else                                                       \
  {                                                          \
    pr_err("kernel function %s addr: %llx\n", #func, func);  \
    return -21;                                              \
  }

#define hook_func(func, argv, before, after, udata)                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func)                                                      \
  {                                                                         \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -22;                                                             \
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
  }\
