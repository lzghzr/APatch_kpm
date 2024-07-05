/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __LMKD_DONT_KILL_H
#define __LMKD_DONT_KILL_H

#include <hook.h>
#include <ksyms.h>
#include <linux/cred.h>
#include <linux/sched.h>

#define logkm(fmt, ...) printk("lmkd_dont_kill: " fmt, ##__VA_ARGS__)

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

#endif /* __LMKD_DONT_KILL_H */
