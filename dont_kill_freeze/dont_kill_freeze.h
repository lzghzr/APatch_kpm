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

#include "../kpm_utils.h"

#define logkm(fmt, ...) printk("dont_kill_freeze: " fmt, ##__VA_ARGS__)

#define task_real_uid(task)                                                                       \
  ({                                                                                              \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                        \
    ___val;                                                                                       \
  })

#undef task_uid
#define task_uid(task) task_real_uid(task)
// linux/sched/jobctl.h
#define JOBCTL_TRAP_FREEZE_BIT 23
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)

// uapi/asm/signal.h
#define SIGKILL 9
struct siginfo;

// linux/signal_types.h
#define __SIGINFO \
  struct {        \
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
