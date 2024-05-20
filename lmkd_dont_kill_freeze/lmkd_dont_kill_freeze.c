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

#ifdef DEBUG
#include <uapi/linux/limits.h>
#endif /* DEBUG */

#include "lmkd_dont_kill_freeze.h"

KPM_NAME("lmkd_dont_kill_freeze");
KPM_VERSION(LDKF_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("lmkd_dont_kill_freeze");

#define MIN_SYSTEM_UID 1000
#define MAX_SYSTEM_UID 2000
#define MIN_USERAPP_UID 10000
#define MAX_USERAPP_UID 90000

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// cgroup_freezing
static bool (*cgroup_freezing)(struct task_struct* task);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);
#ifdef DEBUG
static int (*get_cmdline)(struct task_struct* task, char* buffer, int buflen);
#endif /* DEBUG */

static uint64_t task_struct_flags_offset = UZERO, task_struct_jobctl_offset = UZERO, task_struct_frozen_offset = UZERO, task_struct_css_set_offset = UZERO,
css_set_dfl_cgrp_offset = UZERO,
cgroup_flags_offset = UZERO,
task_struct_frozen_bit = UZERO;

static uint64_t last_uid = UZERO;

// 判断线程是否进入 frozen 状态
static inline bool cgroup_task_frozen(struct task_struct* task) {
    if (task_struct_frozen_offset == UZERO) {
        return false;
    }
    unsigned int frozen = *(unsigned int*)((uintptr_t)task + task_struct_frozen_offset);
    return bit(frozen, task_struct_frozen_bit);
}
static inline bool cgroup_task_freeze(struct task_struct* task) {
    bool ret = false;
    if (task_struct_css_set_offset == UZERO || css_set_dfl_cgrp_offset == UZERO || cgroup_flags_offset == UZERO) {
        return false;
    }

    struct css_set* css_set = *(struct css_set**)((uintptr_t)task + task_struct_css_set_offset);
    struct cgroup* cgrp = *(struct cgroup**)((uintptr_t)css_set + css_set_dfl_cgrp_offset);
    unsigned long cgrp_flags = *(unsigned long*)((uintptr_t)cgrp + cgroup_flags_offset);
    ret = bit(cgrp_flags, CGRP_FREEZE);
    return ret;
}
static inline bool frozen(struct task_struct* p) {
    unsigned int flags = *(unsigned int*)((uintptr_t)p + task_struct_flags_offset);
    return (flags & PF_FROZEN);
}
static inline bool frozen_task_group(struct task_struct* task) {
    return (cgroup_task_frozen(task) || cgroup_task_freeze(task) || frozen(task) || cgroup_freezing(task));
}

char lmkd[] = "lmkd";
static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
    int sig = (int)args->arg0;
    struct kernel_siginfo* siginfo = (struct kernel_siginfo*)args->arg1;
    struct task_struct* dst = (struct task_struct*)args->arg2;

#ifdef DEBUG
    if (sig == SIGKILL
        && task_uid(dst).val >= MIN_USERAPP_UID) {
        char cmdline[PATH_MAX];
        memset(&cmdline, 0, PATH_MAX);
        int res = get_cmdline(current, cmdline, PATH_MAX - 1);
        cmdline[res] = '\0';
        printk("dont_kill_freeze: killer=%d,dst=%d,cmdline=%s,comm=%s\n", task_uid(current).val, task_uid(dst).val, cmdline, get_task_comm(current));
    }
#endif /* DEBUG */
    if (sig != SIGKILL || siginfo->si_code != 0)
        return;
    if (task_uid(dst).val < MIN_USERAPP_UID || task_uid(dst).val > MAX_USERAPP_UID)
        return;
    last_uid = task_uid(dst).val;

    const char* comm = get_task_comm(current);
    if (!memcmp(comm, lmkd, sizeof(lmkd) - 1)
        && frozen_task_group(dst)) {
        args->ret = -EPERM;
        args->skip_origin = true;
#ifdef DEBUG
        printk("dont_kill_freeze: skip\n");
#endif /* DEBUG */
    }
}

static long calculate_offsets() {
    // 获取 cgroup 相关偏移，没有就是不支持 CGRP_FREEZE
    // cgroup_exit_count = 1; task->css_set
    // cgroup_exit_count = 2; css_set->dfl_cgrp
    // cgroup_exit_count = 3; cgroup->flags
    void (*cgroup_exit)(struct task_struct* task);
    lookup_name(cgroup_exit);

    bool cgroup_exit_start = false;
    u32 cgroup_exit_count = 0;
    uint32_t* cgroup_exit_src = (uint32_t*)cgroup_exit;
    for (u32 i = 0; i < 0x50; i++) {
#ifdef DEBUG
        printk("dont_kill_freeze: cgroup_exit %x %llx\n", i, cgroup_exit_src[i]);
#endif /* DEBUG */
        if (cgroup_exit_src[i] == ARM64_RET) {
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 2 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            cgroup_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 1 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            css_set_dfl_cgrp_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 2;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            task_struct_css_set_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 1;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_ADD_64) == INST_ADD_64) {
            uint32_t sh = bit(cgroup_exit_src[i], 22);
            uint64_t imm12 = imm12 = bits32(cgroup_exit_src[i], 21, 10);
            if (sh) {
                task_struct_css_set_offset = sign64_extend((imm12 << 12u), 16u);
            } else {
                task_struct_css_set_offset = sign64_extend((imm12), 16u);
            }
            cgroup_exit_count = 1;
        } else if ((cgroup_exit_src[i] & MASK_TBNZ) == INST_TBNZ) {
            cgroup_exit_start = true;
        }
    }
    // 获取 task_struct->frozen, task_struct->jobctl, 没有就是不支持 PF_FROZEN
    void (*recalc_sigpending_and_wake)(struct task_struct* t);
    lookup_name(recalc_sigpending_and_wake);

    uint32_t* recalc_sigpending_and_wake_src = (uint32_t*)recalc_sigpending_and_wake;
    for (u32 i = 0; i < 0x20; i++) {
#ifdef DEBUG
        printk("dont_kill_freeze: recalc_sigpending_and_wake %x %llx\n", i, recalc_sigpending_and_wake_src[i]);
#endif /* DEBUG */
        if (recalc_sigpending_and_wake_src[i] == ARM64_RET) {
            break;
        } else if ((recalc_sigpending_and_wake_src[i] & MASK_TBZ) == INST_TBZ || (recalc_sigpending_and_wake_src[i] & MASK_TBNZ) == INST_TBNZ) {
            if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRB) == INST_LDRB) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12), 16u);
                break;
            } else if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRH) == INST_LDRH) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12 << 1u), 16u);
                break;
            }
        } else if ((recalc_sigpending_and_wake_src[i] & MASK_LDRB_X0) == INST_LDRB_X0) {
            uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i], 21, 10);
            task_struct_jobctl_offset = sign64_extend((imm12), 16u) - 0x2;
        }
    }
    // 获取 task_struct->flags
    bool (*freezing_slow_path)(struct task_struct* p);
    lookup_name(freezing_slow_path);

    uint32_t* freezing_slow_path_src = (uint32_t*)freezing_slow_path;
    for (u32 i = 0; i < 0x20; i++) {
#ifdef DEBUG
        printk("dont_kill_freeze: freezing_slow_path %x %llx\n", i, freezing_slow_path_src[i]);
#endif /* DEBUG */
        if (freezing_slow_path_src[i] == ARM64_RET) {
            break;
        } else if ((freezing_slow_path_src[i] & MASK_LDR_32_X0) == INST_LDR_32_X0) {
            uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
            task_struct_flags_offset = sign64_extend((imm12 << 0b10u), 16u);
            break;
        } else if ((freezing_slow_path_src[i] & MASK_LDR_64_X0) == INST_LDR_64_X0) {
            uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
            task_struct_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        }
    }
    if (task_struct_flags_offset == UZERO) {
        return -11;
    }

    return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
    lookup_name(cgroup_freezing);
    lookup_name(do_send_sig_info);
#ifdef DEBUG
    lookup_name(get_cmdline);
#endif /* DEBUG */

    int rc = calculate_offsets();
    if (rc < 0) {
        return rc;
    }

    hook_func(do_send_sig_info, 4, do_send_sig_info_before, NULL, NULL);

    return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
    char msg[64];
    snprintf(msg, sizeof(msg), "_(._.)_");
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
