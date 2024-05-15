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

#include "lmkd_dont_kill.h"

KPM_NAME("lmkd_dont_kill");
KPM_VERSION(LDK_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("lmkd_dont_kill");

#define MIN_SYSTEM_UID 1000
#define MIN_USERAPP_UID 10000

// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);

char lmkd[] = "lmkd";
static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
    int sig = (int)args->arg0;
    struct kernel_siginfo* siginfo = (struct kernel_siginfo*)args->arg1;
    struct task_struct* dst = (struct task_struct*)args->arg2;

    if (sig != SIGKILL || siginfo->si_code != 0)
        return;
    if (task_uid(current).val < MIN_SYSTEM_UID
        || task_uid(dst).val < MIN_USERAPP_UID
        || task_uid(current).val == task_uid(dst).val)
        return;

    const char* comm = get_task_comm(current);
    if (!memcmp(comm, lmkd, sizeof(lmkd) - 1)) {
        args->ret = -EPERM;
        args->skip_origin = true;
    }
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved)
{
    lookup_name(do_send_sig_info);
    hook_func(do_send_sig_info, 4, do_send_sig_info_before, 0, 0);

    return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen)
{
    char msg[64];
    snprintf(msg, sizeof(msg), "_(._.)_");
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long inline_hook_exit(void* __user reserved)
{
    unhook_func(do_send_sig_info);

    return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
