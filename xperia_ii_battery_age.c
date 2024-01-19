/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 lzghzr. All Rights Reserved.
 */

#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>

KPM_NAME("xperia_ii_battery_age");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("xperia ii set battery aging level");

#define FG_IMA_DEFAULT 0
#define SOMC_AGING_LEVEL_WORD 291
#define SOMC_AGING_LEVEL_OFFSET 0

struct fg_dev;

int (*fg_sram_read)(struct fg_dev *fg, u16 address, u8 offset, u8 *val, int len, int flags) = 0;
int (*fg_sram_write)(struct fg_dev *fg, u16 address, u8 offset, u8 *val, int len, int flags) = 0;

u8 aging = 0;

void before_read(hook_fargs6_t *args, void *udata)
{
    unhook(fg_sram_read);
    struct fg_dev *fg = (struct fg_dev *)args->arg0;
    // u8 *arg3 = (u8 *)args->arg3;
    // logkd("before read fg: %llu, address: %u, offset: %u, val: %u, len: %d, flags: %d\n", args->arg0, (u16)args->arg1,
    //       (u8)args->arg2, (u8)*arg3, (int)args->arg4, (int)args->arg5);
    int rc = fg_sram_write(fg, SOMC_AGING_LEVEL_WORD, SOMC_AGING_LEVEL_OFFSET, &aging, 1, FG_IMA_DEFAULT);
    if (rc < 0)
        logke("fg_sram_write error, rc=%d\n", rc);
    else
        logki("fg_sram_write success, set batt_aging_level to %u\n", aging);
}

int inline_hook_init(const char *args)
{
    aging = args ? *args - '0' : 0;
    if (aging > 5)
        return -1;

    fg_sram_read = (typeof(fg_sram_read))kallsyms_lookup_name("fg_sram_read");
    pr_info("kernel function fg_sram_read addr: %llx\n", fg_sram_read);

    fg_sram_write = (typeof(fg_sram_write))kallsyms_lookup_name("fg_sram_write");
    pr_info("kernel function fg_sram_write addr: %llx\n", fg_sram_write);

    if (!fg_sram_read || !fg_sram_write)
        return -2;

    hook_err_t err = hook_wrap6(fg_sram_read, before_read, 0, 0);
    if (err)
    {
        pr_err("hook fg_sram_read error: %d\n", err);
        return -3;
    }
    else
    {
        pr_info("hook fg_sram_read success\n");
        return 0;
    }
}

void inline_hook_exit()
{
    if (fg_sram_read)
        unhook(fg_sram_read);
}

KPM_INIT(inline_hook_init);
KPM_EXIT(inline_hook_exit);