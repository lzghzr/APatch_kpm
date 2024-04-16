/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <taskext.h>

#include "../demo.h"

KPM_NAME("hosts_redirect");
KPM_VERSION("1.1.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("redirect /system/etc/hosts to /data/adb/hosts/{n}");

struct open_flags;
struct file *(*do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *op);

char hosts_source[] = "/system/etc/hosts";
char hosts_target[] = "/data/adb/hosts/0";

static long inline_hook_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
  char num = ctl_args ? *ctl_args : '1';
  if (unlikely(num < '0' || num > '9'))
  {
    return -11;
  }
  hosts_target[16] = num;
  return 0;
}

void do_filp_open_before(hook_fargs3_t *args, void *udata)
{
  args->local.data0 = 0;
  if (unlikely(hosts_target[16] == '0'))
  {
    return;
  }
  char **fname = *(char ***)args->arg1;
  if (unlikely(!memcmp(fname, hosts_source, sizeof(hosts_source))))
  {
    struct task_ext *ext = get_current_task_ext();
    args->local.data0 = (uint64_t)ext;
    ext->priv_selinux_allow = true;

    memcpy(fname, hosts_target, sizeof(hosts_target));
  }
}

void do_filp_open_after(hook_fargs3_t *args, void *udata)
{
  if (unlikely(args->local.data0))
  {
    char **fname = *(char ***)args->arg1;
    memcpy(fname, hosts_source, sizeof(hosts_source));

    struct task_ext *ext = (struct task_ext *)args->local.data0;
    ext->priv_selinux_allow = false;
  }
}

static long inline_hook_init(const char *args, const char *event, void *__user reserved)
{
  int rc = inline_hook_control0(args, NULL, NULL);
  if (rc < 0)
  {
    return rc;
  }
  lookup_name(do_filp_open);
  hook_func(do_filp_open, 3, do_filp_open_before, do_filp_open_after, 0);
  return 0;
}

static long inline_hook_exit(void *__user reserved)
{
  unhook_func(do_filp_open);
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
