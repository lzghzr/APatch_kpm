/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "../kpm_utils.h"
#include "hr_utils.h"

KPM_NAME("hosts_redirect");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("redirect /system/etc/hosts to /data/adb/hosts/{name}");

struct open_flags;
struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);

char hosts_source[] = "/system/etc/hosts";
char hosts_target[64] = "/data/adb/hosts/hosts";

static bool set_hosts(const char* name) {
  if (!name) {
    logkm("target rejected: NULL name; rule unchanged\n");
    return false;
  }
  size_t len = strlen(name);
  if (!len || len > 40) {
    logkm("target rejected: length=%zu, expected 1..40; rule unchanged\n", len);
    return false;
  }
  if (len == 1 && name[0] == '.') {
    logkm("target rejected: dot name; rule unchanged\n");
    return false;
  }
  bool blank = true;
  for (size_t i = 0; i < len; i++) {
    if (name[i] == '/' || (name[i] == '.' && name[i + 1] == '.')) {
      logkm("target rejected: slash or dot-dot at byte %zu; rule unchanged\n", i);
      return false;
    }
    if (name[i] != ' ' && name[i] != '\t' && name[i] != '\n' && name[i] != '\r' && name[i] != '\v' && name[i] != '\f')
      blank = false;
  }
  if (blank) {
    logkm("target rejected: whitespace-only name; rule unchanged\n");
    return false;
  }
  // Validate the complete component before the first write to the current rule.
  for (size_t i = 0; i <= len; i++) hosts_target[16 + i] = name[i];
  logkm("hosts_target=%s\n", hosts_target);
  return true;
}

static void do_filp_open_before(hook_fargs3_t* args, void* udata) {
  args->local.data0 = 0;
  if (current_uid() != 0)
    return;
  if (unlikely(!strcmp(hosts_target, "/data/adb/hosts/disable")))
    return;

  struct filename* pathname = (struct filename*)args->arg1;

  if (unlikely(!strcmp(pathname->name, hosts_source))) {
    args->local.data0 = (uint64_t)pathname->name;
    pathname->name = hosts_target;
  }
}

static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  if (unlikely(args->local.data0)) {
    struct filename* pathname = (struct filename*)args->arg1;
    pathname->name = (char*)args->local.data0;
  }
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  bool success = set_hosts(ctl_args);

  const char* msg = success ? "_(._.)_\n" : "_(x_x)_\n";
  const int msg_len = sizeof("_(._.)_\n");
  if (out_msg && outlen >= msg_len)
    compat_copy_to_user(out_msg, msg, msg_len);
  return 0;
}

static long install_open_hook(void) {
  hook_func(do_filp_open, 3, do_filp_open_before, do_filp_open_after, 0);
  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  int rc = inline_hook_control0(args, NULL, NULL);
  if (rc < 0) {
    return rc;
  }

  lookup_name(do_filp_open);
  rc = install_open_hook();
  if (rc < 0) {
    do_filp_open = 0;
    return rc;
  }
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  if (do_filp_open && !is_bad_address(do_filp_open)) {
    unhook_func(do_filp_open);
    do_filp_open = 0;
  }
  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
