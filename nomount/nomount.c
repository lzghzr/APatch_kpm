/* SPDX-License-Identifier: GPL-2.0-only */
/* NoMount by maxsteeel; KPM adaptation by Codex (OpenAI), modified 2026-10-13. */
#include <kpmodule.h>

// 完整引擎、原生管理锁与keyring注册按依赖顺序准备。
#include "nm_control_entry.c"

#ifndef MYKPM_VERSION
#define MYKPM_VERSION NM_KPM_VERSION
#endif

KPM_NAME("NoMount");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("maxsteeel, Codex");
KPM_DESCRIPTION("NoMount: read-only file and directory views, resident until reboot");

#ifdef CONFIG_KPM_BASELINES
#define NM_OFFSET_MODE "static"
#else
#define NM_OFFSET_MODE "dynamic"
#endif
KPM_INFO(offset_mode, NM_OFFSET_MODE, 32);
KPM_INFO(lifetime, "reboot", 32);

static bool nm_initialized;

static long nomount_init(const char* args, const char* event, void* reserved) {
  if (args && *args)
    return -EINVAL;
  int rc = nm_prepare_control_engine();
  if (rc) {
    nm_log_error("initialization failed: %d\n", rc);
    return rc;
  }
  // 原生已能调用keyring表；注册后不再执行可能失败的初始化步骤。
  nm_initialized = true;
  nm_log_info("ready, version=%s, offsets=%s; resident until reboot, do not unload\n", NM_KPM_VERSION, NM_OFFSET_MODE);
  return 0;
}

static long nomount_ctl0(const char* args, char __user* out_msg, int outlen) {
  if (!nm_initialized)
    return -ENODEV;
  if (args && *args && strcmp(args, "status"))
    return -EINVAL;
  static const char reply[] = "NoMount " NM_KPM_VERSION "; offsets=" NM_OFFSET_MODE "; lifetime=reboot";
  if (!out_msg || outlen < (int)sizeof(reply))
    return -EINVAL;
  return compat_copy_to_user(out_msg, reply, sizeof(reply)) == sizeof(reply) ? 0 : -EFAULT;
}

static long nomount_exit(void* reserved) {
  if (nm_initialized)
    nm_log_error("do not unload; native keyring and VFS may retain callbacks\n");
  return 0;
}

KPM_INIT(nomount_init);
KPM_CTL0(nomount_ctl0);
KPM_EXIT(nomount_exit);
