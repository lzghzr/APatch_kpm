/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/thread_info.h>

// KP 已取得当前线程和 cred 布局；这里只复用已初始化的 SDK 值。
static int nm_prepare_current(void) {
  return task_struct_offset.cred_offset < 0 || cred_offset.fsuid_offset < 0 ? -ENOENT : 0;
}
static u32 nm_current_fsuid(void) { return task_fsuid(current).val; }
static bool nm_current_compat(void) {
  return !!(__atomic_load_n(&current_thread_info()->flags, __ATOMIC_RELAXED) & (1UL << TIF_32BIT));
}
