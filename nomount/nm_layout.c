/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <kallsyms.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/stddef.h>

#include "../kpm_utils.h"
#include "nm_log.h"
#include "nm_structs.h"

// 偏移实现依赖上面的共同结构定义。
#include "nm_offsets.c"

// 布局获取层供后续 KPM 入口调用；成功不表示 VFS 操作表已安装。
int nm_prepare_layout(void) { return calculate_offsets(); }
