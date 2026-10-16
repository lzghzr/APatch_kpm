/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <kallsyms.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/stddef.h>

#include "../kpm_utils.h"
#include "nm_log.h"
#include "nm_protocol.h"
#include "nm_rules.h"
#include "nm_structs.h"

// 布局获取先于原生封装。
#include "nm_offsets.c"

// 规则数组使用原生 RCU 与分配器。
#include "nm_native.c"

// 原生路径与规则引用。
#include "nm_rules.c"

// 独立编译入口，尚未发布任何 VFS 回调或控制入口。
int nm_prepare_rule_engine(void) {
  int rc = calculate_offsets();
#ifndef CONFIG_KPM_BASELINES
  if (!rc)
    rc = nm_prepare_rule_layout();
#endif
  if (!rc)
    rc = nm_prepare_native();
  return rc ? rc : nm_prepare_rule_functions();
}
