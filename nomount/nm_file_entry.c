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

// 布局和访问器先定义。
#include "nm_offsets.c"

// 内存、RCU 与原生目录接口。
#include "nm_native.c"

// 规则和路径引用。
#include "nm_rules.c"

// 完整操作表分配。
#include "nm_operations.c"

// 文件回调。
#include "nm_file.c"

// 返回发布前的完整表，调用者负责将其绑定到物化后的 inode。
int nm_prepare_file_engine(void** operations) {
  *operations = NULL;
  int rc = calculate_offsets();
#ifndef CONFIG_KPM_BASELINES
  if (!rc)
    rc = nm_prepare_rule_layout();
#endif
  if (!rc)
    rc = nm_prepare_file_layout();
  if (!rc)
    rc = nm_prepare_operation_sizes();
  if (!rc)
    rc = nm_prepare_native();
  if (!rc)
    rc = nm_prepare_rule_functions();
  if (!rc)
    rc = nm_prepare_file_functions();
  if (rc)
    return rc;
  void* table = nm_new_file_operations();
  if (IS_ERR(table))
    return PTR_ERR(table);
  *operations = table;
  return 0;
}
