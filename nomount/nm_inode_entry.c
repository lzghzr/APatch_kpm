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

// 布局和访问器。
#include "nm_offsets.c"

// 原生接口。
#include "nm_native.c"

// 规则引用。
#include "nm_rules.c"

// 完整操作表。
#include "nm_operations.c"

// 文件回调。
#include "nm_file.c"

// 新inode的原生安全上下文。
#include "nm_security.c"

// inode 物化与原生回收。
#include "nm_inode.c"

int nm_prepare_materialization(void) {
  int rc = calculate_offsets();

#ifndef CONFIG_KPM_BASELINES
  if (!rc) {
    rc = nm_prepare_rule_layout();
    if (rc)
      nm_log_error("layout: rule prefixes failed (%d)\n", rc);
  }
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
  return rc ? rc : nm_prepare_inode_engine();
}

// 尚未由 KPM 入口发布；单独入口使物化、回收及原生表复制都进入 ARM64 编译对象。
int nm_prepare_parent_superblock(struct inode* parent) { return nm_install_super_proxy(nm_inode_superblock(parent)); }
struct dentry* nm_materialize_regular_file(struct inode* parent, struct dentry* dentry, struct nomount_rule* rule,
                                           u64 number) {
  return nm_materialize_file(parent, dentry, rule, number);
}
