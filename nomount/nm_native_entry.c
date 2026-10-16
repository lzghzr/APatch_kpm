/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <kallsyms.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/stddef.h>

#include "../kpm_utils.h"
#include "nm_log.h"
#include "nm_protocol.h"
#include "nm_structs.h"

// 先定义布局访问器。
#include "nm_offsets.c"

// 原生封装依赖上面的访问器和协议。
#include "nm_native.c"

// 操作表分配使用已解析的原生接口。
#include "nm_operations.c"

// 编译入口；调用方在两层准备成功后才可发布回调。
int nm_prepare_platform(void) {
  int rc = calculate_offsets();
  if (!rc)
    rc = nm_prepare_operation_sizes();
  return rc ? rc : nm_prepare_native();
}
