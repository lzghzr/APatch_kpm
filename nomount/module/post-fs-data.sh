#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR=${0%/*}
. "$MODDIR/common.sh"
mkdir -p "$NM_DATA" || exit 1
if ! nm_check_api; then
    nm_log "[ERROR] NoMount 接口未就绪，文件加载不可用。"
    exit 1
fi
nm_log "[INFO] NoMount 接口可用，驱动版本：$NM_DRIVER_VERSION"
