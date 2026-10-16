#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR=${0%/*}
. "$MODDIR/common.sh"
if [ -f "$NM_PENDING" ]; then
    rm -f "$NM_PENDING"
    nm_log "[OK] 系统已完成开机。"
fi
