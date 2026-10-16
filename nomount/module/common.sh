#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

NM_BIN="$MODDIR/bin/nm"
NM_DATA="/data/adb/nomount"
NM_LOG="$NM_DATA/nomount.log"
NM_PENDING="$NM_DATA/.booting"

nm_log() {
    printf '%s\n' "$*" >> "$NM_LOG"
}

# 查询控制协议；不根据内核版本或驱动版本字符串决定兼容性。
nm_check_api() {
    [ -x "$NM_BIN" ] || return 1
    NM_DRIVER_VERSION=$("$NM_BIN" version 2>/dev/null) || return 1
    [ -n "$NM_DRIVER_VERSION" ] || return 1
    isolated_state=$("$NM_BIN" uid block_isolated 2>/dev/null) || return 1
    case "$isolated_state" in 0|1) return 0 ;; *) return 1 ;; esac
}

nm_restore_exclusions() {
    "$NM_BIN" uid clear >> "$NM_LOG" 2>&1 || return 1
    if [ -f "$NM_DATA/.exclusion_list.json" ]; then
        # WebUI保存UID字符串；允许JSON中的空白，逐个验证十进制UID。
        uids=$(grep -oE '"uid"[[:space:]]*:[[:space:]]*"[0-9]+"' "$NM_DATA/.exclusion_list.json" | tr -cd '0-9\n')
        for uid in $uids; do
            "$NM_BIN" uid add "$uid" >> "$NM_LOG" 2>&1 || return 1
        done
    fi
    if [ -f "$NM_DATA/.block_isolated_uids" ]; then
        "$NM_BIN" uid block_isolated on >> "$NM_LOG" 2>&1
    else
        "$NM_BIN" uid block_isolated off >> "$NM_LOG" 2>&1
    fi
}

nm_clear_rules() {
    "$NM_BIN" rule clear >> "$NM_LOG" 2>&1
}
