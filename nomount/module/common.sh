#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

NM_BIN="$MODDIR/bin/nm"
NM_DATA="/data/adb/nomount"
NM_LOG="$NM_DATA/nomount.log"
NM_PENDING="$NM_DATA/.booting"

nm_log() {
    printf '%s\n' "$*" >> "$NM_LOG"
}

# 无参数只打印用法并返回 1，不访问 KPM；先区分 ELF/运行库加载失败与驱动查询失败。
nm_check_cli() {
    if NM_CLI_OUTPUT=$("$NM_BIN" 2>&1); then
        NM_CLI_EXIT=0
    else
        NM_CLI_EXIT=$?
    fi
    [ "$NM_CLI_EXIT" -eq 1 ] || return 1
    case "$NM_CLI_OUTPUT" in
        'NoMount CLI (nm) - Usage Guide:'*) return 0 ;;
        *) return 1 ;;
    esac
}

# 首项是线协议号，不是内核版本或 KPM 发布版本；只接受本包验证过的 v22/v23 ABI。
nm_check_api() {
    [ -x "$NM_BIN" ] || return 1
    NM_DRIVER_VERSION=$("$NM_BIN" version 2>/dev/null) || return 1
    [ -n "$NM_DRIVER_VERSION" ] || return 1
    case "${NM_DRIVER_VERSION%% *}" in
        22|23) ;;
        *) printf 'nm: unsupported protocol: %s (supported: 22, 23)\n' "$NM_DRIVER_VERSION" >&2; return 1 ;;
    esac
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

# 查询成功后才输出规则；日志或查询失败只向调用者返回状态。
nm_dump_rules() {
    rules=$("$NM_BIN" rule list 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '%s\n' "$rules" >&2
        return "$rc"
    fi
    log -t nomount -p i "rules dump started ($*)" || return 1
    printf '%s\n' "$rules" | while IFS= read -r line; do
        [ -z "$line" ] || log -t nomount -p i "$line" || exit 1
    done || return 1
    log -t nomount -p i "rules dump end"
}
