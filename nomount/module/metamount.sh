#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR=${0%/*}
. "$MODDIR/common.sh"
MODULES_DIR="${MODULE_DIR:-/data/adb/modules}"
MODULES_DIR="${MODULES_DIR%/}"

mkdir -p "$NM_DATA" || exit 1
nm_log "=== NoMount 文件加载：$(date) ==="
if ! nm_check_api; then
    nm_log "[ERROR] 无法连接 NoMount，请检查嵌入的 KPM 并重启。已跳过文件加载。"
    exit 1
fi
if [ -f "$NM_DATA/disable" ] || [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
    nm_clear_rules || exit 1
    rm -f "$NM_PENDING"
    nm_log "[INFO] 文件加载已停用。"
    exit 0
fi

boot_id=$(cat /proc/sys/kernel/random/boot_id) || exit 1
[ -n "$boot_id" ] || exit 1
if [ -f "$NM_PENDING" ] && [ "$(cat "$NM_PENDING")" != "$boot_id" ]; then
    nm_clear_rules || exit 1
    touch "$NM_DATA/disable"
    rm -f "$NM_PENDING"
    nm_log "[WARN] 上次加载后未收到开机完成回执，已暂停文件加载。"
    exit 1
fi
printf '%s\n' "$boot_id" > "$NM_PENDING" || exit 1
abort_injection() {
    nm_log "[ERROR] 文件加载准备失败，未继续发布规则。"
    rm -f "$NM_PENDING"
    exit 1
}
# 元模块挂载先于普通post-fs-data，UID屏蔽必须先于规则发布。
nm_clear_rules || abort_injection
nm_restore_exclusions || abort_injection

status=0

for mod_path in "$MODULES_DIR"/*; do
    [ -d "$mod_path" ] || continue
    [ "${mod_path##*/}" = nomount ] && continue
    if [ -f "$mod_path/disable" ] || [ -f "$mod_path/remove" ] || [ -f "$mod_path/skip_mount" ]; then
        continue
    fi
    nm_log "[INFO] 加载 ${mod_path##*/}"
    "$NM_BIN" module load "$mod_path" >> "$NM_LOG" 2>&1 || status=1
done
if [ "$status" -eq 0 ]; then
    nm_log "[OK] 文件加载完成，等待系统开机完成。"
else
    nm_log "[ERROR] 文件加载部分失败，已保留成功规则，等待系统开机完成。"
fi
# 列表仅用于诊断，不改变已经发布的规则；开机回执仍负责删除 pending。
"$NM_BIN" rule list >> "$NM_LOG" 2>&1 || nm_log "[WARN] 无法记录规则列表。"
if [ -f "$NM_DATA/dump_rules" ]; then
    nm_dump_rules boot || nm_log "[WARN] 无法将规则列表写入 logcat。"
fi
exit "$status"
