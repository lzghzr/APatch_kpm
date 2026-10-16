#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR=${0%/*}
. "$MODDIR/common.sh"
MODULES_DIR="${MODULE_DIR:-/data/adb/modules}"
MODULES_DIR="${MODULES_DIR%/}"
TARGET_PARTITIONS="system system_ext vendor odm product apex oem optics prism
    mi_ext my_bigball my_carrier my_company my_engineering my_heytap
    my_manifest my_preload my_product my_region my_reserve my_stock"

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
fail_injection() {
    nm_log "[ERROR] 文件加载失败，正在撤销本次规则。"
    nm_clear_rules
    rm -f "$NM_PENDING" "$NM_DATA/.paths"
    exit 1
}
# 元模块挂载先于普通post-fs-data，UID屏蔽必须先于规则发布。
nm_clear_rules || fail_injection
nm_restore_exclusions || fail_injection

for mod_path in "$MODULES_DIR"/*; do
    [ -d "$mod_path" ] || continue
    [ "${mod_path##*/}" = nomount ] && continue
    if [ -f "$mod_path/disable" ] || [ -f "$mod_path/remove" ] || [ -f "$mod_path/skip_mount" ]; then
        continue
    fi
    for partition in $TARGET_PARTITIONS; do
        [ -d "$mod_path/$partition" ] || continue
        [ -d "/$partition" ] || [ -d "/system/$partition" ] || continue
        nm_log "[INFO] 加载 ${mod_path##*/}/$partition"
        # 分步执行，保留find及xargs各自的失败状态。路径以NUL分隔。
        find -L "$mod_path/$partition" \( -type d -o -type c -o -name .replace \) \
            -exec sh "$MODDIR/rule-paths.sh" path "$mod_path" {} + > "$NM_DATA/.paths" || fail_injection
        xargs -0 -r -n 200 "$NM_BIN" rule add --whiteout < "$NM_DATA/.paths" >> "$NM_LOG" 2>&1 || fail_injection
        find -L "$mod_path/$partition" \( -type f -o -type l \) ! -name .replace \
            -exec sh "$MODDIR/rule-paths.sh" pair "$mod_path" {} + > "$NM_DATA/.paths" || fail_injection
        xargs -0 -r -n 200 "$NM_BIN" rule add < "$NM_DATA/.paths" >> "$NM_LOG" 2>&1 || fail_injection
    done
done
rm -f "$NM_DATA/.paths"
nm_log "[OK] 文件加载完成，等待系统开机完成。"
"$NM_BIN" rule list >> "$NM_LOG" 2>&1 || fail_injection
