#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

ui_print " "
ui_print "- 安装 NoMount-kpm"
if [ "$APATCH" = true ]; then
    ROOT_IMP=ap
elif [ "$KSU" = true ]; then
    ROOT_IMP=ksu
elif command -v apd >/dev/null 2>&1 || [ -x /data/adb/ap/bin/apd ]; then
    ROOT_IMP=ap
elif command -v ksud >/dev/null 2>&1 || [ -x /data/adb/ksu/bin/ksud ]; then
    ROOT_IMP=ksu
else
    abort "! 请使用支持元模块的 APatch 或 KernelSU 安装。"
fi

[ "$ARCH" = arm64 ] || abort "! 当前配套模块支持 arm64。"
set_perm "$MODPATH/bin/nm" 0 0 0755
MODDIR="$MODPATH"
. "$MODDIR/common.sh"
if ! nm_check_api; then
    ui_print "! 无法连接 NoMount。请先在 APatch 中嵌入对应设备的 KPM，参数留空。"
    abort "! 嵌入后重启手机，再安装这个 ZIP。"
fi
ui_print "- NoMount 已连接，驱动版本：$NM_DRIVER_VERSION"

mkdir -p "$NM_DATA" "/data/adb/$ROOT_IMP/bin" || abort "! 无法建立模块数据目录。"
ln -sf /data/adb/modules/nomount/bin/nm "/data/adb/$ROOT_IMP/bin/nm" || abort "! 无法安装 nm 快捷入口。"
ui_print "- 安装完成。重启后加载已启用模块的文件。"
