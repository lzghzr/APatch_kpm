#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR=${0%/*}
. "$MODDIR/common.sh"
mkdir -p "$NM_DATA"
if nm_check_api; then
    nm_clear_rules || exit 1
fi
for root in ap ksu; do
    link="/data/adb/$root/bin/nm"
    if [ -L "$link" ] && [ "$(readlink "$link")" = /data/adb/modules/nomount/bin/nm ]; then
        rm -f "$link"
    fi
done
rm -rf "$NM_DATA"
