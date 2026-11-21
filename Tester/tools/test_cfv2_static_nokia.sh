#!/usr/bin/env bash
#
# Tester/tools/test_cfv2_static_nokia.sh
# 依据任务书: docs/records/2026-11-19-cfv2-static-nokia-test.md
# 目标: cgroupv2_freeze 1.1.0 静态基线真机测试（Nokia 7 Plus 4.4.192-perf+）
#
# 约定:
#   * 所有 adb 调用带超时
#   * 序列号明文不落盘，使用 sha256(serial)[:8]
#   * 原始数据保存到 Tester/reports/data/2026-11-19-cfv2-static-nokia/
#   * 严禁执行 kpm unload
#

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"
[ -n "$SERIAL" ] || { echo "test_cfv2_static_nokia.sh: 请设置 ANDROID_SERIAL" >&2; exit 2; }

FP="$(printf '%s' "$SERIAL" | shasum -a 256 | cut -c1-8)"
DATADIR="Tester/reports/data/2026-11-19-cfv2-static-nokia"
mkdir -p "$DATADIR"

echo "=== 开始 cgroupv2_freeze 1.1.0 静态基线真机测试 (设备指纹: $FP) ==="

CANDIDATE_PATH="local/keep/cfv2-static-nokia-v2/cgroupv2_freeze_1.1.0_baselines.kpm"
EXPECTED_SHA="207257da06bf7a99efcdb23ae94f4f30db46a7083dc3ee06864920e5c78e173a"

# 1. 推送测试脚本到设备
echo ">>> [准备] 推送测试脚本到设备端..."
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_static_device_runner.sh /data/local/tmp/cfv2_static_device_runner.sh
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_static_uid1000_probe.sh /data/local/tmp/cfv2_static_uid1000_probe.sh
"$ADB" -s "$SERIAL" shell "chmod 755 /data/local/tmp/cfv2_static_device_runner.sh /data/local/tmp/cfv2_static_uid1000_probe.sh"

# 2. 在设备端执行测试套件
echo ">>> [执行] 设备端运行 cfv2_static_device_runner.sh..."
"$ADB" -s "$SERIAL" shell "su -c 'sh /data/local/tmp/cfv2_static_device_runner.sh'"

# 3. 拉取测试结果
echo ">>> [收集] 从设备拉取测试结果到 $DATADIR/ ..."
"$ADB" -s "$SERIAL" pull /data/local/tmp/cfv2_static_results/ "$DATADIR/"
if [ -d "$DATADIR/cfv2_static_results" ]; then
  mv "$DATADIR/cfv2_static_results"/* "$DATADIR/"
  rmdir "$DATADIR/cfv2_static_results"
fi

# 日志脱敏（去除明文序列号与主机路径）
python3 -c "
import os
datadir = '$DATADIR'
serial = '$SERIAL'
for fname in os.listdir(datadir):
    fpath = os.path.join(datadir, fname)
    if os.path.isfile(fpath):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            changed = False
            if serial and serial in content:
                content = content.replace(serial, '<REDACTED>')
                changed = True
            if '/home/' in content or '/Volumes/' in content or '/Users/' in content:
                import re
                content = re.sub(r'/(home|Volumes|Users)/[a-zA-Z0-9_.-]+', '<REDACTED_PATH>', content)
                changed = True
            if changed:
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(content)
        except Exception:
            pass
"

# 4. 清理设备端临时测试脚本与结果缓存（不碰模块本身）
echo ">>> [清理] 清理设备端临时测试脚本与结果缓存..."
"$ADB" -s "$SERIAL" shell "su -c 'rm -rf /data/local/tmp/cfv2_static_results /data/local/tmp/cfv2_static_device_runner.sh /data/local/tmp/cfv2_static_uid1000_probe.sh'"

echo ""
echo "==================== 判据核验与判定 ===================="

# 判据 1
echo "--- [判据 1] 带内容的挂载 ---"
CG_MOUNT="$(grep " /sys/fs/cgroup " "$DATADIR/proc_1_mountinfo.txt" || true)"
ACCT_COUNT="$(cat "$DATADIR/acct_entry_count.txt" | tr -d ' \r\n')"
CG_COUNT="$(cat "$DATADIR/sys_cgroup_entry_count.txt" | tr -d ' \r\n')"
ACCT_UID_COUNT="$(cat "$DATADIR/acct_uid_count.txt" | tr -d ' \r\n')"
CG_UID_COUNT="$(cat "$DATADIR/sys_cgroup_uid_count.txt" | tr -d ' \r\n')"
UID_0_STATUS="$(cat "$DATADIR/uid_0_exists.txt" | tr -d ' \r\n')"

echo "  Mount /sys/fs/cgroup     : $CG_MOUNT"
echo "  /acct total entries      : $ACCT_COUNT"
echo "  /sys/fs/cgroup entries   : $CG_COUNT"
echo "  /acct uid_* count        : $ACCT_UID_COUNT"
echo "  /sys/fs/cgroup uid count : $CG_UID_COUNT"
echo "  uid_0 directory exists   : $UID_0_STATUS"

# 判据 2
echo "--- [判据 2] 自建组与 freeze 文件 ---"
STAT_FROZEN="$(cat "$DATADIR/stat_frozen_dir.txt")"
STAT_UNFROZEN="$(cat "$DATADIR/stat_unfrozen_dir.txt")"
VAL_FROZEN="$(cat "$DATADIR/val_frozen_freeze.txt" | tr -d ' \r\n')"
VAL_UNFROZEN="$(cat "$DATADIR/val_unfrozen_freeze.txt" | tr -d ' \r\n')"
echo "  frozen dir               : $STAT_FROZEN"
echo "  unfrozen dir             : $STAT_UNFROZEN"
echo "  frozen/cgroup.freeze     : $VAL_FROZEN"
echo "  unfrozen/cgroup.freeze   : $VAL_UNFROZEN"
echo "  uid_9999 r/w test output :"
cat "$DATADIR/criterion2_rw_test.txt"

# 判据 3
echo "--- [判据 3] 零 cgroup_bpf AVC ---"
ENFORCE="$(cat "$DATADIR/getenforce.txt" | tr -d ' \r\n')"
DMESG_AVC="$(cat "$DATADIR/dmesg_cgroup_bpf_avc_count.txt" | tr -d ' \r\n')"
LOGCAT_AVC="$(cat "$DATADIR/logcat_cgroup_bpf_avc_count.txt" | tr -d ' \r\n')"
echo "  SELinux status           : $ENFORCE"
echo "  dmesg cgroup_bpf AVC     : $DMESG_AVC"
echo "  logcat cgroup_bpf AVC    : $LOGCAT_AVC"

# 判据 4
echo "--- [判据 4] 冻结能力验证 ---"
echo "  UID 1000 probe output:"
cat "$DATADIR/criterion4_uid1000_probe.txt"
echo "  Controlled freeze output:"
cat "$DATADIR/criterion4_controlled_freeze.txt"

# 判据 5
echo "--- [判据 5] 引导链路 ---"
BOOT_COMPLETED="$(cat "$DATADIR/boot_completed.txt" | tr -d ' \r\n')"
BUG_COUNT="$(cat "$DATADIR/bug_count.txt" | tr -d ' \r\n')"
PANIC_COUNT="$(cat "$DATADIR/panic_count.txt" | tr -d ' \r\n')"
echo "  sys.boot_completed       : $BOOT_COMPLETED"
echo "  BUG: count               : $BUG_COUNT"
echo "  Kernel panic count       : $PANIC_COUNT"
echo "  Boot events in dmesg:"
cat "$DATADIR/criterion5_boot_chain.txt"

# 判据 6
echo "--- [判据 6] 静态专有：Static baseline 拒载检查 ---"
STATIC_REJECT="$(cat "$DATADIR/static_reject_count.txt" 2>/dev/null | tr -d ' \r\n')"
echo "  Static baseline拒载计数   : ${STATIC_REJECT:-0}"
if [ "${STATIC_REJECT:-0}" -gt 0 ] 2>/dev/null; then
  echo "  拒载原文:"
  cat "$DATADIR/dmesg_static_baseline_rejection.txt"
fi

# 判据 7
echo "--- [判据 7] 静态专有：ctl0 事件链与卸载策略 ---"
cat "$DATADIR/criterion7_ctl0_event_chain.txt"

echo ""
echo "=== 测试执行完毕 ==="
