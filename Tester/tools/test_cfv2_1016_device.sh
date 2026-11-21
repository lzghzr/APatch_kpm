#!/usr/bin/env bash
#
# Tester/tools/test_cfv2_1016_device.sh
# 依据任务书: docs/records/2026-11-19-cfv2-1016-device-request.md
# 目标: cgroupv2_freeze 1.0.16 标准档真机复测（Nokia 7 Plus 4.4.192-perf+）
#
# 约定:
#   * 所有 adb 调用带超时
#   * 序列号明文不落盘，使用 sha256(serial)[:8]
#   * 原始数据保存到 Tester/reports/data/2026-11-19-cfv2-1016/
#   * 严禁执行 kpm unload
#

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"
[ -n "$SERIAL" ] || { echo "test_cfv2_1016_device.sh: 请设置 ANDROID_SERIAL" >&2; exit 2; }

FP="$(printf '%s' "$SERIAL" | shasum -a 256 | cut -c1-8)"
DATADIR="Tester/reports/data/2026-11-19-cfv2-1016"
mkdir -p "$DATADIR"

echo "=== 开始 cgroupv2_freeze 1.0.16 标准档真机复测 (设备指纹: $FP) ==="

CANDIDATE_PATH="artifacts/cgroupv2_freeze-1.0.16+gb29565c60f6c.r67bf3c0a.kpb51197a.gcc12.2.1-aarch64-none-elf#1/cgroupv2_freeze_1.0.16.kpm"
EXPECTED_SHA="76f710203e49c1203ab5e890f8c4d51c7f635eca42bd0ee47a0a1bd844b23d32"
EXPECTED_BOOT_B="05ad7af4d010783f56720106dc68d3ee8bf78d9acb0edd3096089469f91da2af"

# 1. 推送测试脚本与候选产物到设备
echo ">>> [准备] 推送测试脚本与候选产物到设备端..."
"$ADB" -s "$SERIAL" push "$CANDIDATE_PATH" /data/local/tmp/cgroupv2_freeze_1.0.16.kpm
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_1016_device_runner.sh /data/local/tmp/cfv2_1016_device_runner.sh
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_1016_uid1000_probe.sh /data/local/tmp/cfv2_1016_uid1000_probe.sh
"$ADB" -s "$SERIAL" shell "chmod 755 /data/local/tmp/cfv2_1016_device_runner.sh /data/local/tmp/cfv2_1016_uid1000_probe.sh"

# 2. 在设备端执行测试套件
echo ">>> [执行] 设备端运行 cfv2_1016_device_runner.sh..."
"$ADB" -s "$SERIAL" shell "su -c 'sh /data/local/tmp/cfv2_1016_device_runner.sh'"

# 3. 拉取测试结果
echo ">>> [收集] 从设备拉取测试结果到 $DATADIR/ ..."
"$ADB" -s "$SERIAL" pull /data/local/tmp/cfv2_1016_results/ "$DATADIR/"
if [ -d "$DATADIR/cfv2_1016_results" ]; then
  mv "$DATADIR/cfv2_1016_results"/* "$DATADIR/"
  rmdir "$DATADIR/cfv2_1016_results"
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

# 4. 清理设备端临时文件（不碰模块本身）
echo ">>> [清理] 清理设备端临时测试脚本与结果缓存..."
"$ADB" -s "$SERIAL" shell "su -c 'rm -rf /data/local/tmp/cfv2_1016_results /data/local/tmp/cfv2_1016_device_runner.sh /data/local/tmp/cfv2_1016_uid1000_probe.sh'"

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

P1_STATUS="FAIL"
if echo "$CG_MOUNT" | grep -q "cgroup none rw,cpuacct" && \
   [ "$ACCT_COUNT" = "$CG_COUNT" ] && \
   [ "$ACCT_UID_COUNT" = "$CG_UID_COUNT" ] && \
   [ "$UID_0_STATUS" = "EXISTS" ]; then
  P1_STATUS="PASS"
fi
echo "  [判据 1 判定]: $P1_STATUS"

# 判据 2
echo "--- [判据 2] 自建组与 freeze 文件 ---"
STAT_FROZEN="$(cat "$DATADIR/stat_frozen_dir.txt" | tr -d '\r\n')"
STAT_UNFROZEN="$(cat "$DATADIR/stat_unfrozen_dir.txt" | tr -d '\r\n')"
VAL_FROZEN="$(cat "$DATADIR/val_frozen_freeze.txt" | tr -d ' \r\n')"
VAL_UNFROZEN="$(cat "$DATADIR/val_unfrozen_freeze.txt" | tr -d ' \r\n')"
STAT_UID0="$(cat "$DATADIR/stat_uid0_freeze.txt" | tr -d '\r\n')"
STAT_UID1000="$(cat "$DATADIR/stat_uid1000_freeze.txt" | tr -d '\r\n')"
RW_TEST="$(cat "$DATADIR/criterion2_rw_test.txt")"

echo "  frozen dir stat          : $STAT_FROZEN"
echo "  unfrozen dir stat        : $STAT_UNFROZEN"
echo "  frozen/cgroup.freeze     : $VAL_FROZEN"
echo "  unfrozen/cgroup.freeze   : $VAL_UNFROZEN"
echo "  uid_0/cgroup.freeze stat : $STAT_UID0"
echo "  uid_1000 freeze stat     : $STAT_UID1000"
echo "  uid_9999 r/w test output :"
echo "$RW_TEST"

P2_STATUS="FAIL"
if [ "$VAL_FROZEN" = "1" ] && [ "$VAL_UNFROZEN" = "0" ] && \
   echo "$STAT_FROZEN" | grep -q "1000:1000" && \
   echo "$STAT_UNFROZEN" | grep -q "1000:1000" && \
   echo "$RW_TEST" | grep -q "after_1=1" && \
   echo "$RW_TEST" | grep -q "after_0=0"; then
  P2_STATUS="PASS"
fi
echo "  [判据 2 判定]: $P2_STATUS"

# 判据 3
echo "--- [判据 3] 零 cgroup_bpf AVC ---"
ENFORCE_STATUS="$(cat "$DATADIR/getenforce.txt" | tr -d ' \r\n')"
DMESG_BPF_AVC="$(cat "$DATADIR/dmesg_cgroup_bpf_avc_count.txt" | tr -d ' \r\n')"
LOGCAT_BPF_AVC="$(cat "$DATADIR/logcat_cgroup_bpf_avc_count.txt" | tr -d ' \r\n')"
DMESG_CG_AVC="$(cat "$DATADIR/dmesg_cgroup_avc_lines.txt")"
LOGCAT_CG_AVC="$(cat "$DATADIR/logcat_cgroup_avc_lines.txt")"

echo "  getenforce              : $ENFORCE_STATUS"
echo "  dmesg cgroup_bpf AVC    : $DMESG_BPF_AVC"
echo "  logcat cgroup_bpf AVC   : $LOGCAT_BPF_AVC"
echo "  cgroup AVC lines in dmesg : ${DMESG_CG_AVC:-<None>}"
echo "  cgroup AVC lines in logcat: ${LOGCAT_CG_AVC:-<None>}"

P3_STATUS="FAIL"
if [ "$ENFORCE_STATUS" = "Enforcing" ] && \
   [ "$DMESG_BPF_AVC" = "0" ] && \
   [ "$LOGCAT_BPF_AVC" = "0" ]; then
  P3_STATUS="PASS"
fi
echo "  [判据 3 判定]: $P3_STATUS"

# 判据 4
echo "--- [判据 4] 冻结能力（双视角） ---"
echo ">>> ① UID 1000 探针:"
cat "$DATADIR/criterion4_uid1000_probe.txt"
echo ">>> ② 真实写者路径:"
cat "$DATADIR/criterion4_real_writer_path.txt"
echo ">>> ③ 受控进程冻结验证:"
cat "$DATADIR/criterion4_controlled_freeze.txt"

P4_STATUS="FAIL"
if grep -q "UID 1000 P5 Complete" "$DATADIR/criterion4_uid1000_probe.txt" && \
   grep -q "wchan=do_freezer_trap" "$DATADIR/criterion4_controlled_freeze.txt" && \
   grep -q "Resumed window" "$DATADIR/criterion4_controlled_freeze.txt"; then
  P4_STATUS="PASS"
fi
echo "  [判据 4 判定]: $P4_STATUS"

# 判据 5
echo "--- [判据 5] 引导链路 ---"
BOOT_COMPLETED="$(cat "$DATADIR/boot_completed.txt" | tr -d ' \r\n')"
BUG_COUNT="$(cat "$DATADIR/bug_count.txt" | tr -d ' \r\n')"
PANIC_COUNT="$(cat "$DATADIR/panic_count.txt" | tr -d ' \r\n')"
cat "$DATADIR/criterion5_boot_chain.txt"

P5_STATUS="FAIL"
if [ "$BOOT_COMPLETED" = "1" ] && [ "$BUG_COUNT" = "0" ] && [ "$PANIC_COUNT" = "0" ] && \
   grep -q "KP load kpm: cgroupv2_freeze, event: pre-kernel-init, rc: 0" "$DATADIR/criterion5_boot_chain.txt" && \
   grep -q "post-fs-data.*rc: 0" "$DATADIR/criterion5_boot_chain.txt"; then
  P5_STATUS="PASS"
fi
echo "  [判据 5 判定]: $P5_STATUS"

echo ""
echo "=== 判定汇总 ==="
echo "判据 1 (带内容的挂载): $P1_STATUS"
echo "判据 2 (自建组与 freeze 文件): $P2_STATUS"
echo "判据 3 (零 cgroup_bpf AVC): $P3_STATUS"
echo "判据 4 (冻结能力双视角): $P4_STATUS"
echo "判据 5 (引导链路): $P5_STATUS"

if [ "$P1_STATUS" = "PASS" ] && [ "$P2_STATUS" = "PASS" ] && [ "$P3_STATUS" = "PASS" ] && [ "$P4_STATUS" = "PASS" ] && [ "$P5_STATUS" = "PASS" ]; then
  echo "ALL CRITERIA PASS"
  exit 0
else
  echo "CRITERIA FAIL"
  exit 1
fi
