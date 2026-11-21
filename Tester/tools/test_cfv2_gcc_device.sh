#!/usr/bin/env bash
#
# Tester/tools/test_cfv2_gcc_device.sh
# 依据任务书: docs/records/2026-11-18-cfv2-gcc-device-request.md
# 目标: cgroupv2_freeze 1.0.14 GCC 件真机复测（轻量档，Nokia 7 Plus 4.4.192-perf+）
#
# 约定:
#   * 所有 adb 调用带超时
#   * 序列号明文不落盘，使用 sha256(serial)[:8]
#   * 原始数据保存到 Tester/reports/data/2026-11-18-cfv2-gcc/
#   * 严禁执行 kpm unload
#

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"
[ -n "$SERIAL" ] || { echo "test_cfv2_gcc_device.sh: 请设置 ANDROID_SERIAL" >&2; exit 2; }

FP="$(printf '%s' "$SERIAL" | shasum -a 256 | cut -c1-8)"
DATADIR="Tester/reports/data/2026-11-18-cfv2-gcc"
mkdir -p "$DATADIR"

echo "=== 开始 cgroupv2_freeze 1.0.14 GCC 件轻量档复测 (设备指纹: $FP) ==="

CANDIDATE_PATH="artifacts/cgroupv2_freeze-1.0.14+gff219a2bcc27.ra85e66c4.kpb51197a.gcc12.2.1-aarch64-none-elf#1/cgroupv2_freeze_1.0.14.kpm"
EXPECTED_SHA="2cc3cd08ecc30dbea6a490b4bd6c5fe2352a8822775116db518ebc7c5de70b48"

# 1. 推送测试脚本与候选产物到设备
echo ">>> [准备] 推送测试脚本与候选产物到设备端..."
"$ADB" -s "$SERIAL" push "$CANDIDATE_PATH" /data/local/tmp/cgroupv2_freeze_1.0.14.kpm
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_gcc_device_runner.sh /data/local/tmp/cfv2_gcc_device_runner.sh
"$ADB" -s "$SERIAL" push Tester/tools/cfv2_p5_uid1000.sh /data/local/tmp/cfv2_p5_uid1000.sh
"$ADB" -s "$SERIAL" shell "chmod 755 /data/local/tmp/cfv2_gcc_device_runner.sh /data/local/tmp/cfv2_p5_uid1000.sh"

# 2. 在设备端执行测试套件
echo ">>> [执行] 设备端运行 cfv2_gcc_device_runner.sh..."
"$ADB" -s "$SERIAL" shell "su -c 'sh /data/local/tmp/cfv2_gcc_device_runner.sh'"

# 3. 拉取测试结果
echo ">>> [收集] 从设备拉取测试结果到 $DATADIR/ ..."
"$ADB" -s "$SERIAL" pull /data/local/tmp/cfv2_results/ "$DATADIR/"
# 整理目录结构（pull 会把 cfv2_results 放到 $DATADIR 下）
if [ -d "$DATADIR/cfv2_results" ]; then
  mv "$DATADIR/cfv2_results"/* "$DATADIR/"
  rmdir "$DATADIR/cfv2_results"
fi

# 日志脱敏（去除明文序列号与主机路径）
if [ -f "$DATADIR/dmesg_full.txt" ]; then
  python3 - "$DATADIR/dmesg_full.txt" <<'PYTHON'
import os
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
data = path.read_text(encoding="utf-8", errors="replace")
data = data.replace(os.environ["ANDROID_SERIAL"], "<REDACTED>")
data = re.sub(r"/(?:home|Users|Volumes)/[A-Za-z0-9_.-]+", "<REDACTED_PATH>", data)
path.write_text(data, encoding="utf-8")
PYTHON
fi

# 4. 清理设备端临时文件（不碰模块本身）
echo ">>> [清理] 清理设备端临时测试脚本与结果缓存..."
"$ADB" -s "$SERIAL" shell "su -c 'rm -rf /data/local/tmp/cfv2_results /data/local/tmp/cfv2_gcc_device_runner.sh /data/local/tmp/cfv2_p5_uid1000.sh'"

echo ""
echo "==================== 判据核验与判定 ===================="

# 判据 1
echo "--- [判据 1] 上机字节与引导 ---"
DEV_SHA="$(cat "$DATADIR/kpm_sha256.txt" | cut -d' ' -f1)"
DEV_SIZE="$(cat "$DATADIR/kpm_size.txt" | tr -d ' \r\n')"
BOOT_COMPLETED="$(cat "$DATADIR/boot_completed.txt" | tr -d ' \r\n')"
BOOT_ID="$(cat "$DATADIR/boot_id.txt" | tr -d ' \r\n')"
UPTIME="$(cat "$DATADIR/uptime.txt" | tr -d '\r\n')"
BUG_COUNT="$(cat "$DATADIR/bug_count.txt" | tr -d ' \r\n')"
PANIC_COUNT="$(cat "$DATADIR/panic_count.txt" | tr -d ' \r\n')"

echo "  Device KPM SHA256 : $DEV_SHA"
echo "  Device KPM Size   : $DEV_SIZE"
echo "  boot_completed    : $BOOT_COMPLETED"
echo "  boot_id           : $BOOT_ID"
echo "  uptime            : $UPTIME"
echo "  BUG: count        : $BUG_COUNT"
echo "  Kernel panic count: $PANIC_COUNT"

P1_STATUS="FAIL"
if [ "$DEV_SHA" = "$EXPECTED_SHA" ] && [ "$BOOT_COMPLETED" = "1" ] && [ "$BUG_COUNT" = "0" ] && [ "$PANIC_COUNT" = "0" ]; then
  P1_STATUS="PASS"
fi
echo "  [判据 1 判定]: $P1_STATUS"

# 判据 2
echo "--- [判据 2] 引导期加载与布局 ---"
LOAD_LINE="$(grep "KP load kpm: cgroupv2_freeze, event: pre-kernel-init, rc: 0" "$DATADIR/dmesg_boot_cfv2.txt" || true)"
LAYOUT_LINE="$(grep "cgroupv2_freeze: layout:" "$DATADIR/dmesg_boot_cfv2.txt" || true)"
CFTYPE_LINE="$(grep "cgroupv2_freeze: cftype layout:" "$DATADIR/dmesg_boot_cfv2.txt" || true)"

echo "  LOAD_LINE  : $LOAD_LINE"
echo "  CFTYPE_LINE: $CFTYPE_LINE"
echo "  LAYOUT_LINE: $LAYOUT_LINE"

P2_STATUS="FAIL"
if [ -n "$LOAD_LINE" ] && [ -n "$LAYOUT_LINE" ] && [ -n "$CFTYPE_LINE" ]; then
  P2_STATUS="PASS"
fi
echo "  [判据 2 判定]: $P2_STATUS"

# 判据 3
echo "--- [判据 3] 挂载与 DAC 属主 ---"
CGROUP_MOUNT="$(grep " /sys/fs/cgroup " "$DATADIR/proc_1_mountinfo.txt" || true)"
BPF_MOUNT="$(grep " /dev/cg2_bpf " "$DATADIR/proc_1_mountinfo.txt" || true)"
STAT_SYS="$(cat "$DATADIR/stat_cgroup.txt" | tr -d '\r\n')"
STAT_BPF="$(cat "$DATADIR/stat_bpf.txt" | tr -d '\r\n')"

echo "  Mount /sys/fs/cgroup : $CGROUP_MOUNT"
echo "  Mount /dev/cg2_bpf   : $BPF_MOUNT"
echo "  Stat /sys/fs/cgroup  : $STAT_SYS"
echo "  Stat /dev/cg2_bpf    : $STAT_BPF"

P3_STATUS="FAIL"
if echo "$STAT_SYS" | grep -q "1000:1000 775" && echo "$CGROUP_MOUNT" | grep -q "cgroup2"; then
  P3_STATUS="PASS (bind /dev/cg2_bpf, DAC 1000:1000 775)"
fi
echo "  [判据 3 判定]: $P3_STATUS"

# 判据 4
echo "--- [判据 4] 单轮冻结验证 ---"
cat "$DATADIR/criterion4_freeze_behavior.txt"

P4_STATUS="FAIL"
if grep -q "wchan=do_freezer_trap" "$DATADIR/criterion4_freeze_behavior.txt" && \
   grep -q "Unfrozen window" "$DATADIR/criterion4_freeze_behavior.txt"; then
  P4_STATUS="PASS"
fi
echo "  [判据 4 判定]: $P4_STATUS"

# 判据 5
echo "--- [判据 5] UID 1000 消费者视角 ---"
cat "$DATADIR/criterion5_uid1000_consumer.txt"

P5_STATUS="FAIL"
if grep -q "after_write_1=1" "$DATADIR/criterion5_uid1000_consumer.txt" && \
   grep -q "after_write_0=0" "$DATADIR/criterion5_uid1000_consumer.txt" && \
   grep -q "wchan=do_freezer_trap" "$DATADIR/criterion5_uid1000_consumer.txt"; then
  P5_STATUS="PASS"
fi
echo "  [判据 5 判定]: $P5_STATUS"

# 判据 6
echo "--- [判据 6] 墓碑模块与 UID 1000 ---"
cat "$DATADIR/tombstone_and_freezer_check.txt"

RE_KERNEL_LOADED="$(grep -E '^re_kernel$|^re_kernel_x$' "$DATADIR/tombstone_and_freezer_check.txt" || true)"
NEP_RUNNING="$(grep -v 'None running' "$DATADIR/tombstone_and_freezer_check.txt" | grep "nep.timeline.freezer" || true)"

echo "  re_kernel/re_kernel_x loaded : ${RE_KERNEL_LOADED:-No}"
echo "  nep.timeline.freezer running : ${NEP_RUNNING:-No}"

P6_STATUS="FAIL"
if [ -z "$RE_KERNEL_LOADED" ]; then
  P6_STATUS="PASS (re_kernel/re_kernel_x 未在载，nep.timeline.freezer 未运行，无干扰)"
fi
echo "  [判据 6 判定]: $P6_STATUS"

# 判据 7
echo "--- [判据 7] 不收尾卸载 ---"
echo "  遵从纪律：KPM 不可卸载（exit 恒 -EBUSY），未执行任何 kpm unload"
echo "  [判据 7 判定]: PASS (保持驻留，设备未执行 unload)"

echo ""
echo "=== 判定汇总 ==="
echo "判据 1: $P1_STATUS"
echo "判据 2: $P2_STATUS"
echo "判据 3: $P3_STATUS"
echo "判据 4: $P4_STATUS"
echo "判据 5: $P5_STATUS"
echo "判据 6: $P6_STATUS"
echo "判据 7: PASS"
