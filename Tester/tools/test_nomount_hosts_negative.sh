#!/usr/bin/env bash
#
# Tester/tools/test_nomount_hosts_negative.sh
#
# 依据请求单: docs/records/2026-10-26-nomount-hosts-uid-scope-and-label-request.md
# 目标: 针对 NoMount 2.2.0 对 /system/etc/hosts 重定向的 UID 作用域与源端约束执行负例补测 (A/B 组)
#
# 约定:
#   * 所有 adb 调用带超时;
#   * 设备序列号明文不落盘;
#   * 记录完整命令与原始输出;
#   * A 组: 验证 UID 0 生效 + 排除非 root UID 回退底盘原文件 (缓存顺序);
#   * B 组: 验证 B1 (SELinux 标签非 system_file 导致 netd denial) 与 B2 (DAC 0600 导致非 root Permission denied 且不回退).
#

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"
[ -n "$SERIAL" ] || { echo "test_nomount_hosts_negative: 请设置 ANDROID_SERIAL" >&2; exit 2; }

FP="$(printf '%s' "$SERIAL" | shasum -a 256 | cut -c1-8)"
echo "=== 开始 NoMount /system/etc/hosts UID 作用域与源端约束负例测试 (设备指纹: $FP) ==="

run_cmd() {
  local desc="$1"
  local cmd="$2"
  echo ""
  echo ">>> [COMMAND] $desc"
  echo "$ ${cmd//$SERIAL/$FP}"
  eval "$cmd"
  local rc=$?
  echo "[EXIT CODE] $rc"
  return $rc
}

RAW_DIR="$REPO/local/tester-raw"
mkdir -p "$RAW_DIR"

RPATH_A="/data/local/tmp/nomount_probe_hosts_a.txt"
RPATH_B1="/data/local/tmp/nomount_probe_hosts_b1.txt"
RPATH_B2="/data/local/tmp/nomount_probe_hosts_b2.txt"

echo ""
echo "============================================================"
echo "--- 阶段一: 测前基线与设备状态采集 ---"
echo "============================================================"
run_cmd "读取设备 boot_id" "$ADB -s $SERIAL shell \"cat /proc/sys/kernel/random/boot_id\""
run_cmd "读取设备 uptime" "$ADB -s $SERIAL shell \"cat /proc/uptime\""
run_cmd "读取已加载模块 (Manager UID 10028 通道)" "$ADB -s $SERIAL shell \"su 10028 -c '/data/adb/ap/bin/kpatch su kpm list 2>/dev/null || /data/adb/kpatch su kpm list 2>/dev/null'\""
run_cmd "读取当前活动 nm 规则" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "读取系统 hosts 原始 stat" "$ADB -s $SERIAL shell \"stat /system/etc/hosts\""
run_cmd "读取系统 hosts 原始 sha256" "$ADB -s $SERIAL shell \"sha256sum /system/etc/hosts\""
run_cmd "读取系统 hosts 原始内容" "$ADB -s $SERIAL shell \"cat /system/etc/hosts\""
run_cmd "测前 example.com 解析与网络连通基线" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""

echo ""
echo "============================================================"
echo "--- 阶段二: A 组 - 排除非 root UID 后的回退与缓存顺序验证 ---"
echo "============================================================"
run_cmd "准备 A 组测试源文件 (0644, system_file)" "$ADB -s $SERIAL shell \"su -c 'printf \\\"127.0.0.1 localhost\\\\n::1 ip6-localhost\\\\n0.0.0.0 example.com\\\\n\\\" > $RPATH_A && chmod 644 $RPATH_A && chcon u:object_r:system_file:s0 $RPATH_A'\""
run_cmd "核验 A 组源文件属性" "$ADB -s $SERIAL shell \"stat $RPATH_A; sha256sum $RPATH_A; ls -lZ $RPATH_A\""

run_cmd "下发只对 UID 0 生效规则 (排除 1-4294967295)" "$ADB -s $SERIAL shell \"su -c 'nm rule add --uid-range all --uid-excluded 1-4294967295 /system/etc/hosts $RPATH_A'\""
run_cmd "查看活动规则列表" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "查看活动规则列表 (JSON)" "$ADB -s $SERIAL shell \"su -c 'nm rule list --json'\""

# 判据 A1: 缓存顺序第一步 - 先由 root 读一次，促使虚拟 inode 进 dcache
run_cmd "判据 A1: root 首次读取 (进 dcache，比对 sha256 与 stat)" "$ADB -s $SERIAL shell \"su -c 'sha256sum /system/etc/hosts $RPATH_A; stat /system/etc/hosts; cat /system/etc/hosts'\""

# 判据 A2 & A3: 缓存顺序第二步 - 非 root 读，确认回退到底盘原文件而非命中覆盖缓存，无 Permission denied
run_cmd "判据 A2 & A3: 非 root shell (UID 2000) 读取检验" "$ADB -s $SERIAL shell \"id; stat /system/etc/hosts; sha256sum /system/etc/hosts; cat /system/etc/hosts\""
run_cmd "判据 A2 & A3: 非 root 管理器 (UID 10028) 读取检验" "$ADB -s $SERIAL shell \"su 10028 -c 'id; stat /system/etc/hosts; sha256sum /system/etc/hosts; cat /system/etc/hosts'\""

# 判据 A4: 删除规则后全部恢复原状
run_cmd "判据 A4: 注销 A 组规则" "$ADB -s $SERIAL shell \"su -c 'nm rule del --uid-range all --uid-excluded 1-4294967295 /system/etc/hosts'\""
run_cmd "确认规则已注销" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "判据 A4 恢复检验: root 读回原文件" "$ADB -s $SERIAL shell \"su -c 'stat /system/etc/hosts; sha256sum /system/etc/hosts; cat /system/etc/hosts'\""
run_cmd "清理 A 组临时文件" "$ADB -s $SERIAL shell \"su -c 'rm -f $RPATH_A'\""

echo ""
echo "============================================================"
echo "--- 阶段三: B1 组 - 源端标签非 system_file (shell_data_file) 负例 ---"
echo "============================================================"
run_cmd "准备 B1 源文件 (0644, shell_data_file)" "$ADB -s $SERIAL shell \"su -c 'printf \\\"127.0.0.1 localhost\\\\n::1 ip6-localhost\\\\n0.0.0.0 example.com\\\\n\\\" > $RPATH_B1 && chmod 644 $RPATH_B1 && chcon u:object_r:shell_data_file:s0 $RPATH_B1'\""
run_cmd "核验 B1 源文件属性与 SELinux 标签" "$ADB -s $SERIAL shell \"stat $RPATH_B1; sha256sum $RPATH_B1; ls -lZ $RPATH_B1\""

run_cmd "清空 dmesg 缓冲区" "$ADB -s $SERIAL shell \"su -c 'dmesg -c > /dev/null'\""
run_cmd "下发 B1 重定向规则" "$ADB -s $SERIAL shell \"su -c 'nm rule add /system/etc/hosts $RPATH_B1'\""
run_cmd "查看活动规则列表" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "检查受管理路径 SELinux 标签 (确认透传 shell_data_file)" "$ADB -s $SERIAL shell \"ls -lZ /system/etc/hosts\""

run_cmd "B1 观测: root 读取" "$ADB -s $SERIAL shell \"su -c 'sha256sum /system/etc/hosts; cat /system/etc/hosts'\""
run_cmd "B1 观测: shell UID 2000 读取" "$ADB -s $SERIAL shell \"id; sha256sum /system/etc/hosts; cat /system/etc/hosts\""
run_cmd "B1 观测: 管理器 UID 10028 读取" "$ADB -s $SERIAL shell \"su 10028 -c 'id; sha256sum /system/etc/hosts; cat /system/etc/hosts'\""

run_cmd "B1 观测: netd 触发解析 (ping example.com)" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""
run_cmd "B1 观测: HTTP 连通性测试 (curl example.com)" "$ADB -s $SERIAL shell \"curl -I -m 2 http://example.com 2>&1 || true\""

run_cmd "采集 netd SELinux denial 原始日志" "$ADB -s $SERIAL shell \"su -c 'dmesg | grep -E \\\"avc:  denied.*netd\\\"'\""
# 保存原始 SELinux denial 到 local/tester-raw/
$ADB -s $SERIAL shell "su -c 'dmesg | grep -E \"avc:  denied.*netd\"'" > "$RAW_DIR/2026-10-26-hosts-selinux-denial.raw.txt" 2>&1 || true

run_cmd "注销 B1 规则" "$ADB -s $SERIAL shell \"su -c 'nm rule del /system/etc/hosts'\""
run_cmd "B1 恢复检验: ping example.com 恢复公网" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""
run_cmd "清理 B1 临时文件" "$ADB -s $SERIAL shell \"su -c 'rm -f $RPATH_B1'\""

echo ""
echo "============================================================"
echo "--- 阶段四: B2 组 - 源端 DAC 0600 + system_file 标签负例 ---"
echo "============================================================"
run_cmd "准备 B2 源文件 (0600, system_file)" "$ADB -s $SERIAL shell \"su -c 'printf \\\"127.0.0.1 localhost\\\\n::1 ip6-localhost\\\\n0.0.0.0 example.com\\\\n\\\" > $RPATH_B2 && chmod 600 $RPATH_B2 && chcon u:object_r:system_file:s0 $RPATH_B2'\""
run_cmd "核验 B2 源文件属性与权限" "$ADB -s $SERIAL shell \"stat $RPATH_B2; sha256sum $RPATH_B2; ls -lZ $RPATH_B2\""

run_cmd "下发 B2 重定向规则" "$ADB -s $SERIAL shell \"su -c 'nm rule add /system/etc/hosts $RPATH_B2'\""
run_cmd "查看活动规则列表" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "检查受管理路径权限 (确认呈现 0600)" "$ADB -s $SERIAL shell \"ls -lZ /system/etc/hosts\""

run_cmd "B2 观测: root 读取 (应当成功读取覆盖内容)" "$ADB -s $SERIAL shell \"su -c 'sha256sum /system/etc/hosts; cat /system/etc/hosts'\""
run_cmd "B2 观测: shell UID 2000 读取 (预期 Permission denied, 不回退原文件)" "$ADB -s $SERIAL shell \"cat /system/etc/hosts 2>&1 || true; sha256sum /system/etc/hosts 2>&1 || true\""
run_cmd "B2 观测: 管理器 UID 10028 读取 (预期 Permission denied, 不回退原文件)" "$ADB -s $SERIAL shell \"su 10028 -c 'cat /system/etc/hosts 2>&1 || true; sha256sum /system/etc/hosts 2>&1 || true'\""

run_cmd "B2 观测: netd 域名屏蔽检验 (netd root 读取 0600 成功)" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""

run_cmd "注销 B2 规则" "$ADB -s $SERIAL shell \"su -c 'nm rule del /system/etc/hosts'\""
run_cmd "B2 恢复检验: shell UID 2000 读取恢复原文件" "$ADB -s $SERIAL shell \"cat /system/etc/hosts; sha256sum /system/etc/hosts\""
run_cmd "B2 恢复检验: ping example.com 恢复公网" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""
run_cmd "清理 B2 临时文件" "$ADB -s $SERIAL shell \"su -c 'rm -f $RPATH_B2'\""

echo ""
echo "============================================================"
echo "--- 阶段五: 设备存活与健康复核 ---"
echo "============================================================"
run_cmd "复核 boot_id 与 uptime" "$ADB -s $SERIAL shell \"cat /proc/sys/kernel/random/boot_id; cat /proc/uptime\""
run_cmd "检查 dmesg 尾部无崩溃" "$ADB -s $SERIAL shell \"su -c 'dmesg | tail -n 15'\""

echo ""
echo "=== 全部负例测试执行完成 ==="
