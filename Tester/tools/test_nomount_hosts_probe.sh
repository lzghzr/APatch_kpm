#!/usr/bin/env bash
#
# 注意：本脚本是**操作记录**（打印命令与退出码），不产出 PASS/FAIL 判据，
#       不得作为验收依据；判据由对应请求单的 run_test 轮次承担。
# Tester/tools/test_nomount_hosts_probe.sh
#
# 依据请求单: docs/records/2026-10-26-nomount-hosts-redirect-replacement-request.md
# 目标: 探测 NoMount 2.2.0 对既有路径 /system/etc/hosts 做重定向的能力
#
# 约定:
#   * 所有 adb 调用带超时;
#   * 设备序列号明文不落盘;
#   * 记录完整命令与原始输出;
#   * 覆盖请求单最小判据 1-4 与 UID 记录要求.
#

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"
[ -n "$SERIAL" ] || { echo "test_nomount_hosts_probe: 请设置 ANDROID_SERIAL" >&2; exit 2; }

FP="$(printf '%s' "$SERIAL" | shasum -a 256 | cut -c1-8)"
echo "=== 开始探测 NoMount /system/etc/hosts 重定向能力 (设备指纹: $FP) ==="

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

adb_dev() {
  "$ADB" -s "$SERIAL" shell "$1"
}

adb_root() {
  "$ADB" -s "$SERIAL" shell "su -c '$1'"
}

RPATH="/data/local/tmp/nomount_probe_hosts.txt"

echo "--- 阶段一: 测前基线采集 ---"
run_cmd "读取系统 hosts 原始 stat" "$ADB -s $SERIAL shell \"stat /system/etc/hosts\""
run_cmd "读取系统 hosts 原始 sha256" "$ADB -s $SERIAL shell \"sha256sum /system/etc/hosts\""
run_cmd "读取系统 hosts 原始内容" "$ADB -s $SERIAL shell \"cat /system/etc/hosts\""
run_cmd "非 root 读取原始 hosts" "$ADB -s $SERIAL shell \"cat /system/etc/hosts; sha256sum /system/etc/hosts\""
run_cmd "测前 example.com 解析与网络连通基线" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""

echo "--- 阶段二: 准备 <rpath> 目标测试文件 ---"
run_cmd "创建 <rpath> 内容 (屏蔽 example.com)" "$ADB -s $SERIAL shell \"su -c 'printf \\\"127.0.0.1 localhost\\\\n::1 ip6-localhost\\\\n0.0.0.0 example.com\\\\n\\\" > $RPATH && chmod 644 $RPATH && chcon u:object_r:system_file:s0 $RPATH'\""
run_cmd "核验 <rpath> 属性与哈希" "$ADB -s $SERIAL shell \"stat $RPATH; sha256sum $RPATH; cat $RPATH; ls -lZ $RPATH\""

echo "--- 阶段三: 执行 nm rule add 注入既有路径 ---"
run_cmd "注入重定向规则: /system/etc/hosts -> $RPATH" "$ADB -s $SERIAL shell \"su -c 'nm rule add /system/etc/hosts $RPATH'\""
run_cmd "列出活动规则" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "列出活动规则 (JSON)" "$ADB -s $SERIAL shell \"su -c 'nm rule list --json'\""

echo "--- 阶段四: 判据 1 & 2 受管理路径元信息与内容检验 ---"
run_cmd "加规则后 /system/etc/hosts stat" "$ADB -s $SERIAL shell \"su -c 'stat /system/etc/hosts'\""
run_cmd "判据 1: root 读取 sha256 对比 (逐字节匹配 <rpath>)" "$ADB -s $SERIAL shell \"su -c 'sha256sum /system/etc/hosts $RPATH'\""
run_cmd "root 读取内容验证" "$ADB -s $SERIAL shell \"su -c 'cat /system/etc/hosts'\""

echo "--- 阶段五: UID 观察 (root vs 非 root) ---"
run_cmd "非 root (UID 2000 shell) 读取 hosts 内容与哈希" "$ADB -s $SERIAL shell \"cat /system/etc/hosts; sha256sum /system/etc/hosts; stat /system/etc/hosts\""
run_cmd "非 root (UID 10028 app) 读取 hosts 内容与哈希" "$ADB -s $SERIAL shell \"su 10028 -c 'cat /system/etc/hosts; sha256sum /system/etc/hosts'\""

echo "--- 阶段六: 判据 4 端到端域名屏蔽检验 ---"
run_cmd "解析检验: ping 被屏蔽域名 example.com" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""
run_cmd "连接检验: curl 被屏蔽域名 example.com" "$ADB -s $SERIAL shell \"curl -I -m 2 http://example.com 2>&1 || true\""

echo "--- 阶段七: 判据 3 规则注销与现场完整恢复 ---"
run_cmd "注销重定向规则: nm rule del /system/etc/hosts" "$ADB -s $SERIAL shell \"su -c 'nm rule del /system/etc/hosts'\""
run_cmd "列出活动规则 (确认已空)" "$ADB -s $SERIAL shell \"su -c 'nm rule list'\""
run_cmd "判据 3: /system/etc/hosts stat 恢复检验" "$ADB -s $SERIAL shell \"su -c 'stat /system/etc/hosts'\""
run_cmd "判据 3: /system/etc/hosts sha256 恢复检验" "$ADB -s $SERIAL shell \"su -c 'sha256sum /system/etc/hosts'\""
run_cmd "非 root 读取恢复检验" "$ADB -s $SERIAL shell \"cat /system/etc/hosts; sha256sum /system/etc/hosts\""
run_cmd "判据 4 恢复: ping example.com 恢复解析检验" "$ADB -s $SERIAL shell \"ping -c 1 -W 2 example.com 2>&1 || true\""

echo "--- 阶段八: 清理测试文件与设备健康复核 ---"
run_cmd "删除 <rpath> 临时测试文件" "$ADB -s $SERIAL shell \"su -c 'rm -f $RPATH'\""
run_cmd "检查 boot_id 与 uptime 单调性" "$ADB -s $SERIAL shell \"cat /proc/sys/kernel/random/boot_id; cat /proc/uptime\""
run_cmd "检查 dmesg 最近是否有崩溃或 panic" "$ADB -s $SERIAL shell \"su -c 'dmesg | tail -n 15'\""

echo "=== 探测流程执行完毕 ==="
