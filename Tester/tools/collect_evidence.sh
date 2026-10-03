#!/usr/bin/env bash
# 真机异常证据采集（死机/卡死/崩溃后立即执行）。
#
#   bash Tester/tools/collect_evidence.sh --build-id <build_id> --module re_kernel
#
# 原则（docs/process/07-escalation-device.md）:
#   * 采集优先，失败不阻塞其它项；每项都带超时；
#   * 不清理现场：不清 dmesg、不清 pstore、不卸载模块、不刷机；
#   * 采不到就写明「采不到 + 原因」，不要编造。

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

BUILD_ID=""
MODULE=""
OUTDIR="${OUTDIR:-Tester/reports/escalations}"
ADB="${ADB:-adb}"
TIMEOUT="${TIMEOUT:-15}"
KP_CMD="${KP_CMD:-truncate}"
SUPERKEY="${SUPERKEY:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --build-id) BUILD_ID="$2"; shift 2 ;;
    --module) MODULE="$2"; shift 2 ;;
    --out) OUTDIR="$2"; shift 2 ;;
    *) echo "用法: collect_evidence.sh --build-id <id> --module <name> [--out DIR]" >&2; exit 2 ;;
  esac
done
[ -n "$BUILD_ID" ] || { echo "缺少 --build-id" >&2; exit 2; }
[ -n "$MODULE" ] || { echo "缺少 --module" >&2; exit 2; }

run_to() {
  local t="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$t"; kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null ) &
  local wd=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  return $rc
}

DEST="$OUTDIR/$(date +%F)-${MODULE}-$(printf '%s' "$BUILD_ID" | tr '/+' '__')"
mkdir -p "$DEST"
STAMP="$(date +%Y-%m-%dT%H:%M:%S%z)"

# 逐项采集：cmd <名称> <adb shell 命令>  /  root_cmd 走 su
collect() {
  local name="$1" cmd="$2" mode="${3:-shell}"
  local target="$DEST/$name.txt"
  local rc=0
  if [ "$mode" = "root" ]; then
    run_to "$TIMEOUT" "$ADB" shell "su -c '$cmd'" > "$target" 2>&1 || rc=$?
  else
    run_to "$TIMEOUT" "$ADB" shell "$cmd" > "$target" 2>&1 || rc=$?
  fi
  if [ "$rc" -eq 0 ] && [ -s "$target" ]; then
    echo "OK      $name ($(wc -c < "$target" | tr -d ' ') 字节)"
  else
    echo "MISS    $name (rc=$rc)" | tee -a "$target"
  fi
}

echo "== 证据采集（不清理现场、不重试、不修改任何东西）=="
collect "pstore-console-ramoops" "cat /sys/fs/pstore/console-ramoops* 2>/dev/null" root
collect "pstore-dmesg-ramoops" "cat /sys/fs/pstore/dmesg-ramoops* 2>/dev/null" root
collect "last-kmsg" "cat /proc/last_kmsg 2>/dev/null" root
collect "dmesg-tail" "dmesg | tail -n 400"
collect "dmesg-crash-lines" "dmesg | grep -E 'Unable to handle kernel|Kernel panic|BUG:|Call trace|watchdog|hard lockup|soft lockup' | tail -n 100"
collect "uptime-btime" "cat /proc/uptime; cat /proc/stat | grep btime; cat /proc/sys/kernel/random/boot_id"
collect "env" "uname -a; getprop ro.product.model; getprop ro.build.fingerprint; getprop ro.build.version.release; getenforce"
if [ -n "$SUPERKEY" ]; then
  collect "modules-list" "$KP_CMD $SUPERKEY module list"
  collect "module-info" "$KP_CMD $SUPERKEY module info $MODULE"
else
  echo "MISS    modules-list（未提供 SUPERKEY）" | tee "$DEST/modules-list.txt"
fi

cat > "$DEST/README.md" <<EOF
# 升级证据：$MODULE / $BUILD_ID

- 采集时间：$STAMP
- 采集工具：\`Tester/tools/collect_evidence.sh\`
- 流程：\`docs/process/07-escalation-device.md\`
- 升级单模板：\`docs/templates/escalation.md\`

## 文件清单

| 文件 | 内容 | 采集结果 |
| --- | --- | --- |
$(for f in "$DEST"/*.txt; do printf '| `%s` | | %s |\n' "$(basename "$f")" "$(head -c 40 "$f" | grep -q '^MISS' && echo 采不到 || echo 有内容)"; done)

## 未做（必须确认）

- [x] 未重复加载同一 \`.kpm\`
- [x] 未修改代码或偏移
- [x] 未刷机 / 未进 recovery / 未清 pstore
- [ ] 是否强制重启过设备：______（若重启过，写明时间，pstore 仍在）

## 下一步

1. 用 \`docs/templates/escalation.md\` 写升级单（本目录），补全现象与请求事项。
2. **通知维护者**（会话 @维护者，或提 issue），附本目录相对路径。
3. 在维护者裁决前不要继续测试。
EOF

echo
echo "证据目录：$DEST"
echo "下一步：写升级单并通知维护者（不要继续重试）"
