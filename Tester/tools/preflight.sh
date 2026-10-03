#!/usr/bin/env bash
# 真机预检：采集环境事实与加载前基线，落盘供实机报告引用。
#
#   export SUPERKEY=<superkey>
#   bash Tester/tools/preflight.sh
#
# 约定:
#   * 每个 adb/fastboot 调用都有硬超时（run_to），不会挂住；
#   * 设备序列号只落 sha256 前 8 位，明文不写文件；
#   * 预检失败（设备离线 / superkey 错误 / 无 truncate）属测试环境问题，不要进入功能测试；
#   * 采不到的项必须写明原因（C7），不允许留空。
#
# 规则来源: docs/process/tester-handbook.md 2/3.2、docs/process/02-roles.md Tester 授权表 A1/C4/C7

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

ADB="${ADB:-adb}"
FASTBOOT="${FASTBOOT:-fastboot}"
TIMEOUT="${TIMEOUT:-15}"
OUTDIR="${OUTDIR:-Tester/reports/environments}"
KP_CMD="${KP_CMD:-truncate}"
SUPERKEY="${SUPERKEY:-}"

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}
stamp() { date +%Y-%m-%dT%H:%M:%S%z; }

# 便携超时执行（macOS 无 timeout 命令）；超时统一返回 124
run_to() {
  local t="$1"; shift
  local flag; flag="$(mktemp "${TMPDIR:-/tmp}/run_to.XXXXXX")"
  "$@" &
  local pid=$!
  ( sleep "$t"; if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid" 2>/dev/null; printf x > "$flag"; fi ) &
  local wd=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  [ -s "$flag" ] && rc=124
  rm -f "$flag"
  return $rc
}

fail() { echo "preflight: $*" >&2; exit 2; }

run_to 5 "$ADB" version >/dev/null 2>&1 || fail "adb 不可用（$ADB version 失败）"
SERIAL="$(run_to 8 "$ADB" get-serialno 2>/dev/null)"
SERIAL="${SERIAL//$'\r'/}"; SERIAL="${SERIAL//$'\n'/}"
[ -n "$SERIAL" ] && [ "$SERIAL" != "unknown" ] || fail "拿不到设备序列号（设备未连接或未授权）"
FP="$(printf '%s' "$SERIAL" | sha256_hex | cut -c1-8)"
unset SERIAL

# 去 \r 用参数展开，不走管道（管道会吞掉 run_to 的超时返回码）
dev() {
  local out rc
  out="$(run_to "$TIMEOUT" "$ADB" shell "$1" 2>/dev/null)"; rc=$?
  printf '%s' "${out//$'\r'/}"
  return $rc
}
dev_root() {
  local out rc
  out="$(run_to "$TIMEOUT" "$ADB" shell "su -c '$1'" 2>/dev/null)"; rc=$?
  printf '%s' "${out//$'\r'/}"
  return $rc
}

KERNEL="$(dev 'uname -r')"
UNAME_A="$(dev 'uname -a')"
MODEL="$(dev 'getprop ro.product.model')"
FINGERPRINT="$(dev 'getprop ro.build.fingerprint')"
RELEASE="$(dev 'getprop ro.build.version.release')"
PATCH="$(dev 'getprop ro.build.version.security_patch')"
SELINUX="$(dev 'getenforce')"
UPTIME="$(dev 'cat /proc/uptime')"
BTIME="$(dev 'cat /proc/stat | grep btime')"

# C4 基线：boot_id / uptime / pstore 残留 / 已加载模块
BOOTID="$(dev 'cat /proc/sys/kernel/random/boot_id')"
BOOTID_SRC="直接读取"
if [ -z "$BOOTID" ]; then
  BOOTID="$(dev_root 'cat /proc/sys/kernel/random/boot_id')"
  BOOTID_SRC="su -c 回退"
fi
[ -n "$BOOTID" ] || BOOTID_SRC="采不到（直接读取与 su -c 都失败：可能无 su 权限或路径不可读）"

PSTORE_LIST="$(dev 'ls -A /sys/fs/pstore/ 2>&1')"
if printf '%s' "$PSTORE_LIST" | grep -Eq 'Permission denied'; then
  PSTORE_LIST="$(dev_root 'ls -A /sys/fs/pstore/ 2>&1')"
fi
if printf '%s' "$PSTORE_LIST" | grep -Eq 'Permission denied|No such file|not found'; then
  PSTORE_STATE="采不到（${PSTORE_LIST}）"
elif [ -n "$(printf '%s' "$PSTORE_LIST" | tr -d '[:space:]')" ]; then
  PSTORE_STATE="**有残留**：$PSTORE_LIST —— 有旧崩溃残留在场，C4 要求先停下问维护者，不要加载"
else
  PSTORE_STATE="空（无旧崩溃残留）"
fi

CRASH_RECENT="$(dev "dmesg | grep -E 'Unable to handle kernel|Kernel panic|BUG:|Call trace|watchdog|lockup' | tail -n 20")"
if [ -z "$(printf '%s' "$CRASH_RECENT" | tr -d '[:space:]')" ]; then
  CRASH_RECENT_STATE="未观察到崩溃特征（弱证据：日志可能在 panic 中丢失）"
else
  CRASH_RECENT_STATE="**观察到**（弱证据，但出现即按 07 升级）"
fi

MODULES=""
KPVER=""
KP_PATH="未使用（未提供 SUPERKEY 且未找到 Manager UID）"
MODULES_OK=0
MANAGER_UID=""
if [ -z "$SUPERKEY" ]; then
  MANAGER_PKG="$(dev "pm list packages -U 2>/dev/null | grep -E 'me\.bmax\.apatch'")"
  MANAGER_UID="$(printf '%s' "$MANAGER_PKG" | grep -oE 'uid:[0-9]+' | cut -d: -f2)"
fi

if [ -n "$SUPERKEY" ]; then
  MODULES="$(dev "$KP_CMD $SUPERKEY module list")"
  KP_PATH="$KP_CMD <superkey> module list（直接执行）"
  [ -n "$MODULES" ] || { MODULES="$(dev_root "$KP_CMD $SUPERKEY module list")"; KP_PATH="${KP_CMD}（su -c 回退）"; }
  if [ -n "$MODULES" ]; then MODULES_OK=1; else
    MODULES="采不到（$KP_CMD 无输出，且 su -c 回退也无输出：检查 superkey 与 $KP_CMD 是否存在/可执行）"
    KP_PATH="$KP_CMD 直接执行与 su -c 回退均失败"
  fi
  KPVER="$(dev "$KP_CMD $SUPERKEY kpver")"
  [ -n "$KPVER" ] || KPVER="$(dev "$KP_CMD $SUPERKEY version")"
  [ -n "$KPVER" ] || KPVER="采不到（$KP_CMD kpver/version 无输出）"
elif [ -n "$MANAGER_UID" ]; then
  MODULES="$(dev_root "su $MANAGER_UID -c '/data/adb/ap/bin/kpatch su kpm list'")"
  KP_PATH="kpatch su kpm list（Manager UID $MANAGER_UID 免密通道）"
  if [ -n "$MODULES" ]; then MODULES_OK=1; else
    MODULES="采不到（Manager UID $MANAGER_UID 执行 kpatch 无输出）"
  fi
  KPVER="$(dev_root "su $MANAGER_UID -c '/data/adb/ap/bin/kpatch su kpver'")"
  [ -n "$KPVER" ] || KPVER="采不到（kpatch kpver 无输出）"
fi

FB_STATE="$(run_to 8 "$FASTBOOT" devices 2>/dev/null || true)"
FB_STATE="$(printf '%s' "$FB_STATE" | tr -d '\r')"
[ -n "$(printf '%s' "$FB_STATE" | tr -d '[:space:]')" ] || FB_STATE="无 fastboot 设备在列（正常：设备当前在 adb 模式）"

SCRIPT_SHA="$(sha256_hex < "${BASH_SOURCE[0]}")"

mkdir -p "$OUTDIR"
STAMP="$(date +%F)"
OUT="$OUTDIR/${STAMP}-${FP}.md"

cat > "$OUT" <<EOF
# 真机环境事实：${STAMP}（设备指纹 ${FP}）

> 由 \`Tester/tools/preflight.sh\` 生成（脚本 \`sha256=$SCRIPT_SHA\`）。序列号只保留 \`sha256(serial)[:8]\`，明文不落盘。
> **弱证据**（dmesg 类）只能写"未观察到"，不能写"没有发生"；**采不到**必须写明原因（C7）。

## 身份指纹

| 项 | 值 |
| --- | --- |
| 设备指纹哈希 | \`sha256(serial)[:8] = $FP\` |
| 采集时间 | $(stamp) |

## 环境事实

| 项 | 值 |
| --- | --- |
| 内核 | \`$KERNEL\` |
| 机型 | \`$MODEL\` |
| 系统版本 / 补丁级别 | \`$RELEASE\` / \`$PATCH\` |
| 构建指纹 | \`$FINGERPRINT\` |
| SELinux | \`$SELINUX\` |
| KernelPatch | \`$KPVER\` |
| 特权路径 | \`$KP_PATH\` |
| 已加载模块 | \`$MODULES\` |
| 采样时 uptime | \`$UPTIME\` |
| \`/proc/stat\` btime | \`$BTIME\` |
| fastboot 状态 | \`$FB_STATE\` |
| uname -a | \`$UNAME_A\` |

## 加载前基线（C4，缺一项就不许加载）

| 项 | 值 | 采集结果 |
| --- | --- | --- |
| boot_id | \`$BOOTID\` | $BOOTID_SRC |
| uptime | \`$UPTIME\` | $( [ -n "$UPTIME" ] && echo 已采集 || echo 采不到 ) |
| pstore 残留 | — | $PSTORE_STATE |
| 近期崩溃特征（dmesg，弱） | — | $CRASH_RECENT_STATE |

## 预检结论

- [x] adb 可用、设备已授权
- [$( [ -n "$KERNEL" ] && [ -n "$MODEL" ] && echo x || echo ' ' )] 拿到内核版本与机型
- [$( [ -n "$BOOTID" ] && [ -n "$UPTIME" ] && echo x || echo ' ' )] 基线可用（boot_id + uptime）
- [$( [ "$PSTORE_STATE" = "空（无旧崩溃残留）" ] && echo x || echo ' ' )] pstore 干净
- [$( [ "$MODULES_OK" -eq 1 ] && echo x || echo ' ' )] 特权通道可用（已获取已加载模块列表）

> 预检失败（离线 / KP 通道异常 / 基线缺失）属**测试环境问题**，不是产品缺陷；先修环境再测。
> 未获得特权通道时功能测试不可执行（A3），按 A6 记为「未执行」，不算失败，但必须写进报告的未覆盖清单。
EOF

echo "preflight: OK"
echo "环境事实已写入 $OUT"
echo "设备指纹：$FP  内核：$KERNEL  SELinux：$SELINUX"
echo "基线：boot_id=[$BOOTID] uptime=[$UPTIME] pstore=[$PSTORE_STATE]"
[ -n "$SUPERKEY" ] || echo "提示：未设置 SUPERKEY，无法读取模块清单（功能测试会因缺 superkey 退出码 2）"
exit 0
