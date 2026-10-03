#!/usr/bin/env bash
# 离线 mock 设备：模拟 adb / fastboot 的行为，供 Tester 工具自检使用。
#
#   export MOCK_DIR=<状态目录>          # 必填：保存 loaded/uptime 等模拟状态
#   export MOCK_SCEN=<场景名>           # 默认 ok
#   ln -sf mock_device.sh adb ; ln -sf mock_device.sh fastboot
#
# 场景:
#   ok            一切正常
#   load_fail     加载输出 unknown symbol（AUD-001 形态）
#   unload_fail   unload 报 not found 且模块仍在列表
#   crash         加载后 dmesg 出现 Call trace
#   reboot        加载后 boot_id 变化（软重启）
#   hang          所有 adb shell 无响应（看门狗应触发退出码 90）
#   hang_late     加载成功之后才无响应（用于验证 A2「基线已记录才允许一次 adb reboot」）
#   pstore_dirty  加载前 pstore 已有旧崩溃残留（应退出码 3，且不加载）
#
# 这不是真机结论（C2）：mock 只验证脚本逻辑、分支与退出码；真机行为必须在设备上复验。

set -uo pipefail

NAME="$(basename "$0")"
DIR="${MOCK_DIR:?缺少 MOCK_DIR}"
SCEN="${MOCK_SCEN:-ok}"
mkdir -p "$DIR"
UP="$DIR/uptime"

up_next() {
  local v=100
  [ -f "$UP" ] && v="$(cat "$UP")"
  v=$((v+7))
  printf '%s' "$v" > "$UP"
  printf '%s.00' "$v"
}

boot_now() {
  if [ "$SCEN" = reboot ] && [ -f "$DIR/loaded" ]; then echo "boot-new-2222"; else echo "boot-old-1111"; fi
}

dmesg_text() {
  if [ "$SCEN" = crash ] && [ -f "$DIR/loaded" ]; then
    echo "[   12.345678] Call trace:"
    echo "[   12.345679]  mock_crash+0x1c/0x40"
  else
    echo "[    0.000000] mock dmesg clean"
  fi
}

pstore_list() {
  if [ "$SCEN" = pstore_dirty ] && [ ! -f "$DIR/loaded" ]; then
    echo "console-ramoops-0"
  fi
}

shell_dispatch() {
  local s="$1"
  case "$s" in
    su\ -c\ *) s="${s#su -c }"; s="${s#\'}"; s="${s%\'}" ;;
  esac
  [ "$SCEN" = hang ] && exec sleep 999
  [ "$SCEN" = hang_late ] && [ -f "$DIR/loaded" ] && exec sleep 999

  case "$s" in
    "echo ok") echo ok; return 0 ;;
    *"random/boot_id"*) boot_now; return 0 ;;
    *"/proc/uptime"*) up_next; return 0 ;;
    *"dmesg -c"*) return 0 ;;
    *"ls -A /sys/fs/pstore"*) pstore_list; return 0 ;;
    *"cat /sys/fs/pstore"*) echo "mock pstore dump"; return 0 ;;
    *"module list"*) [ -f "$DIR/loaded" ] && echo "${MOCK_MODULE:-re_kernel} mock-version"; return 0 ;;
    *"module unload"*)
      if [ "$SCEN" = unload_fail ]; then echo "unload failed: module not found"; return 1; fi
      rm -f "$DIR/loaded"; echo "unload ok"; return 0 ;;
    *"module load"*)
      if [ "$SCEN" = load_fail ]; then echo "unknown symbol: kf_get_task_ext"; return 1; fi
      : > "$DIR/loaded"; echo "load ok"; return 0 ;;
    *"module info"*) echo "${MOCK_MODULE:-re_kernel} mock-version mock"; return 0 ;;
    *dmesg*) dmesg_text; return 0 ;;
    *kpver*|*" version"*) echo "0.13.9-mock"; return 0 ;;
    *"uname -r"*) echo "4.14.356-mock"; return 0 ;;
    *"uname -a"*) echo "Linux localhost 4.14.356-mock aarch64 GNU/Linux"; return 0 ;;
    *"ro.product.model"*) echo "MOCK-MODEL"; return 0 ;;
    *"ro.build.fingerprint"*) echo "mock/mock/mock:14/MOCK/1:user/release-keys"; return 0 ;;
    *"ro.build.version.release"*) echo "14"; return 0 ;;
    *"ro.build.version.security_patch"*) echo "2024-01-01"; return 0 ;;
    *getenforce*) echo Enforcing; return 0 ;;
    *btime*) echo "btime 1700000000"; return 0 ;;
  esac
  echo "mock: 未实现: $s" >&2
  return 0
}

if [ "$NAME" = "fastboot" ]; then
  case "${1:-}" in
    devices) [ -f "$DIR/fb" ] && printf 'MOCKFB\tfastboot\n' ;;
    getvar) echo "MOCKFB" ;;
    reboot) : ;;
  esac
  exit 0
fi

case "${1:-}" in
  version) echo "Android Debug Bridge version 1.0.41-mock"; exit 0 ;;
  get-serialno) echo "MOCKDEVICE0001"; exit 0 ;;
  devices) printf 'List of devices attached\nMOCKDEVICE0001\tdevice\n'; exit 0 ;;
  push) exit 0 ;;
  reboot) exit 0 ;;
  shell) shift; shell_dispatch "$*"; exit $? ;;
  *) echo "mock-adb: 未实现: ${1:-}" >&2; exit 0 ;;
esac
