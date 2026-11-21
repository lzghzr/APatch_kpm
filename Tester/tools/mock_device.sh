#!/usr/bin/env bash
# 离线 mock 设备：模拟 adb / fastboot 的行为，供 Tester 工具自检使用。
#
#   export MOCK_DIR=<状态目录>          # 必填：保存 loaded/uptime 等模拟状态
#   export MOCK_SCEN=<场景名>           # 默认 ok
#   ln -sf mock_device.sh adb ; ln -sf mock_device.sh fastboot
#
# 场景:
#   ok            一切正常
#   load_fail     加载输出 unknown symbol（AUD-001 形态，退出码 1）
#   load_fail_255 加载返回 255（TST-002 内核 -EINVAL CLI 退出码，属判据 FAIL，退出码 1）
#   load_timeout  加载命令超时返回 124（看门狗超时，退出码 90）
#   load_sigkill  加载命令被 SIGKILL 杀死返回 137（真实信号，退出码 90）
#   load_sigterm  加载命令被 SIGTERM 杀死返回 143（真实信号，退出码 90）
#   unload_fail   unload 报 not found 且模块仍在列表
#   crash         加载后 dmesg 出现 Call trace
#   reboot        加载后 boot_id 变化（软重启）
#   hang          所有 adb shell 无响应（看门狗应触发退出码 90）
#   hang_late     加载成功之后才无响应（用于验证 A2「基线已记录才允许一次 adb reboot」）
#   pstore_dirty  加载前 pstore 已有旧崩溃残留（应退出码 3，且不加载）
#   already_loaded 加载前模块已在运行（MNT-022：应退出码 3 且不卸载不继续）
#   list_fail     模块列表读取失败（MNT-022：应退出码 3 且不加载）
#   reject_old_record dmesg 中有本次启动曾成功加载记录（MNT-022：拒载拦截应退出码 3）
#   reject_truncated dmesg 被截断未包含启动起点（MNT-022：历史不明应退出码 3）
#   reject_clean_ok  干净启动且从未加载，拒载返回明确内核错误码（MNT-022：拒载通过退出码 0）
#   reject_clean_fail_unknown_sym 干净启动但错误仅为 unknown symbol（MNT-022：符号缺陷不作通过退出码 1）
#   reject_clean_fail_nodots 干净启动，load 失败但无诊断信息（MNT-022：不可把任意失败算通过退出码 1）
#   reject_post_list_fail 干净启动，load 报错但后置 list 查询失败（MNT-022：list 查询错误不可当不存在，退出码 1）
#   nomount_reject_clean_ok NoMount 真实拒载正例，窗口日志出现专用诊断（MNT-022：退出码 0）
#   reject_cli_95_no_diag 错误码与专用诊断不匹配，CLI 返回 -95 无专用诊断（MNT-022：退出码 1）
#   reject_old_dmesg_diag 旧日志相同诊断不在本次窗口（MNT-022：退出码 1）
#   reject_pre_dmesg_fail 拒载前内核日志读取失败（MNT-022：退出码 3）
#   reject_post_dmesg_fail 拒载后观察期内核日志读取失败（MNT-022：退出码 1）
#   resident_fail 加载后首次查询在场，后续查询消失（验证常驻存活独立取证，退出码 1）
#   resident_list_fail 加载后首次查询在场，后续查询失败（验证后续查询失败不作空表，退出码 1）
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
  local now=100
  [ -f "$UP" ] && now="$(cat "$UP")"
  if [ "$SCEN" = crash ] && [ -f "$DIR/loaded" ]; then
    echo "[   $now.123456] Call trace:"
    echo "[   $now.123457]  mock_crash+0x1c/0x40"
  elif [ "$SCEN" = reject_truncated ]; then
    echo "[  850.123456] mock truncated dmesg buffer"
  elif [ "$SCEN" = reject_old_record ]; then
    echo "[    0.000000] Linux version 4.14.356-mock"
    echo "[    1.234567] [${MOCK_MODULE:-re_kernel}] succeed with [base]"
    echo "[    1.234568] load AP KPM: ${MOCK_MODULE:-re_kernel} (rc: 0)"
  elif [ "$SCEN" = reject_old_dmesg_diag ]; then
    echo "[    0.000000] Linux version 4.14.356-mock clean boot"
    echo "[    1.234567] ${MOCK_RUNNING_MODULE:-${MOCK_MODULE:-NoMount}}: static baseline is unconfigured ... refusing to load (-22)"
  elif [ "$SCEN" = nomount_reject_clean_ok ] && [ -f "$DIR/last_load_cmd" ]; then
    echo "[    0.000000] Linux version 4.14.356-mock clean boot"
    echo "[   $now.123456] ${MOCK_RUNNING_MODULE:-${MOCK_MODULE:-NoMount}}: static baseline is unconfigured ... refusing to load (-22)"
  elif [ "$SCEN" = reject_clean_ok ] && [ -f "$DIR/last_load_cmd" ]; then
    echo "[    0.000000] Linux version 4.14.356-mock clean boot"
    echo "[   $now.123456] ${MOCK_MODULE:-re_kernel}: module reject error: -22"
  else
    echo "[    0.000000] Linux version 4.14.356-mock clean boot"
    echo "[    0.000001] mock dmesg clean"
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
  printf '%s\n' "$s" >> "$DIR/cmd_history.log"
  [ "$SCEN" = hang ] && exec sleep 999
  [ "$SCEN" = hang_late ] && [ -f "$DIR/loaded" ] && exec sleep 999

  case "$s" in
    "echo ok") echo ok; return 0 ;;
    *"random/boot_id"*) boot_now; return 0 ;;
    *"/proc/uptime"*) up_next; return 0 ;;
    *"dmesg -c"*) return 0 ;;
    *"ls -A /sys/fs/pstore"*) pstore_list; return 0 ;;
    *"cat /sys/fs/pstore"*) echo "mock pstore dump"; return 0 ;;
    *"pm list packages"*)
      if [ "$SCEN" = "no_privilege" ]; then return 0; fi
      echo "package:me.bmax.apatch uid:10234"; return 0 ;;
    *"su hello"*) echo "hello1158"; return 0 ;;
    *"kpm list"*|*"module list"*)
      if [ "$SCEN" = list_fail ] || { [ "$SCEN" = reject_post_list_fail ] && [ -f "$DIR/last_load_cmd" ]; }; then
        echo "failed to query module list: kernel interface error"
        return 1
      fi
      if [ "$SCEN" = resident_list_fail ] && [ -f "$DIR/loaded_first_seen" ]; then
        echo "failed to query module list: kernel interface error"
        return 1
      fi
      if [ "$SCEN" = resident_fail ] && [ -f "$DIR/loaded_first_seen" ]; then
        return 0
      fi
      if [ "$SCEN" = already_loaded ] || [ -f "$DIR/loaded" ]; then
        { [ "$SCEN" = resident_fail ] || [ "$SCEN" = resident_list_fail ]; } && : > "$DIR/loaded_first_seen"
        echo "${MOCK_RUNNING_MODULE:-${MOCK_MODULE:-re_kernel}} mock-version"
      fi
      return 0 ;;
    *"kpm unload"*|*"module unload"*)
      if [ "$SCEN" = unload_fail ]; then echo "unload failed: module not found"; return 1; fi
      rm -f "$DIR/loaded"; echo "unload ok"; return 0 ;;
    *"kpm load"*|*"module load"*)
      printf '%s\n' "$s" > "$DIR/last_load_cmd"
      if [ "$SCEN" = load_fail ]; then echo "unknown symbol: kf_get_task_ext"; return 1; fi
      if [ "$SCEN" = reject_clean_ok ] || [ "$SCEN" = reject_post_list_fail ] || [ "$SCEN" = nomount_reject_clean_ok ] || [ "$SCEN" = reject_post_dmesg_fail ]; then
        echo "failed with (null) error: -22"
        return 255
      fi
      if [ "$SCEN" = reject_cli_95_no_diag ] || [ "$SCEN" = reject_old_dmesg_diag ]; then
        echo "failed with (null) error: -95"
        return 255
      fi
      if [ "$SCEN" = reject_clean_fail_unknown_sym ]; then
        echo "unknown symbol: kf_get_task_ext"
        return 1
      fi
      if [ "$SCEN" = reject_clean_fail_nodots ]; then
        echo "generic abort code 1"
        return 1
      fi
      if [ "$SCEN" = load_fail_255 ]; then echo "failed with (null) error: -22"; return 255; fi
      if [ "$SCEN" = load_timeout ]; then return 124; fi
      if [ "$SCEN" = load_sigkill ]; then return 137; fi
      if [ "$SCEN" = load_sigterm ]; then return 143; fi
      : > "$DIR/loaded"; echo "load ok"; return 0 ;;
    *"kpm info"*|*"module info"*) echo "${MOCK_MODULE:-re_kernel} mock-version mock"; return 0 ;;
    *dmesg*)
      if [ "$SCEN" = reject_pre_dmesg_fail ] && [ ! -f "$DIR/last_load_cmd" ]; then
        echo "dmesg: read error: Permission denied" >&2
        return 1
      fi
      if [ "$SCEN" = reject_post_dmesg_fail ] && [ -f "$DIR/last_load_cmd" ]; then
        echo "dmesg: read error: internal hardware fault" >&2
        return 1
      fi
      dmesg_text; return 0 ;;
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
  printf 'fastboot %s\n' "$*" >> "$DIR/cmd_history.log"
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
  push) printf 'adb push %s %s\n' "${2:-}" "${3:-}" >> "$DIR/cmd_history.log"; exit 0 ;;
  reboot) printf 'adb reboot\n' >> "$DIR/cmd_history.log"; exit 0 ;;
  shell) shift; shell_dispatch "$*"; exit $? ;;
  *) echo "mock-adb: 未实现: ${1:-}" >&2; exit 0 ;;
esac
