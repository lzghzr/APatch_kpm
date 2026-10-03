#!/usr/bin/env bash
# 真机功能测试（带看门狗）：加载一个 KPM 变体、跑判据、卸载。
#
#   export SUPERKEY=<superkey>
#   bash Tester/tools/run_test.sh --kpm artifacts/<instance_id>/re_kernel_8.0.0.kpm \
#        --module re_kernel --timeout 120 [--observe 60] [--tool-freeze-commit <完整 SHA>]
#        --instance-id '<build_id>#<n>' [--recover]
#
# 退出码:
#   0  判据通过                1  判据失败（设备仍可用，归属待判）
#   2  用法/环境错误            3  前置条件未满足（pstore 残留 / 基线采不到）→ 需维护者裁决
#   90 设备无响应 / 崩溃 / 重启（走升级流程，零重试）
#
# 规则来源:
#   docs/process/07-escalation-device.md      升级流程（停止重试、保现场、采集证据）
#   docs/process/tester-handbook.md 3.1~3.3   证据强度 / 加载前基线 / 判据脚本绑定
#   docs/process/02-roles.md Tester 授权表    A1 设备白名单、A2 至多一次 adb reboot、C1/C4/C5
#
# 环境变量: ADB / KP_CMD / SUPERKEY / TIMEOUT / OBSERVE / POLL
#   （POLL 是观察轮询间隔，默认 10s；离线自检用它加速）

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2

KPM=""
MODULE=""
INSTANCE_ID="${INSTANCE_ID:-}"
TOOL_FREEZE_COMMIT="${TOOL_FREEZE_COMMIT:-}"
TIMEOUT="${TIMEOUT:-30}"
OBSERVE="${OBSERVE:-60}"
POLL="${POLL:-10}"
ADB="${ADB:-adb}"
KP_CMD="${KP_CMD:-truncate}"
SUPERKEY="${SUPERKEY:-}"
RECOVER=0
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

while [ $# -gt 0 ]; do
  case "$1" in
    --kpm) KPM="$2"; shift 2 ;;
    --module) MODULE="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --observe) OBSERVE="$2"; shift 2 ;;
    --instance-id) INSTANCE_ID="$2"; shift 2 ;;
    --tool-freeze-commit) TOOL_FREEZE_COMMIT="$2"; shift 2 ;;
    --recover) RECOVER=1; shift ;;
    *) echo "用法: run_test.sh --kpm <path> --module <name> [--timeout N] [--observe N] [--tool-freeze-commit SHA] [--instance-id ID] [--recover]" >&2; exit 2 ;;
  esac
done

[ -n "$KPM" ] || { echo "缺少 --kpm" >&2; exit 2; }
[ -n "$MODULE" ] || { echo "缺少 --module" >&2; exit 2; }
[ -f "$KPM" ] || { echo "产物不存在: $KPM" >&2; exit 2; }
[ -n "$INSTANCE_ID" ] || { echo "缺少 --instance-id（必须是 metadata 在册的 instance_id，形如 <build_id>#<n>）" >&2; exit 2; }
[ -n "$SUPERKEY" ] || { echo "缺少 SUPERKEY（环境变量），无法加载模块" >&2; exit 2; }

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}
stamp() { date +%Y-%m-%dT%H:%M:%S%z; }

# 看门狗：超时被杀统一返回 124（与 timeout(1) 约定一致）
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

# 返回码必须透传：用参数展开去 \r，不能走管道（管道会把 run_to 的超时返回码吞成 0）
adb_out() {
  local cmd="$1" out rc
  out="$(run_to "$TIMEOUT" "$ADB" shell "$cmd" 2>/dev/null)"
  rc=$?
  printf '%s' "${out//$'\r'/}"
  return $rc
}

# 超时判定：124 = 看门狗杀死；>=128 = 进程被信号终结（看门狗兜底，防止标记失效）
timed_out() { [ "$1" -eq 124 ] 2>/dev/null || [ "$1" -ge 128 ] 2>/dev/null; }

FAIL_PAT='unknown symbol|hook .* error|error:|Error|failed|Failed|not found|No such file|Permission denied|Operation not permitted|Invalid argument|denied'
fail_text() { printf '%s' "$1" | grep -Eq "$FAIL_PAT"; }

# ---------------------------------------------------------------- 候选身份绑定（MNT-008）
# 加载入口必须绑定"在册实例"：instance_id 能在 metadata 里找到，且产物字节哈希与登记一致。
# 这里直接解析登记 JSON（只读），刻意不调用维护者/实现方脚本，保持 Tester 侧独立。
BLOB_SHA="$(sha256_hex < "$KPM")"
RECORD="metadata/modules/${MODULE}.json"
[ -f "$RECORD" ] || { echo "找不到模块登记记录: $RECORD" >&2; exit 2; }
IDENT="$(python3 - "$RECORD" "$INSTANCE_ID" "$BLOB_SHA" <<'PY'
import hashlib, json, sys
path, want, blob = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    raw = open(path, "rb").read()
    rec = json.loads(raw.decode("utf-8"))
except Exception as exc:
    print("ERR|登记记录无法解析: %s" % exc); raise SystemExit(0)
builds = rec.get("builds", [])
hit = None
for b in builds:
    aliases = b.get("build_id_aliases") or []
    if want in {b.get("instance_id"), b.get("build_id")} or want in aliases:
        hit = b; break
if hit is None:
    cand = ", ".join(sorted({b.get("instance_id") or "?" for b in builds})) or "（无）"
    print("ERR|instance_id 不在册: %s ; 在册候选: %s" % (want, cand)); raise SystemExit(0)
hashes = [a.get("sha256") for a in hit.get("artifacts", []) if a.get("sha256")]
if blob not in hashes:
    print("ERR|产物哈希与登记不一致: 文件 sha256=%s ; 登记=%s" % (blob, ", ".join(hashes))); raise SystemExit(0)
record_sha = hashlib.sha256(raw).hexdigest()
print("OK|%s|%s|%s|%s" % (hit.get("instance_id") or "", hit.get("source_commit") or "",
                           hit.get("build_id") or "", record_sha))
PY
)"
case "$IDENT" in
  ERR*) echo "run_test: ${IDENT#ERR|}" >&2; exit 2 ;;
  OK*) : ;;
  *) echo "run_test: 身份核对异常（python3 输出: ${IDENT}）" >&2; exit 2 ;;
esac
IFS='|' read -r _ REG_INSTANCE REG_SOURCE_COMMIT REG_BUILD_ID REGISTRY_SHA <<<"$IDENT"

SCRIPT_SHA="$(sha256_hex < "${BASH_SOURCE[0]}")"
TOOL_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
TOOL_FREEZE_COMMIT="${TOOL_FREEZE_COMMIT:-$TOOL_COMMIT}"
TOOL_FREEZE_RC=0
TOOL_FREEZE_JSON="$(bash Tester/tools/instrument_frozen.sh --repo "$REPO" \
  --frozen-commit "$TOOL_FREEZE_COMMIT" --json 2>/dev/null)" || TOOL_FREEZE_RC=$?
TOOL_FREEZE_RESULT="$(python3 - "$TOOL_FREEZE_JSON" "$TOOL_FREEZE_RC" <<'PY'
import json, re, sys
raw, rc = sys.argv[1], int(sys.argv[2])
try:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("JSON root is not an object")
    commit = data.get("frozen_commit") or "unresolved"
    set_hash = data.get("instrument_set_sha256") or "unavailable"
    paths = data.get("instrument_paths") or []
    reasons = data.get("reasons") or []
    if not isinstance(paths, list) or not isinstance(reasons, list):
        raise ValueError("invalid result fields")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        commit = "unresolved"
    if not re.fullmatch(r"[0-9a-f]{64}", set_hash):
        set_hash = "unavailable"
    frozen = data.get("frozen") is True and rc == 0 and commit != "unresolved" and set_hash != "unavailable"
    reason = "；".join(str(item).replace("\t", " ").replace("\n", " ") for item in reasons)
    if not frozen and not reason:
        reason = "冻结核验失败或 helper 结果不完整"
    path_text = " ".join(str(item).replace("\t", " ") for item in paths) or "unavailable"
    reason = reason or ("冻结核验通过" if frozen else "冻结核验失败")
    print("\t".join(("YES" if frozen else "NO", commit, set_hash, path_text, reason)))
except Exception as exc:
    print("\t".join(("NO", "unresolved", "unavailable", "unavailable", f"冻结结果解析失败: {exc}")))
PY
)"
IFS=$'\t' read -r TOOL_FROZEN_FLAG TOOL_FREEZE_COMMIT TOOL_INSTRUMENT_SHA TOOL_INSTRUMENT_PATHS TOOL_FREEZE_REASON <<<"$TOOL_FREEZE_RESULT"
if [ "$TOOL_FROZEN_FLAG" = "YES" ]; then
  TOOL_FROZEN="是"
else
  TOOL_FROZEN="否（${TOOL_FREEZE_REASON:-冻结核验失败}）"
fi

RUNDIR="${RUNDIR:-Tester/reports/runs}"
ESCDIR="${ESCDIR:-Tester/reports/escalations}"
mkdir -p "$RUNDIR" "$ESCDIR"
# 唯一运行 ID（MNT-008）：报告、日志、**升级单**共享同一 ID，三者都必须可用才采用该编号。
# 升级单必须参与占用检查：同一产物重跑时若升级目录已有同名现场，绝不允许覆盖它。
BASE_RUN_ID="$(date +%F)-${MODULE}-$(basename "$KPM" .kpm)"
N=1
while :; do
  RUN_ID="${BASE_RUN_ID}#${N}"
  LOG="$RUNDIR/${RUN_ID}.log"
  REPORT="$RUNDIR/${RUN_ID}.md"
  ESC="$ESCDIR/${RUN_ID}.md"
  if [ ! -e "$LOG" ] && [ ! -e "$REPORT" ] && [ ! -e "$ESC" ]; then
    if ( set -o noclobber; : > "$LOG" ) 2>/dev/null; then break; fi
  fi
  N=$((N+1))
  [ "$N" -le 999 ] || { echo "run_test: 同日同产物的运行编号已用尽（#1..#999），请先归档旧证据" >&2; exit 2; }
done

PSTORE_CLEAN=0
REBOOT_TRIED=0
BOOT0=""
UPTIME0=""

log() { echo "[$(stamp)] $*" | tee -a "$LOG"; }

log "候选身份 instance_id=${REG_INSTANCE}（在册）；产物 sha256=$BLOB_SHA 与登记一致"
log "候选 source_commit=${REG_SOURCE_COMMIT}；测试启动 HEAD=${TOOL_COMMIT}；工具冻结基线=${TOOL_FREEZE_COMMIT} 冻结=${TOOL_FROZEN}；仪器集合 sha256=${TOOL_INSTRUMENT_SHA}；判据脚本 sha256=${SCRIPT_SHA}；登记记录 sha256=${REGISTRY_SHA}"
log "本次运行 ID=${RUN_ID}（报告 ${REPORT}）"

# ---------------------------------------------------------------- 升级（退出码 90）
# $1 原因；$2 是否允许按 A2 尝试一次 adb reboot（仅"设备无响应"类允许）
escalate() {
  local reason="$1" allow_reboot="${2:-0}" reboots="未尝试（非无响应类，保现场）"
  if [ "$allow_reboot" -eq 1 ] && [ "$RECOVER" -eq 1 ]; then
    if [ "$PSTORE_CLEAN" -ne 1 ]; then
      reboots="未尝试：基线 pstore 未确认干净（A2 前置条件③）"
    elif [ "$REBOOT_TRIED" -eq 1 ]; then
      reboots="已尝试过 1 次（A2 只允许一次）"
    elif [ -z "$BOOT0" ]; then
      reboots="未尝试：基线未记录（A2 前置条件①）"
    else
      REBOOT_TRIED=1
      local rrc=0
      run_to 20 "$ADB" reboot >>"$LOG" 2>&1 || rrc=$?
      reboots="已尝试 1 次 adb reboot（A2）：rc=${rrc}；重启不清 pstore，请立即采集 pstore"
    fi
  fi
  echo "[$(stamp)] $reboots" | tee -a "$LOG"
  REPORT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

  # 原子占位后再写：占不到就顺延后缀，任何情况下都不覆盖已有升级单（MNT-008）
  local esc="$ESCDIR/${RUN_ID}.md" k=2
  while ! ( set -o noclobber; : > "$esc" ) 2>/dev/null; do
    esc="$ESCDIR/${RUN_ID}-${k}.md"
    k=$((k+1))
    [ "$k" -le 99 ] || { echo "run_test: 升级单路径无法占用，放弃写入以免覆盖旧证据: $ESCDIR/${RUN_ID}*" >&2; exit 90; }
  done
  {
    echo "# 真机异常升级单：$MODULE"
    echo
    echo "> 由 \`Tester/tools/run_test.sh\` 自动生成骨架，**必须**由 Tester 补全后通知维护者。"
    echo "> 流程：\`docs/process/07-escalation-device.md\`；模板：\`docs/templates/escalation.md\`"
    echo
    echo "## 身份三要素（最重要）"
    echo
    echo "| 项 | 值 |"
    echo "| --- | --- |"
    echo "| commit | \`$COMMIT\` |"
    echo "| instance_id（在册） | \`$REG_INSTANCE\` |"
    echo "| 候选 source_commit | \`$REG_SOURCE_COMMIT\` |"
    echo "| 工具冻结基线 commit | \`$TOOL_FREEZE_COMMIT\` |"
    echo "| 工具冻结状态 | $TOOL_FROZEN |"
    echo "| 报告生成 HEAD | \`$REPORT_HEAD\` |"
    echo "| 仪器路径 / 集合 sha256 | \`$TOOL_INSTRUMENT_PATHS\` / \`$TOOL_INSTRUMENT_SHA\` |"
    echo "| 模块登记记录 sha256 | \`$REGISTRY_SHA\` |"
    echo "| 产物 | \`$KPM\` |"
    echo "| 产物 SHA-256 | \`$BLOB_SHA\` |"
    echo "| 判据脚本 | \`Tester/tools/run_test.sh\` \`sha256=$SCRIPT_SHA\` |"
    echo
    echo "## 现象"
    echo
    echo "- 触发时间：$(stamp)"
    echo "- 触发原因：$reason"
    echo "- 自动处置：**已停止一切重试**（未重复加载、未改任何东西、未卸载模块）"
    echo
    echo "## 基线（加载前，C4）"
    echo
    echo "| 项 | 值 |"
    echo "| --- | --- |"
    echo "| boot_id | \`$BOOT0\` |"
    echo "| uptime | \`$UPTIME0\` |"
    echo "| pstore 基线 | \`$( [ "$PSTORE_CLEAN" -eq 1 ] && echo '空（无旧崩溃残留）' || echo '未确认' )\` |"
    echo
    echo "## 证据清单（待补全）"
    echo
    echo "| 证据 | 文件 | 采集结果 |"
    echo "| --- | --- | --- |"
    echo "| console-ramoops / pstore | | |"
    echo "| dmesg 尾部 | \`$LOG\` | 见日志 |"
    echo "| 模块列表 / info | | |"
    echo "| 设备环境事实 | \`Tester/reports/environments/\` | |"
    echo
    echo "## 需要维护者执行的物理动作（Tester 发起，A5）"
    echo
    echo "| 项 | 内容 |"
    echo "| --- | --- |"
    echo "| 动作 | 长按电源键强制重启 / 进 fastboot / 拔插 USB / 换机 / 其它 |"
    echo "| 为什么我做不了 | 无按键通道 / 设备无响应 / 需要人手在场 |"
    echo "| 已尝试的软件通道 | \`adb reboot\`：$reboots |"
    echo "| 期望结果 | 设备回到系统 / 进入 fastboot / 保持当前现场不动 |"
    echo "| 风险与不可逆性 | |"
    echo "| 发起时间 | $(stamp) |"
    echo
    echo "## 动作回执（由维护者执行后回填）"
    echo
    echo "| 项 | 内容 |"
    echo "| --- | --- |"
    echo "| 执行时间 | |"
    echo "| 实际动作 | |"
    echo "| 结果 | 成功 / 失败 / 部分 |"
    echo "| 设备状态 | 回到系统 / fastboot / 仍无响应 |"
    echo "| pstore 变化 | 残留 / 已清（若被清，说明是哪一步清的） |"
    echo "| 回执人 | 维护者 |"
    echo
    echo "## 请求维护者裁决"
    echo
    echo "- [ ] 是否继续用同一 instance_id 测试"
    echo "- [ ] 是否需要 Developer 介入"
    echo "- [ ] 设备恢复方式由谁决定"
  } >| "$esc"   # 写入本次已占位的文件（>| 显式覆盖我们自己刚占的空文件）

  echo "run_test: 设备异常（${reason}）" >&2
  echo "run_test: 已生成升级单 $esc —— 停止重试，请采集证据并通知维护者（见 docs/process/07-escalation-device.md）" >&2
  echo "run_test: 提示：bash Tester/tools/collect_evidence.sh --build-id <instance_id> --module $MODULE" >&2
  exit 90
}

# ---------------------------------------------------------------- 0. 前置：基线与预检
adb_alive() { adb_out 'echo ok' >/dev/null 2>&1; }

log "预检：设备响应"
if ! adb_alive; then
  log "首次 adb 探测无响应；按 07 阈值再确认一次（此时尚未加载，无崩溃风险）"
  adb_alive || escalate "adb 连续 2 次无响应" 1
fi

BOOT0="$(adb_out 'cat /proc/sys/kernel/random/boot_id')"
UPTIME0="$(adb_out 'cat /proc/uptime')"
PSTORE_RAW="$(adb_out 'ls -A /sys/fs/pstore/ 2>&1')"
BASE_LIST="$(adb_out "$KP_CMD $SUPERKEY module list")"

# pstore 基线判定：空 → 干净；有文件名 → 旧崩溃残留；含错误文本 → 未采集
if printf '%s' "$PSTORE_RAW" | grep -Eq 'Permission denied|No such file|not found|Error'; then
  log "pstore 基线**未采集**（${PSTORE_RAW}）；按 C4/A6 不进入加载"
  exit 3
elif [ -n "$(printf '%s' "$PSTORE_RAW" | tr -d '[:space:]')" ]; then
  log "pstore 基线**非空**（${PSTORE_RAW}）：有旧崩溃残留在场，先停下问维护者（C4）"
  exit 3
else
  PSTORE_CLEAN=1
fi

if [ -z "$BOOT0" ] || [ -z "$UPTIME0" ]; then
  log "基线缺失（boot_id='$BOOT0' uptime='$UPTIME0'）：无基线不许加载（C4/A6）"
  exit 3
fi
log "基线 boot_id=$BOOT0 uptime=$UPTIME0 pstore=空 已加载模块=[$BASE_LIST]"

if printf '%s' "$BASE_LIST" | grep -q "$MODULE"; then
  log "模块 $MODULE 已在运行，先卸载再测（不覆盖旧状态）"
  adb_out "$KP_CMD $SUPERKEY module unload $MODULE" | tee -a "$LOG"
fi

log "清空 dmesg（只在测试开始前清一次）"
run_to "$TIMEOUT" "$ADB" shell 'dmesg -c >/dev/null 2>&1 || true' >/dev/null 2>&1

# ---------------------------------------------------------------- 1. 推送并加载
REMOTE="/data/local/tmp/$(basename "$KPM")"
log "推送 $KPM -> $REMOTE"
run_to "$((TIMEOUT*3))" "$ADB" push "$KPM" "$REMOTE" >>"$LOG" 2>&1 || escalate "adb push 失败/超时（设备可能已无响应）" 1

log "加载模块"
LOAD_OUT="$(adb_out "$KP_CMD $SUPERKEY module load $REMOTE")"
LOAD_RC=$?
printf '%s\n' "$LOAD_OUT" | tee -a "$LOG"
timed_out "$LOAD_RC" && escalate "module load 超时未返回" 1

# ---------------------------------------------------------------- 2. 观察窗口（存活=强证据，dmesg=弱证据）
OBS_BOOT_SAME=1; OBS_UPTIME_MONO=1; OBS_CRASH=0; OBS_UNRESP=0
observe() {  # $1 阶段名（仅用于日志）
  local phase="$1" prev="${UPTIME0%% *}" elapsed=0 up rc cur boot dmesg
  OBS_UNRESP=0
  while [ "$elapsed" -lt "$OBSERVE" ]; do
    sleep "$POLL"; elapsed=$((elapsed+POLL))
    up="$(adb_out 'cat /proc/uptime')"; rc=$?
    if timed_out "$rc"; then
      OBS_UNRESP=$((OBS_UNRESP+1))
      [ "$OBS_UNRESP" -lt 2 ] || escalate "连续 ${OBS_UNRESP} 次 adb 超时（${phase}）" 1
      continue
    fi
    OBS_UNRESP=0
    boot="$(adb_out 'cat /proc/sys/kernel/random/boot_id')"
    if [ -n "$BOOT0" ] && [ -n "$boot" ] && [ "$boot" != "$BOOT0" ]; then
      escalate "检测到重启（boot_id 变化，${phase}）" 0
    fi
    cur="${up%% *}"
    if [ -n "$prev" ] && [ -n "$cur" ]; then
      if ! printf '%s\n%s\n' "$prev" "$cur" | awk 'NR==1{p=$1;next}{exit !($1+0>=p+0)}'; then
        OBS_UPTIME_MONO=0
        escalate "uptime 非单调（$prev -> ${cur}，疑似重启，${phase}）" 0
      fi
      prev="$cur"
    fi
    dmesg="$(adb_out 'dmesg | tail -n 200')"
    if printf '%s' "$dmesg" | grep -Eq 'Kernel panic|Unable to handle kernel|BUG:|Call trace'; then
      printf '%s\n' "$dmesg" >> "$LOG"
      OBS_CRASH=1
      break
    fi
  done
}

log "观察 ${OBSERVE}s（加载后）"
observe "加载后"
if [ "$OBS_CRASH" -eq 1 ]; then
  escalate "dmesg 出现崩溃特征（Call trace/panic/BUG）——出现即按 07 升级，保留现场不卸载" 0
fi

# 加载后的模块列表：这是"加载成功"判据的一部分，必须在卸载前取
LOADED_LISTED=0
printf '%s' "$(adb_out "$KP_CMD $SUPERKEY module list")" | grep -q "$MODULE" && LOADED_LISTED=1

# ---------------------------------------------------------------- 3. 卸载
log "卸载模块"
UNLOAD_OUT="$(adb_out "$KP_CMD $SUPERKEY module unload $MODULE")"
UNLOAD_RC=$?
printf '%s\n' "$UNLOAD_OUT" | tee -a "$LOG"
timed_out "$UNLOAD_RC" && escalate "module unload 超时未返回" 1

AFTER_LIST="$(adb_out "$KP_CMD $SUPERKEY module list")"
STILL_LISTED=0
printf '%s' "$AFTER_LIST" | grep -q "$MODULE" && STILL_LISTED=1

log "观察 ${OBSERVE}s（卸载后）"
OBS_CRASH=0
observe "卸载后"
if [ "$OBS_CRASH" -eq 1 ]; then
  escalate "dmesg 出现崩溃特征（卸载后）" 0
fi

# ---------------------------------------------------------------- 4. 判据
PASS=0; FAIL=0
declare -a RESULTS=()
judge() {  # judge <证据强度> <名称> <0/1>
  if [ "$3" -eq 0 ]; then RESULTS+=("PASS|$1|$2"); PASS=$((PASS+1));
  else RESULTS+=("FAIL|$1|$2"); FAIL=$((FAIL+1)); fi
}

# 存活判据：两个观察窗口内无 adb 连续超时、boot_id 不变、uptime 单调
# （任一不成立时 observe()/escalate() 已经以 90 退出；能走到这里即成立）
judge "强" "设备存活（整轮：adb 持续响应 + boot_id 不变 + uptime 单调）" "$( [ "$OBS_BOOT_SAME" -eq 1 ] && [ "$OBS_UPTIME_MONO" -eq 1 ] && echo 0 || echo 1 )"
judge "强" "加载成功（rc=0 且无失败特征 且 module list 出现模块）" "$( [ "$LOAD_RC" -eq 0 ] && ! fail_text "$LOAD_OUT" && [ "$LOADED_LISTED" -eq 1 ] && echo 0 || echo 1 )"
judge "强" "卸载干净（rc=0 且无失败特征 且 module list 不含模块）" "$( [ "$UNLOAD_RC" -eq 0 ] && ! fail_text "$UNLOAD_OUT" && [ "$STILL_LISTED" -eq 0 ] && echo 0 || echo 1 )"

# ---------------------------------------------------------------- 5. 报告骨架 + 日志
REPORT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
{
  echo
  echo "## 判据结果（自动采集；强证据才可写 PASS，弱证据只能写\"未观察到\"）"
  echo
  echo "- commit: \`$COMMIT\`"
  echo "- instance_id: \`$REG_INSTANCE\`（在册）"
  echo "- 候选 source_commit: \`$REG_SOURCE_COMMIT\`"
  echo "- 工具冻结基线 commit: \`$TOOL_FREEZE_COMMIT\`；冻结状态: $TOOL_FROZEN"
  echo "- 报告生成 HEAD: \`$REPORT_HEAD\`；仪器路径: \`$TOOL_INSTRUMENT_PATHS\`；仪器集合 sha256: \`$TOOL_INSTRUMENT_SHA\`"
  echo "- 模块登记记录 sha256: \`$REGISTRY_SHA\`"
  echo "- 产物: \`$KPM\`"
  echo "- 产物 SHA-256: \`$BLOB_SHA\`"
  echo "- 判据脚本: \`Tester/tools/run_test.sh\` \`sha256=$SCRIPT_SHA\`"
  echo "- 强证据判据通过 $PASS / 失败 ${FAIL}；弱证据（dmesg）崩溃特征命中：$OBS_CRASH"
  echo
  for line in "${RESULTS[@]}"; do
    IFS='|' read -r st strength name <<<"$line"
    echo "- [$st]（${strength}）$name"
  done
} | tee -a "$LOG"

{
  echo "# 实机报告骨架：${MODULE}（自动判据）"
  echo
  echo "> 由 \`Tester/tools/run_test.sh\` 生成；**人工判据、环境事实、失败归属与结论必须由 Tester 补全**。"
  echo "> 模板：\`docs/templates/tester-report.md\`"
  echo
  echo "## 身份"
  echo
  echo "| 项 | 值 |"
  echo "| --- | --- |"
  echo "| commit | \`$COMMIT\` |"
  echo "| instance_id（在册） | \`$REG_INSTANCE\` |"
  echo "| 候选 source_commit（登记值） | \`$REG_SOURCE_COMMIT\` |"
  echo "| 工具冻结基线 commit | \`$TOOL_FREEZE_COMMIT\` |"
  echo "| 工具冻结状态 | $TOOL_FROZEN |"
  echo "| 报告生成 HEAD | \`$REPORT_HEAD\` |"
  echo "| 仪器路径 / 集合 sha256 | \`$TOOL_INSTRUMENT_PATHS\` / \`$TOOL_INSTRUMENT_SHA\` |"
  echo "| 模块登记记录 sha256 | \`$REGISTRY_SHA\` |"
  echo "| 产物 | \`$KPM\` |"
  echo "| 产物 sha256 | \`$BLOB_SHA\` |"
  echo "| 判据脚本 | \`Tester/tools/run_test.sh\` \`sha256=$SCRIPT_SHA\` |"
  echo
  echo "## 环境事实"
  echo
  echo "| 项 | 值 |"
  echo "| --- | --- |"
  echo "| 基线 boot_id | \`$BOOT0\` |"
  echo "| 基线 uptime | \`$UPTIME0\` |"
  echo "| pstore 基线 | $( [ "$PSTORE_CLEAN" -eq 1 ] && echo '空' || echo '未确认' ) |"
  echo "| 测试前已加载模块 | \`$BASE_LIST\` |"
  echo "| 预检记录 | \`Tester/reports/environments/<文件>\` |"
  echo
  echo "## 判据与计数"
  echo
  echo "| 判据 | 证据强度 | 结果 |"
  echo "| --- | --- | --- |"
  for line in "${RESULTS[@]}"; do
    IFS='|' read -r st strength name <<<"$line"
    echo "| $name | $strength | $st |"
  done
  echo "| 未观察到崩溃特征（dmesg） | **弱**（删失：panic 可能丢日志） | $( [ "$OBS_CRASH" -eq 0 ] && echo '未观察到' || echo '观察到' ) |"
  echo "| <功能判据：binder/信号/网络/\\/proc/rekernel> | | 未采集（待人工） |"
  echo
  echo "## 观察与日志摘要"
  echo
  echo '```text'
  echo "运行日志：$LOG"
  echo '```'
  echo
  echo "## 失败归属"
  echo
  echo "| 现象 | 归属（实现缺陷/测试缺陷/环境事实） | 依据 |"
  echo "| --- | --- | --- |"
  echo "| | | |"
  echo
  echo "## 未覆盖"
  echo
  echo "- 未测机型/内核：<补>"
  echo "- 未测功能/判据：binder 解冻、信号解冻、网络解冻、\\/proc/rekernel、偏移推导日志"
  echo "- 未做的破坏性用例及原因：<补>"
  echo "- 未采集项及原因（C7，逐项写）：<补>"
  echo
  echo "## 结论"
  echo
  echo "- 本轮真机结论：<一句话，含判据与计数>"
  echo "- **结论上限（C2）**：只对「该字节在该机型/该内核/该次加载下存活 N 秒且 X/Y 条强证据判据通过」负责，禁止外推。"
} > "$REPORT"

echo
echo "run_test: PASS=$PASS FAIL=$FAIL  日志：$LOG  报告骨架：$REPORT"
if [ "$FAIL" -gt 0 ]; then
  echo "run_test: 请按 docs/templates/tester-report.md 补全报告并判定失败归属（实现缺陷 / 测试缺陷 / 环境事实）"
  exit 1
fi
echo "run_test: 强证据判据全部通过；仍须补功能判据与未覆盖清单，弱证据不得写成\"没有发生\""
exit 0
