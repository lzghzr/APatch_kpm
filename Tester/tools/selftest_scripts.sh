#!/usr/bin/env bash
# Tester 工具离线自检：用 mock 设备（Tester/tools/mock_device.sh）驱动
# preflight.sh / run_test.sh / collect_evidence.sh 的关键分支与退出码。
#
#   bash Tester/tools/selftest_scripts.sh
#
# 覆盖: 身份正反用例（在册实例/缺 instance-id/未登记/产物被篡改/运行 ID 不覆盖）/
#       正常一轮 / 加载失败 / 卸载失败 / 崩溃 / 软重启 / 设备无响应（看门狗）/
#       A2 至多一次 adb reboot / 基线 pstore 残留 / 缺特权通道 / 证据采集 /
#       MNT-010 仪器冻结基线、删除、假冻结、报告绑定
#
# 边界: **这不是真机结论**（C2）。mock 只能证明脚本逻辑、判据分支与退出码；
#       真机行为仍必须在设备上复验，且 mock 通过不得写进任何实机报告当结论。
#       产物全部落在 local/keep/evidence/tester-raw/selftest/（A4 授权的原始证据路径，gitignore），不写进 Tester/reports/。

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2
SELFTEST_FREEZE_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

WORK="${WORK:-local/keep/evidence/tester-raw/selftest}"
[[ "$WORK" = /* ]] || WORK="$REPO/$WORK"
BIN="$WORK/bin"
STATE="$WORK/state"
rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/cases"
chmod +x Tester/tools/mock_device.sh
ln -sf "$REPO/Tester/tools/mock_device.sh" "$BIN/adb"
ln -sf "$REPO/Tester/tools/mock_device.sh" "$BIN/fastboot"

KPM="$WORK/dummy_8.0.0.kpm"
printf 'MOCK-KPM-BYTES\n' > "$KPM"

# 在册实例：从 metadata 现场读取（不硬编码身份串）；产物不在场则身份类用例 SKIP
# 维护者接线（2026-10-03）：模块更名后从现行登记选择夹具，全部身份/异常断言保留。
REAL_INFO="$(python3 - <<'PY_FIXTURE'
import json
from pathlib import Path

# 脚本自检只验证判据逻辑，不绑定任何真机：从元数据取一个在册且产物在场的实例，
# 由 mock 设备驱动 run_test.sh。真机能否加载该模块不属于本自检的判据范围。
records = []
for path in sorted(Path("metadata/modules").glob("*.json")):
    rec = json.loads(path.read_text())
    if rec.get("status") != "archived" and Path(rec["module"], "Makefile").is_file():
        records.append(rec)
for rec in records:
    for build in reversed(rec.get("builds", [])):
        for artifact in build.get("artifacts", []):
            path = artifact.get("path")
            if build.get("instance_id") and path and Path(path).is_file():
                print("\t".join((rec["module"], build["instance_id"], path)))
                raise SystemExit(0)
print((records[0]["module"] if records else "re_kernel") + "\t\t")
PY_FIXTURE
)"
IFS=$'\t' read -r REAL_MODULE REAL_ID REAL_KPM <<< "$REAL_INFO"
export MOCK_MODULE="$REAL_MODULE"
if [ -n "$REAL_ID" ] && [ -f "$REAL_KPM" ]; then
  HAVE_REAL=1
  echo "在册实例：$REAL_ID"
  echo "产物：$REAL_KPM"
else
  HAVE_REAL=0
  echo "（设备未安装任何在册模块，或产物不在场：身份类用例将 SKIP）"
fi
echo

FAILS=0
PASSES=0; SKIPS=0
ok()   { echo "PASS  $1"; PASSES=$((PASSES+1)); }
bad()  { echo "FAIL  $1"; FAILS=$((FAILS+1)); }
skip() { echo "SKIP  $1"; SKIPS=$((SKIPS+1)); }

CASE_DIR=""
CASE_OUT=""
check_rc()  { [ "$3" -eq "$2" ] && ok "$1 (rc=$3)" || { bad "$1 期望 rc=$2 实际 rc=$3"; sed -n '1,30p' "$CASE_OUT"; }; }
check_has() { grep -qF -- "$3" "$2" && ok "$1" || bad "$1（未找到：$3）"; }
check_not() { grep -qF -- "$3" "$2" && bad "$1（不应出现：$3）" || ok "$1"; }
check_cmd_has() {
  local name="$1" needle="$2"
  if [ -f "$STATE/cmd_history.log" ] && grep -Eq -- "$needle" "$STATE/cmd_history.log"; then
    ok "${name}"
  else
    bad "${name}（mock 历史未记录命令: ${needle}）"
  fi
}
check_cmd_not() {
  local name="$1" needle="$2"
  if [ -f "$STATE/cmd_history.log" ] && grep -Eq -- "$needle" "$STATE/cmd_history.log"; then
    bad "${name}（mock 历史不应出现命令: ${needle}）"
  else
    ok "${name}"
  fi
}
check_row_value() {
  local name="$1" file="$2" field="$3" value="$4" needle
  needle="$(printf '| %s | `%s` |' "$field" "$value")"
  grep -qF -- "$needle" "$file" && ok "$name" || bad "$name（未找到：$needle）"
}

first() { ls "$1"/*"$2" 2>/dev/null | head -1; }

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}

run() {  # run <名称> <场景> <OBSERVE> <命令...>
  local name="$1" scen="$2" obs="$3"; shift 3
  rm -rf "$STATE"; mkdir -p "$STATE"
  CASE_DIR="$WORK/cases/$name"
  mkdir -p "$CASE_DIR/runs" "$CASE_DIR/esc" "$CASE_DIR/env" "$CASE_DIR/ev" "$CASE_DIR/raw"
  CASE_DIR="$(cd "$CASE_DIR" && pwd)"
  CASE_OUT="$CASE_DIR/out.txt"
  MOCK_DIR="$STATE" MOCK_SCEN="$scen" ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
  TIMEOUT=1 OBSERVE="$obs" POLL=1 TOOL_FREEZE_COMMIT="$SELFTEST_FREEZE_COMMIT" \
  RUNDIR="$CASE_DIR/runs" ESCDIR="$CASE_DIR/esc" OUTDIR="$CASE_DIR/env" RAW_DIR="$CASE_DIR/raw" \
    "$@" >"$CASE_OUT" 2>&1
  return $?
}

echo "== Tester 工具离线自检（mock 设备，不是真机）=="

# ---- MNT-010：辅助冻结判据的独立临时仓库回归 ------------------------------
CASE_OUT="$WORK/instrument-freeze.txt"
if [ -f tools/selftest_instrument_freeze.py ]; then
  python3 tools/selftest_instrument_freeze.py >"$CASE_OUT" 2>&1
  check_rc "MNT-010/冻结判据独立夹具" 0 "$?"
  check_has "MNT-010/七个冻结边界均通过" "$CASE_OUT" '7/7 通过'
else
  bad "MNT-010/缺少 tools/selftest_instrument_freeze.py 独立夹具"
fi
check_has "MNT-010/run_test 接入仪器冻结 helper" Tester/tools/run_test.sh 'instrument_frozen.sh --repo'
check_not "MNT-010/run_test 不再按报告与 metadata 的整体 Git 状态判定" \
  Tester/tools/run_test.sh 'git status --porcelain -- Tester tools docs metadata'

# ---- TST-002: timed_out 函数判定正反夹具（C1.1） -----------------------------
eval "$(sed -n '/^timed_out() {/,/^}/p' Tester/tools/run_test.sh)"
timed_out 124 && ok "TST-002/函数判据: 124 判定为看门狗超时（->90）" \
  || bad "TST-002/函数判据: 124 未判定为超时"
timed_out 137 && ok "TST-002/函数判据: 137 (SIGKILL) 判定为真实信号（->90）" \
  || bad "TST-002/函数判据: 137 未判定为真实信号"
timed_out 143 && ok "TST-002/函数判据: 143 (SIGTERM) 判定为真实信号（->90）" \
  || bad "TST-002/函数判据: 143 未判定为真实信号"
timed_out 255 && bad "TST-002/函数判据: 255 误判为超时/信号（应为判据 FAIL ->1）" \
  || ok "TST-002/函数判据: 255 判定为 CLI 错误码（->1）"
timed_out 1 && bad "TST-002/函数判据: 1 误判为超时/信号（应为判据 FAIL ->1）" \
  || ok "TST-002/函数判据: 1 判定为 CLI 错误码（->1）"
timed_out 128 && bad "TST-002/函数判据: 128 误判为真实信号（无对应信号码）" \
  || ok "TST-002/函数判据: 128 正确排除（->1）"

# ---- 1. 预检：正常 ----------------------------------------------------------
run preflight_ok ok 0 bash Tester/tools/preflight.sh
check_rc "preflight/正常" 0 "$?"
ENVF="$(first "$CASE_DIR/env" .md)"
check_has "preflight 记录加载前基线（C4）" "$ENVF" "加载前基线"
check_has "preflight 判定 pstore 干净" "$ENVF" "空（无旧崩溃残留）"
check_has "preflight 记录 fastboot 状态" "$ENVF" "fastboot 状态"
check_not "preflight 不落序列号明文" "$ENVF" "MOCKDEVICE0001"

# ---- 2. 预检：未检测到 Manager UID / 特权通道（A3/A6） ------------------------
rm -rf "$STATE"; mkdir -p "$STATE"
CASE_DIR="$WORK/cases/preflight_no_privilege"; mkdir -p "$CASE_DIR/env"
CASE_OUT="$CASE_DIR/out.txt"
MOCK_DIR="$STATE" MOCK_SCEN=no_privilege ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
TIMEOUT=1 OUTDIR="$CASE_DIR/env" \
  bash Tester/tools/preflight.sh >"$CASE_OUT" 2>&1
check_rc "preflight/缺特权通道仍返回 0（环境问题，非缺陷）" 0 "$?"
check_has "preflight 标注未检测到 Manager UID" "$(first "$CASE_DIR/env" .md)" "未检测到 APatch Manager UID"

# ---- 3. 身份：正反用例（MNT-008） ------------------------------------------
if [ "$HAVE_REAL" -eq 1 ]; then
  run run_ok ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --tool-freeze-commit "$SELFTEST_FREEZE_COMMIT" --instance-id "$REAL_ID"
  check_rc "身份正例/在册实例正常一轮" 0 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  REP="$(first "$CASE_DIR/runs" .md)"
  check_has "正例：报告标识为在册 instance_id" "$REP" "$REAL_ID"
  check_has "正例：报告写候选 source_commit" "$REP" '候选 source_commit'
  check_has "正例：报告写工具冻结状态" "$REP" '冻结状态'
  check_row_value "MNT-010：报告写明确工具冻结基线" "$REP" "工具冻结基线 commit" "$SELFTEST_FREEZE_COMMIT"
  check_row_value "MNT-010：报告单列生成 HEAD" "$REP" "报告生成 HEAD" "$SELFTEST_FREEZE_COMMIT"
  check_has "MNT-010：报告绑定仪器集合哈希" "$REP" '仪器路径 / 集合 sha256'
  check_has "MNT-010：报告绑定模块登记记录字节哈希" "$REP" '模块登记记录 sha256'
  check_has "正例：加载成功判 PASS" "$LOG" '[PASS]（强）加载成功'
  check_has "正例：常驻存活判 PASS" "$LOG" '[PASS]（强）常驻存活'
  check_has "正例：存活判据判 PASS" "$LOG" '[PASS]（强）设备存活'
  check_not "正例：无 FAIL 判据" "$LOG" '[FAIL]'
  check_has "正例：报告骨架写判据脚本 hash（C5）" "$REP" 'sha256='
  check_has "正例：报告骨架含结论上限（C2）" "$REP" '结论上限'
  check_has "正例：报告骨架含未覆盖" "$REP" '未覆盖'

  L1="$(ls "$CASE_DIR"/runs/*.log 2>/dev/null | wc -l | tr -d ' ')"
  run run_ok ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "唯一运行 ID/同一产物重跑" 0 "$?"
  L2="$(ls "$CASE_DIR"/runs/*.log 2>/dev/null | wc -l | tr -d ' ')"
  [ "$L1" -eq 1 ] && [ "$L2" -eq 2 ] && ok "唯一运行 ID：重跑不覆盖（${L1}→$L2 份报告）" || bad "唯一运行 ID：重跑覆盖了旧报告（${L1}→${L2}）"
  ls "$CASE_DIR"/runs/*'#2.log' >/dev/null 2>&1 && ok "唯一运行 ID：第二次落为 #2" || bad "唯一运行 ID：未见 #2 后缀文件"

  TAMPER="$WORK/tampered.kpm"
  cp "$REAL_KPM" "$TAMPER"; printf 'X' >> "$TAMPER"
  run run_tampered ok 0 bash Tester/tools/run_test.sh --kpm "$TAMPER" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "身份反例/产物被篡改" 2 "$?"
  check_has "反例：报产物哈希与登记不一致" "$CASE_OUT" '产物哈希与登记不一致'

  # ---- 4. 场景用例（都用在册实例 + 其真实产物） -----------------------------
  # TST-002 场景正反用例：124/137/143 -> 90; 255/1 -> 1
  run run_load_fail load_fail 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载失败" 1 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "加载失败：加载判据 FAIL" "$LOG" '[FAIL]（强）加载成功'
  check_has "加载失败：保留原始输出" "$LOG" 'unknown symbol: kf_get_task_ext'
  [ -z "$(first "$CASE_DIR/esc" .md)" ] && ok "加载失败 rc=1：未误生成升级单" || bad "加载失败 rc=1：误生成升级单"

  run run_load_fail_255 load_fail_255 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载返回 255 (TST-002: CLI 错误码判 FAIL)" 1 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "加载 255：加载判据 FAIL" "$LOG" '[FAIL]（强）加载成功'
  check_has "加载 255：保留原始输出" "$LOG" 'failed with (null) error: -22'
  [ -z "$(first "$CASE_DIR/esc" .md)" ] && ok "加载 255：未误生成升级单（不走 90 升级）" || bad "加载 255：误生成升级单"

  run run_load_timeout load_timeout 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载超时 124 升级" 90 "$?"
  check_has "加载 124：升级单写明超时" "$(first "$CASE_DIR/esc" .md)" 'module load 超时未返回'

  run run_load_sigkill load_sigkill 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载被 SIGKILL 137 升级" 90 "$?"
  check_has "加载 137：升级单写明超时/信号" "$(first "$CASE_DIR/esc" .md)" 'module load 超时未返回'

  run run_load_sigterm load_sigterm 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载被 SIGTERM 143 升级" 90 "$?"
  check_has "加载 143：升级单写明超时/信号" "$(first "$CASE_DIR/esc" .md)" 'module load 超时未返回'

  run run_crash crash 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/崩溃升级" 90 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  ESC="$(first "$CASE_DIR/esc" .md)"
  check_has "崩溃：日志留证" "$LOG" 'Call trace'
  check_has "崩溃：升级单含物理动作请求（A5）" "$ESC" '需要维护者执行的物理动作'
  check_has "崩溃：升级单含动作回执" "$ESC" '动作回执'
  check_has "崩溃：升级单绑定在册实例" "$ESC" "$REAL_ID"
  check_not "崩溃：不自动卸载（保现场）" "$LOG" '卸载模块'

  run run_reboot reboot 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/软重启升级" 90 "$?"
  check_has "软重启：升级单写明原因" "$(first "$CASE_DIR/esc" .md)" '检测到重启'

  T0="$(date +%s)"
  run run_hang hang 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  RC=$?; ELAPSED=$(( $(date +%s) - T0 ))
  check_rc "run_test/设备无响应" 90 "$RC"
  check_has "无响应：升级单写明连续超时" "$(first "$CASE_DIR/esc" .md)" 'adb 连续 2 次无响应'
  [ -z "$(first "$CASE_DIR/runs" .md)" ] && ok "无响应：未产出 PASS 报告骨架" || bad "无响应：产出了报告骨架（应停在升级）"
  [ "$ELAPSED" -lt 30 ] && ok "无响应：看门狗及时触发（${ELAPSED}s）" || bad "无响应：耗时 ${ELAPSED}s，看门狗可能未生效"

  run run_hang_recover hang_late 3 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID" --recover
  check_rc "run_test/--recover 无响应" 90 "$?"
  check_has "A2：升级单记录已尝试一次 adb reboot" "$(first "$CASE_DIR/esc" .md)" '已尝试 1 次 adb reboot'

  run run_pstore_dirty pstore_dirty 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/pstore 残留前置不满足" 3 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "pstore 残留：日志说明原因" "$LOG" 'pstore 基线'
  check_not "pstore 残留：未进入加载" "$LOG" '加载模块'

  # ---- 5. --no-unload 常驻正反用例（AUD-009 / RA-001 / 复测要求） ------------
  run run_no_unload ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID" --no-unload
  check_rc "run_test/--no-unload 正常常驻" 0 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "--no-unload：常驻判据判 PASS" "$LOG" '[PASS]（强）常驻存活（--no-unload：维持运行且在 module list 中）'
  check_not "--no-unload：不触发卸载" "$LOG" '卸载模块'
  check_has "--no-unload：日志标明跳过卸载" "$LOG" '跳过卸载阶段（--no-unload 模式'

  run run_no_unload_fail resident_fail 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID" --no-unload
  check_rc "run_test/--no-unload 常驻失败" 1 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "--no-unload 反例：常驻判据判 FAIL" "$LOG" '[FAIL]（强）常驻存活（--no-unload：维持运行且在 module list 中）'

  # ---- 6. TST-003：--load-args 参数透传正反夹具 -------------------------------
  # 正例 1：不带参数（默认），验证 mock 接收到的 load 命令不含附加参数
  run run_load_default ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID"
  check_rc "TST-003/正例：不带参数加载" 0 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  REP="$(first "$CASE_DIR/runs" .md)"
  check_has "TST-003/正例不带参数：日志显示常规加载" "$LOG" '加载模块'
  check_not "TST-003/正例不带参数：日志不含参数字样" "$LOG" '加载模块（参数:'
  check_not "TST-003/正例不带参数：报告骨架无加载参数项" "$REP" '| 加载参数 |'

  # 正例 2：带参数（如策略路径）
  run run_load_args ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID" --load-args "policy=/data/adb/hma_guard/stock.policy"
  check_rc "TST-003/正例：带参数加载" 0 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  REP="$(first "$CASE_DIR/runs" .md)"
  check_has "TST-003/正例带参数：日志记录参数" "$LOG" '加载模块（参数: policy=/data/adb/hma_guard/stock.policy）'
  check_has "TST-003/正例带参数：报告骨架记录参数" "$REP" '| 加载参数 | `policy=/data/adb/hma_guard/stock.policy` |'
  check_has "TST-003/正例带参数：mock 实际收到参数" "$STATE/last_load_cmd" 'policy=/data/adb/hma_guard/stock.policy'

  # 正例 3：参数含空格（多个空格分隔参数与值含空格）
  run run_load_args_space ok 1 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID" --load-args "policy=/data/adb/hma_guard/stock.policy uid=on"
  check_rc "TST-003/正例：参数含空格（多参数）" 0 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "TST-003/正例多参数：mock 收到完整参数串" "$STATE/last_load_cmd" 'policy=/data/adb/hma_guard/stock.policy uid=on'
  check_has "TST-003/正例多参数：日志完整记录" "$LOG" '加载模块（参数: policy=/data/adb/hma_guard/stock.policy uid=on）'

  # 反例 1：带参数加载失败场景（确认错误捕获机制不受参数影响）
  run run_load_args_fail load_fail 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
    --instance-id "$REAL_ID" --load-args "policy=/data/adb/hma_guard/stock.policy"
  check_rc "TST-003/反例：带参数加载失败仍报 FAIL" 1 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "TST-003/反例带参数加载失败：判据 FAIL" "$LOG" '[FAIL]（强）加载成功'
  check_has "TST-003/反例带参数加载失败：mock 仍收到参数" "$STATE/last_load_cmd" 'policy=/data/adb/hma_guard/stock.policy'

  # ---- MNT-008 独立复核回归：升级目录已有同名 #1，运行目录为空，不得覆盖旧升级单 ----
  rm -rf "$STATE"; mkdir -p "$STATE"
  CASE_DIR="$WORK/cases/esc_collision"; mkdir -p "$CASE_DIR/runs" "$CASE_DIR/esc"
  CASE_OUT="$CASE_DIR/out.txt"
  OLD_ESC="$CASE_DIR/esc/$(date +%F)-${REAL_MODULE}-$(basename "$REAL_KPM" .kpm)#1.md"
  printf 'OLD-ESCALATION-EVIDENCE-MUST-NOT-BE-LOST\n' > "$OLD_ESC"
  OLD_SHA="$(sha256_hex < "$OLD_ESC")"
  MOCK_DIR="$STATE" MOCK_SCEN=crash ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
  TIMEOUT=1 OBSERVE=1 POLL=1 TOOL_FREEZE_COMMIT="$SELFTEST_FREEZE_COMMIT" \
  RUNDIR="$CASE_DIR/runs" ESCDIR="$CASE_DIR/esc" \
    bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID" \
      >"$CASE_OUT" 2>&1
  check_rc "MNT-008/升级目录已有 #1 时的崩溃" 90 "$?"
  NEW_SHA="$(sha256_hex < "$OLD_ESC")"
  if [ -z "$OLD_SHA" ] || [ -z "$NEW_SHA" ]; then
    bad "MNT-008：哈希采集失败（OLD='$OLD_SHA' NEW='$NEW_SHA'），断言不成立，不得判通过"
  elif [ "$OLD_SHA" = "$NEW_SHA" ]; then
    ok "MNT-008：旧升级单 #1 未被覆盖（sha256 ${OLD_SHA%??????????????????????????????????????????????????????}… 不变）"
  else
    bad "MNT-008：旧升级单 #1 被覆盖（$OLD_SHA -> $NEW_SHA）"
  fi
  check_has "MNT-008：旧升级单内容原样保留" "$OLD_ESC" 'OLD-ESCALATION-EVIDENCE-MUST-NOT-BE-LOST'
  ls "$CASE_DIR"/esc/*'#2.md' >/dev/null 2>&1 && ok "MNT-008：新现场顺延为 #2（不覆盖）" \
    || bad "MNT-008：未生成 #2 升级单（$(ls "$CASE_DIR"/esc/ 2>/dev/null | tr '\n' ' ')）"
  NEW_ESC="$(ls "$CASE_DIR"/esc/*'#2.md' 2>/dev/null | head -1)"
  check_has "MNT-008：新升级单绑定在册实例" "$NEW_ESC" "$REAL_ID"
else
  skip "身份正例/反例 + 场景用例（在册实例或产物不在场）"
fi

# 身份反例：缺 --instance-id / 未登记实例（与产物无关，必须在加载前拒绝）
run ident_missing ok 0 bash Tester/tools/run_test.sh --kpm "$KPM" --module "$REAL_MODULE"
check_rc "身份反例/缺 --instance-id" 2 "$?"
check_has "反例：提示必须是 metadata 在册的 instance_id" "$CASE_OUT" '缺少 --instance-id'

run ident_unregistered ok 0 bash Tester/tools/run_test.sh --kpm "$KPM" --module "$REAL_MODULE" --instance-id 'not-registered#9'
check_rc "身份反例/未登记实例" 2 "$?"
# 远程/干净副本没有 metadata/modules，run_test 会以“找不到模块登记记录”拒绝（同样 rc=2）；
# 两种拒绝理由都算这条反例成立，但要如实记出命中的是哪一种。
if grep -q '不在册' "$CASE_OUT"; then
  ok   "反例：报不在册并列出候选"
elif grep -q '找不到模块登记记录' "$CASE_OUT"; then
  ok   "反例：无登记记录时拒绝（干净副本无 metadata/modules）"
else
  bad  "反例：报不在册并列出候选"
fi

# TST-003 反例：--load-args 缺少参数值
run load_args_missing ok 0 bash Tester/tools/run_test.sh --kpm "$KPM" --module "$REAL_MODULE" --instance-id "${REAL_ID:-dummy#1}" --load-args
check_rc "TST-003/反例：--load-args 缺少参数值" 2 "$?"
check_has "TST-003/反例：提示缺少参数值" "$CASE_OUT" '--load-args 缺少参数值'

# ---- 11. collect_evidence：证据采集 ----------------------------------------
run collect_evidence ok 0 bash Tester/tools/collect_evidence.sh --build-id 'mock-instance#1' --module "$REAL_MODULE"
check_rc "collect_evidence/采集" 0 "$?"
EVD="$(ls -d "$CASE_DIR"/env/*/ 2>/dev/null | head -1)"
check_has "证据：生成 README 清单" "$EVD/README.md" '未做（必须确认）'
check_has "证据：dmesg 尾部有内容" "$EVD/dmesg-tail.txt" 'mock dmesg'

# ---- 12. collect_evidence：--out 显式指定目录 --------------------------------
rm -rf "$STATE"; mkdir -p "$STATE"
CASE_DIR="$WORK/cases/collect_out"; mkdir -p "$CASE_DIR"
CASE_OUT="$CASE_DIR/out.txt"
MOCK_DIR="$STATE" MOCK_SCEN=ok ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
TIMEOUT=1 \
  bash Tester/tools/collect_evidence.sh --build-id 'mock-instance#1' --module "$REAL_MODULE" \
    --out "$CASE_DIR/explicit" >"$CASE_OUT" 2>&1
check_rc "collect_evidence/--out 显式目录" 0 "$?"
check_has "证据：--out 生效" "$(ls -d "$CASE_DIR"/explicit/*/ 2>/dev/null | head -1)/README.md" '升级证据'

# ---- 13. MNT-022: 已有同名实例拦截 / 完整日志保留 / 拒载场景正反用例 ----------
# 合成记录只在隔离的 mock 仓库标准目录（不污染发布树，生产代码不使用任何 MODULE_RECORD 后门）
MOCK_REPO="$(cd "$WORK" && pwd)/mock_repo"
rm -rf "$MOCK_REPO"
mkdir -p "$MOCK_REPO/metadata/modules"
mkdir -p "$MOCK_REPO/Tester/tools"
mkdir -p "$MOCK_REPO/Tester/reports/runs" "$MOCK_REPO/Tester/reports/escalations"

# 复制 Tester 工具到 mock 仓库
cp -p "$REPO/Tester/tools/"*.sh "$MOCK_REPO/Tester/tools/"
chmod +x "$MOCK_REPO/Tester/tools/"*.sh

# 准备测试产物
KPM_RE="$MOCK_REPO/dummy_re_kernel_8.0.0.kpm"
printf 'MOCK-REKERNEL-BYTES\n' > "$KPM_RE"
KPM_RE_SHA="$(sha256_hex < "$KPM_RE")"

KPM_NOMOUNT="$MOCK_REPO/dummy_nomount_1.0.0.kpm"
printf 'MOCK-NOMOUNT-BYTES\n' > "$KPM_NOMOUNT"
KPM_NOMOUNT_SHA="$(sha256_hex < "$KPM_NOMOUNT")"

# 在 mock 仓库标准目录生成登记记录
cat > "$MOCK_REPO/metadata/modules/re_kernel.json" <<JSON
{
  "module": "re_kernel",
  "name": "re_kernel",
  "kpm_name": "re_kernel",
  "status": "candidate",
  "builds": [
    {
      "instance_id": "re_kernel-mnt022#1",
      "build_id": "re_kernel-mnt022",
      "source_commit": "$SELFTEST_FREEZE_COMMIT",
      "artifacts": [
        {
          "path": "dummy_re_kernel_8.0.0.kpm",
          "sha256": "$KPM_RE_SHA"
        }
      ]
    }
  ]
}
JSON

cat > "$MOCK_REPO/metadata/modules/nomount.json" <<JSON
{
  "module": "nomount",
  "name": "NoMount",
  "kpm_name": "NoMount",
  "status": "candidate",
  "builds": [
    {
      "instance_id": "nomount-mnt022#1",
      "build_id": "nomount-mnt022",
      "source_commit": "$SELFTEST_FREEZE_COMMIT",
      "artifacts": [
        {
          "path": "dummy_nomount_1.0.0.kpm",
          "sha256": "$KPM_NOMOUNT_SHA"
        }
      ]
    }
  ]
}
JSON

# 用例 1：已有同名实例时拒绝加载（旧记录在场 - 运行列表，Tester 不执行模块热卸载，换件须重启）
run mnt022_already_loaded already_loaded 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1"
check_rc "MNT-022/已有同名实例时在加载前停" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：说明 Tester 不执行热卸载且换件须重启" "$LOG" 'Tester 不执行模块热卸载'
check_cmd_not "MNT-022：已有实例时 mock 命令未调用 kpm unload" 'kpm unload|module unload'
check_cmd_not "MNT-022：已有实例时 mock 命令未调用 kpm load" 'kpm load|module load'

# 用例 2：实际管理名与 metadata key 不同时拦截（NoMount vs nomount）
MOCK_RUNNING_MODULE="NoMount" run mnt022_nomount_already_loaded already_loaded 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_NOMOUNT" --module "nomount" --instance-id "nomount-mnt022#1"
check_rc "MNT-022/管理名不同(NoMount)在场时拦截" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：识别实际管理名 NoMount 已在运行" "$LOG" '模块 NoMount（key: nomount）已在运行列表中'
check_cmd_not "MNT-022：管理名已在场时 mock 命令未调用 kpm unload" 'kpm unload|module unload'
check_cmd_not "MNT-022：管理名已在场时 mock 命令未调用 kpm load" 'kpm load|module load'

# 用例 3：模块清单读取失败时在加载前停（清单读失败）
run mnt022_list_fail list_fail 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1"
check_rc "MNT-022/清单读取失败在加载前停" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：日志说明清单读取失败" "$LOG" '模块清单读取失败'
check_cmd_not "MNT-022：清单失败时 mock 命令未调用 kpm load" 'kpm load|module load'

# 用例 4：保留完整内核日志（不执行 dmesg -c，保留完整日志）
run mnt022_dmesg_preserved ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" --no-unload
check_rc "MNT-022/测试正常执行" 0 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：日志记录保留完整内核日志" "$LOG" '保留完整内核日志快照（不执行 dmesg -c'
check_cmd_has "MNT-022：执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：测试全程 mock 命令未调用 dmesg -c" 'dmesg -c'
check_cmd_not "MNT-022：测试全程 mock 命令未调用 kpm unload" 'kpm unload|module unload'
check_has "MNT-022：私有原始证据保存预载日志" "$CASE_DIR/raw/dmesg_pre_load.log" 'Linux version'
check_has "MNT-022：私有原始证据保存加载后日志" "$CASE_DIR/raw/dmesg_post_load.log" 'Linux version'

# 用例 5：拒载场景/旧成功记录在场拦截（KP 标准日志 "[re_kernel] succeed with [base]"）
run mnt022_reject_old_record reject_old_record 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: 曾成功加载记录在场拦截" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：拒载场景拦截已有成功记录" "$LOG" '已有成功记录'
check_cmd_not "MNT-022：旧成功记录在场时 mock 未调用 kpm load" 'kpm load|module load'

# 用例 6：拒载场景/未提供操作人核验凭据拦截（不能仅靠 dmesg 第一行接近零断言从未加载）
run mnt022_reject_no_credential ok 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22"
check_rc "MNT-022/拒载场景: 缺操作人凭据拦截" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：拒载场景拦截缺操作人核验凭据" "$LOG" '未提供按本轮启动与模块绑定的操作人已核验凭据'
check_cmd_not "MNT-022：缺凭据时 mock 未调用 kpm load" 'kpm load|module load'

# 用例 7：拒载场景/凭据未严格绑定目标模块拦截（boot-only 拦截：不能只有 boot_id 或前缀通配）
run mnt022_reject_boot_only ok 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111"
check_rc "MNT-022/拒载场景: 凭据未绑定模块(boot-only)拦截" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：拒载场景拦截 boot-only 凭据" "$LOG" '操作人凭据未严格绑定目标模块'
check_cmd_not "MNT-022：boot-only 凭据时 mock 未调用 kpm load" 'kpm load|module load'

# 用例 8：拒载场景/操作人凭据与当前 boot_id 不一致拦截
run mnt022_reject_bad_credential ok 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-wrong-0000:re_kernel"
check_rc "MNT-022/拒载场景: 凭据与 boot_id 不匹配拦截" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：拒载场景拦截凭据不匹配" "$LOG" '操作人凭据（boot-wrong-0000:re_kernel）与当前 boot_id（boot-old-1111）或目标模块不一致'
check_cmd_not "MNT-022：凭据不匹配时 mock 未调用 kpm load" 'kpm load|module load'

# 用例 9：拒载场景/拒载前日志读取失败应在加载前停
run mnt022_reject_pre_dmesg_fail reject_pre_dmesg_fail 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: 前置 dmesg 读失败在加载前停" 3 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：日志说明前置内核日志读取失败" "$LOG" '内核日志读取失败'
check_cmd_not "MNT-022：前置日志失败时 mock 未调用 kpm load" 'kpm load|module load'

# 用例 10：NoMount 真实拒载正例（CLI 非零 + 内核本次窗口出现专用诊断）判 PASS
run mnt022_nomount_reject_clean_ok nomount_reject_clean_ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_NOMOUNT" --module "nomount" --instance-id "nomount-mnt022#1" \
  --expect-reject "refusing to load \(-22\)" --clean-boot-credential "boot-old-1111:NoMount"
check_rc "MNT-022/NoMount 真实正例: 窗口专用诊断判 PASS" 0 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
REP="$(first "$CASE_DIR/runs" .md)"
check_has "MNT-022：凭据核验通过" "$LOG" '拒载场景凭据核验通过'
check_cmd_has "MNT-022：拒载验证执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：拒载验证 mock 未调用 kpm unload" 'kpm unload|module unload'
check_has "MNT-022：拒载验证判 PASS" "$LOG" '[PASS]（强）拒载验证（未被加载入列表 且 本次窗口出现明确目标错误码与专用诊断）'
check_has "MNT-022：设备存活判 PASS" "$LOG" '[PASS]（强）设备存活'
check_has "MNT-022：报告骨架记录拒载模式" "$REP" '拒载验证'

# 用例 11：错误码与专用诊断不匹配（CLI 返回 -95 无专用诊断，不能判通过）
run mnt022_reject_cli_95_no_diag reject_cli_95_no_diag 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "refusing to load \(-22\)" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/反例: CLI 返回 -95 且无专用诊断判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：无专用诊断判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 12：拒载场景/旧日志相同诊断拦截（旧日志诊断不在本次窗口，不能判通过）
run mnt022_reject_old_dmesg_diag reject_old_dmesg_diag 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_NOMOUNT" --module "nomount" --instance-id "nomount-mnt022#1" \
  --expect-reject "refusing to load \(-22\)" --clean-boot-credential "boot-old-1111:NoMount"
check_rc "MNT-022/反例: 旧日志相同诊断不在本次窗口判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：旧日志诊断判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 13：拒载场景/缺专用诊断参数不能判通过（缺参数不能 PASS）
run mnt022_reject_no_param reject_clean_ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/反例: 缺专用诊断参数判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：缺参数判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 14：拒载场景/观察期证据读不到不能判通过
run mnt022_reject_post_dmesg_fail reject_post_dmesg_fail 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/反例: 观察期证据读不到判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：证据读不到判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 15：拒载场景/仅有 unknown symbol（代码缺陷非拒载）不判通过
run mnt022_reject_unknown_sym reject_clean_fail_unknown_sym 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: unknown symbol 缺陷判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：unknown symbol 判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 16：拒载场景/无明确内核错误诊断不判通过（不能把任意失败算通过）
run mnt022_reject_no_diag reject_clean_fail_nodots 0 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: 无有效诊断信息判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：无有效诊断信息判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 17：拒载场景/意外成功加载判 FAIL
run mnt022_reject_unexpected_ok ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: 模块意外成功加载判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：意外加载成功判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 18：拒载场景/后置列表查询失败判 FAIL（查询错误不能当模块不存在）
run mnt022_reject_post_list_fail reject_post_list_fail 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" \
  --expect-reject "-22" --clean-boot-credential "boot-old-1111:re_kernel"
check_rc "MNT-022/拒载场景: 后置列表查询失败判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_has "MNT-022：后置列表查询失败判 FAIL" "$LOG" '[FAIL]（强）拒载验证'

# 用例 19：正常首次加载不套用拒载专属前提
run mnt022_normal_first_load ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" --no-unload
check_rc "MNT-022/正常首次加载: 不受拒载专属前提限制正常通过" 0 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_cmd_has "MNT-022：正常首次加载执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：正常首次加载 mock 未调用 kpm unload" 'kpm unload|module unload'
check_cmd_not "MNT-022：正常首次加载 mock 未调用 dmesg -c" 'dmesg -c'
check_has "MNT-022：正常加载判 PASS" "$LOG" '[PASS]（强）加载成功'
check_has "MNT-022：常驻存活判 PASS" "$LOG" '[PASS]（强）常驻存活'
check_not "MNT-022：正常加载不包含拒载核验字样" "$LOG" '拒载场景前置核验'

# 用例 20：常驻存活反例（加载成功但观察期结束消失）对照正常首次加载
run mnt022_resident_fail resident_fail 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" --no-unload
check_rc "MNT-022/常驻存活反例: 加载成功但观察期消失判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_cmd_has "MNT-022：执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：mock 未调用 kpm unload" 'kpm unload|module unload'
check_has "MNT-022：首次加载判 PASS" "$LOG" '[PASS]（强）加载成功'
check_has "MNT-022：常驻存活判 FAIL" "$LOG" '[FAIL]（强）常驻存活'

# 用例 21：常驻列表错误反例（加载成功但后续查询失败，查询错误不能当模块不存在）
run mnt022_resident_list_fail resident_list_fail 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1" --no-unload
check_rc "MNT-022/常驻列表错误反例: 加载成功但后续查询失败判 FAIL" 1 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_cmd_has "MNT-022：执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：mock 未调用 kpm unload" 'kpm unload|module unload'
check_has "MNT-022：首次加载判 PASS" "$LOG" '[PASS]（强）加载成功'
check_has "MNT-022：常驻存活判 FAIL" "$LOG" '[FAIL]（强）常驻存活'

# 用例 22：默认调用（无 --no-unload）正常执行，不触发卸载
run mnt022_normal_default ok 1 \
  bash "$MOCK_REPO/Tester/tools/run_test.sh" --kpm "$KPM_RE" --module "re_kernel" --instance-id "re_kernel-mnt022#1"
check_rc "MNT-022/默认无--no-unload正常执行" 0 "$?"
LOG="$(first "$CASE_DIR/runs" .log)"
check_cmd_has "MNT-022：默认调用执行了 kpm load" 'kpm load|module load'
check_cmd_not "MNT-022：默认调用 mock 未调用 kpm unload" 'kpm unload|module unload'
check_cmd_not "MNT-022：默认调用 mock 未调用 dmesg -c" 'dmesg -c'
check_has "MNT-022：默认调用加载成功判 PASS" "$LOG" '[PASS]（强）加载成功'
check_has "MNT-022：默认调用常驻存活判 PASS" "$LOG" '[PASS]（强）常驻存活'

echo
if [ "$FAILS" -eq 0 ]; then
  if [ "${SKIPS:-0}" -gt 0 ]; then
    echo "selftest_scripts: 通过 ${PASSES} 项，跳过 ${SKIPS} 项（环境不满足，不计为通过；mock 设备，真机行为仍须复验）"
  else
    echo "selftest_scripts: 全部通过（mock 设备；真机行为仍须复验）"
  fi
  exit 0
fi
echo "selftest_scripts: $FAILS 项失败"
exit 1
