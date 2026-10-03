#!/usr/bin/env bash
# Tester 工具离线自检：用 mock 设备（Tester/tools/mock_device.sh）驱动
# preflight.sh / run_test.sh / collect_evidence.sh 的关键分支与退出码。
#
#   bash Tester/tools/selftest_scripts.sh
#
# 覆盖: 身份正反用例（在册实例/缺 instance-id/未登记/产物被篡改/运行 ID 不覆盖）/
#       正常一轮 / 加载失败 / 卸载失败 / 崩溃 / 软重启 / 设备无响应（看门狗）/
#       A2 至多一次 adb reboot / 基线 pstore 残留 / 缺 SUPERKEY / 证据采集 /
#       MNT-010 仪器冻结基线、删除、假冻结、报告绑定
#
# 边界: **这不是真机结论**（C2）。mock 只能证明脚本逻辑、判据分支与退出码；
#       真机行为仍必须在设备上复验，且 mock 通过不得写进任何实机报告当结论。
#       产物全部落在 local/tester-raw/selftest/（A4 授权的原始证据路径，gitignore），不写进 Tester/reports/。

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 2
SELFTEST_FREEZE_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

WORK="${WORK:-local/tester-raw/selftest}"
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
import json, os
from pathlib import Path
records = []
for path in sorted(Path("metadata/modules").glob("*.json")):
    rec = json.loads(path.read_text())
    if rec.get("status") != "archived" and Path(rec["module"], "Makefile").is_file():
        records.append(rec)
for rec in records:
    for build in reversed(rec.get("builds", [])):
        for artifact in build.get("artifacts", []):
            path = artifact.get("path")
            if build.get("instance_id") and path and os.path.isfile(path):
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
  echo "（未找到在册实例或产物不在场：身份类用例将 SKIP）"
fi
echo

FAILS=0
ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; FAILS=$((FAILS+1)); }
skip() { echo "SKIP  $1"; }

CASE_DIR=""
CASE_OUT=""
check_rc()  { [ "$3" -eq "$2" ] && ok "$1 (rc=$3)" || { bad "$1 期望 rc=$2 实际 rc=$3"; sed -n '1,30p' "$CASE_OUT"; }; }
check_has() { grep -qF -- "$3" "$2" && ok "$1" || bad "$1（未找到：$3）"; }
check_not() { grep -qF -- "$3" "$2" && bad "$1（不应出现：$3）" || ok "$1"; }
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
  mkdir -p "$CASE_DIR/runs" "$CASE_DIR/esc" "$CASE_DIR/env" "$CASE_DIR/ev"
  CASE_OUT="$CASE_DIR/out.txt"
  MOCK_DIR="$STATE" MOCK_SCEN="$scen" ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
  SUPERKEY="mock-superkey" TIMEOUT=1 OBSERVE="$obs" POLL=1 TOOL_FREEZE_COMMIT="$SELFTEST_FREEZE_COMMIT" \
  RUNDIR="$CASE_DIR/runs" ESCDIR="$CASE_DIR/esc" OUTDIR="$CASE_DIR/env" \
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

# ---- 1. 预检：正常 ----------------------------------------------------------
run preflight_ok ok 0 bash Tester/tools/preflight.sh
check_rc "preflight/正常" 0 "$?"
ENVF="$(first "$CASE_DIR/env" .md)"
check_has "preflight 记录加载前基线（C4）" "$ENVF" "加载前基线"
check_has "preflight 判定 pstore 干净" "$ENVF" "空（无旧崩溃残留）"
check_has "preflight 记录 fastboot 状态" "$ENVF" "fastboot 状态"
check_not "preflight 不落序列号明文" "$ENVF" "MOCKDEVICE0001"

# ---- 2. 预检：未提供 SUPERKEY（A3/A6） --------------------------------------
rm -rf "$STATE"; mkdir -p "$STATE"
CASE_DIR="$WORK/cases/preflight_nosuperkey"; mkdir -p "$CASE_DIR/env"
CASE_OUT="$CASE_DIR/out.txt"
MOCK_DIR="$STATE" MOCK_SCEN=ok ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
SUPERKEY="" TIMEOUT=1 OUTDIR="$CASE_DIR/env" \
  bash Tester/tools/preflight.sh >"$CASE_OUT" 2>&1
check_rc "preflight/缺 SUPERKEY 仍返回 0（环境问题，非缺陷）" 0 "$?"
check_has "preflight 标注未提供 SUPERKEY" "$(first "$CASE_DIR/env" .md)" "未提供 SUPERKEY"

# ---- 3. 身份：正反用例（MNT-008） ------------------------------------------
if [ "$HAVE_REAL" -eq 1 ]; then
  run run_ok ok 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" \
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
  check_has "正例：卸载干净判 PASS" "$LOG" '[PASS]（强）卸载干净'
  check_has "正例：存活判据判 PASS" "$LOG" '[PASS]（强）设备存活'
  check_not "正例：无 FAIL 判据" "$LOG" '[FAIL]'
  check_has "正例：报告骨架写判据脚本 hash（C5）" "$REP" 'sha256='
  check_has "正例：报告骨架含结论上限（C2）" "$REP" '结论上限'
  check_has "正例：报告骨架含未覆盖" "$REP" '未覆盖'

  L1="$(ls "$CASE_DIR"/runs/*.log 2>/dev/null | wc -l | tr -d ' ')"
  run run_ok ok 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
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
  run run_load_fail load_fail 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/加载失败" 1 "$?"
  LOG="$(first "$CASE_DIR/runs" .log)"
  check_has "加载失败：加载判据 FAIL" "$LOG" '[FAIL]（强）加载成功'
  check_has "加载失败：保留原始输出" "$LOG" 'unknown symbol: kf_get_task_ext'

  run run_unload_fail unload_fail 0 bash Tester/tools/run_test.sh --kpm "$REAL_KPM" --module "$REAL_MODULE" --instance-id "$REAL_ID"
  check_rc "run_test/卸载失败" 1 "$?"
  check_has "卸载失败：卸载判据 FAIL" "$(first "$CASE_DIR/runs" .log)" '[FAIL]（强）卸载干净'

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

  # ---- MNT-008 独立复核回归：升级目录已有同名 #1，运行目录为空，不得覆盖旧升级单 ----
  rm -rf "$STATE"; mkdir -p "$STATE"
  CASE_DIR="$WORK/cases/esc_collision"; mkdir -p "$CASE_DIR/runs" "$CASE_DIR/esc"
  CASE_OUT="$CASE_DIR/out.txt"
  OLD_ESC="$CASE_DIR/esc/$(date +%F)-${REAL_MODULE}-$(basename "$REAL_KPM" .kpm)#1.md"
  printf 'OLD-ESCALATION-EVIDENCE-MUST-NOT-BE-LOST\n' > "$OLD_ESC"
  OLD_SHA="$(sha256_hex < "$OLD_ESC")"
  MOCK_DIR="$STATE" MOCK_SCEN=crash ADB="$BIN/adb" FASTBOOT="$BIN/fastboot" \
  SUPERKEY="mock-superkey" TIMEOUT=1 OBSERVE=1 POLL=1 TOOL_FREEZE_COMMIT="$SELFTEST_FREEZE_COMMIT" \
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
check_has "反例：报不在册并列出候选" "$CASE_OUT" '不在册'

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
SUPERKEY="mock-superkey" TIMEOUT=1 \
  bash Tester/tools/collect_evidence.sh --build-id 'mock-instance#1' --module "$REAL_MODULE" \
    --out "$CASE_DIR/explicit" >"$CASE_OUT" 2>&1
check_rc "collect_evidence/--out 显式目录" 0 "$?"
check_has "证据：--out 生效" "$(ls -d "$CASE_DIR"/explicit/*/ 2>/dev/null | head -1)/README.md" '升级证据'

echo
if [ "$FAILS" -eq 0 ]; then
  echo "selftest_scripts: 全部通过（mock 设备；真机行为仍须复验）"
  exit 0
fi
echo "selftest_scripts: $FAILS 项失败"
exit 1
