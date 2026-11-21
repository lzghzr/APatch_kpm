#!/system/bin/sh
# Tester/tools/cfv2_1016_uid1000_probe.sh
# UID 1000 探针视角测试脚本（依据 DEV-126 判据 4.1）
# 运行身份：UID 1000 (system)

set -e

echo "=== [Probe 1] UID 1000 Identity & Context ==="
id
echo "context=$(cat /proc/self/attr/current 2>/dev/null)"

echo "=== [Probe 2] UID 1000 创建测试子组 ==="
TARGET_DIR="/sys/fs/cgroup/test_freeze_uid1000"
rm -rf "$TARGET_DIR" 2>/dev/null || true
mkdir "$TARGET_DIR"
ls -ld "$TARGET_DIR"
stat -c '%u:%g %a %n' "$TARGET_DIR"

echo "=== [Probe 3] 读取初始 cgroup.freeze ==="
INIT_VAL="$(cat "$TARGET_DIR/cgroup.freeze")"
echo "initial=$INIT_VAL"

echo "=== [Probe 4] 写入 1 并回读 ==="
echo 1 > "$TARGET_DIR/cgroup.freeze"
VAL1="$(cat "$TARGET_DIR/cgroup.freeze")"
echo "after_write_1=$VAL1"

echo "=== [Probe 5] 写入 0 并回读 ==="
echo 0 > "$TARGET_DIR/cgroup.freeze"
VAL0="$(cat "$TARGET_DIR/cgroup.freeze")"
echo "after_write_0=$VAL0"

echo "=== [Probe 6] UID 1000 真实进程冻结行为验证 ==="
BEAT_FILE="/data/local/tmp/freeze_beat_p5.log"
rm -f "$BEAT_FILE"

sh -c 'i=0; while true; do echo $i > /data/local/tmp/freeze_beat_p5.log; i=$((i+1)); sleep 0.1; done' &
P5_PID=$!
echo "$P5_PID" > "$TARGET_DIR/cgroup.procs"

sleep 0.5
RUN1="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
sleep 1
RUN2="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
echo "Running as UID 1000: $RUN1 -> $RUN2"

echo 1 > "$TARGET_DIR/cgroup.freeze"
sleep 0.3
WCHAN="$(cat /proc/$P5_PID/wchan 2>/dev/null || echo unknown)"
STATE="$(cat /proc/$P5_PID/stat 2>/dev/null | cut -d' ' -f3 || echo unknown)"
FROZEN1="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
sleep 2
FROZEN2="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
echo "UID 1000 cgroup.freeze=1"
echo "Frozen window (2s): $FROZEN1 -> $FROZEN2 (state=$STATE wchan=$WCHAN)"

echo 0 > "$TARGET_DIR/cgroup.freeze"
echo "UID 1000 cgroup.freeze=0"
sleep 0.5
RESUME1="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
sleep 1
RESUME2="$(cat "$BEAT_FILE" 2>/dev/null || echo 0)"
echo "UID 1000 Unfrozen window (1s): $RESUME1 -> $RESUME2"

kill -9 "$P5_PID" 2>/dev/null || true
sleep 0.5
rmdir "$TARGET_DIR"
rm -f "$BEAT_FILE"
echo "UID 1000 P5 Complete"
