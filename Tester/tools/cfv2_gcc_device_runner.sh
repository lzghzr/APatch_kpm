#!/system/bin/sh
# Tester/tools/cfv2_gcc_device_runner.sh
# 运行在真机 Android 环境下的轻量档测试执行器

set -e

RES_DIR="/data/local/tmp/cfv2_results"
rm -rf "$RES_DIR"
mkdir -p "$RES_DIR"

echo "=== [Runner] 开始执行轻量档真机测试 ==="

# 1. 上机字节与引导状态
echo "=== [Step 1] 上机字节与引导状态 ==="
sha256sum /data/local/tmp/cgroupv2_freeze_1.0.14.kpm > "$RES_DIR/kpm_sha256.txt"
stat -c '%s' /data/local/tmp/cgroupv2_freeze_1.0.14.kpm > "$RES_DIR/kpm_size.txt"
getprop sys.boot_completed > "$RES_DIR/boot_completed.txt"
cat /proc/sys/kernel/random/boot_id > "$RES_DIR/boot_id.txt"
cat /proc/uptime > "$RES_DIR/uptime.txt"

# 弱证据：内核崩溃统计
dmesg | grep -c "BUG:" > "$RES_DIR/bug_count.txt" || echo "0" > "$RES_DIR/bug_count.txt"
dmesg | grep -c "Kernel panic" > "$RES_DIR/panic_count.txt" || echo "0" > "$RES_DIR/panic_count.txt"

# 2. 引导期加载与布局
echo "=== [Step 2] 引导期加载与布局 ==="
dmesg | grep -E "cgroupv2_freeze|KP load kpm: cgroupv2_freeze" > "$RES_DIR/dmesg_boot_cfv2.txt" || true

# 3. 挂载与 DAC 属主
echo "=== [Step 3] 挂载与 DAC 属主 ==="
cat /proc/1/mountinfo > "$RES_DIR/proc_1_mountinfo.txt"
stat -c '%u:%g %a %n' /sys/fs/cgroup > "$RES_DIR/stat_cgroup.txt"
stat -c '%u:%g %a %n' /dev/cg2_bpf > "$RES_DIR/stat_bpf.txt"

# 4. 单轮冻结验证
echo "=== [Step 4] 单轮冻结验证 ==="
P4_DIR="/sys/fs/cgroup/test_freeze_p4"
P4_BEAT="/data/local/tmp/freeze_beat_p4.log"
rm -rf "$P4_DIR" "$P4_BEAT"
mkdir "$P4_DIR"

sh -c 'i=0; while true; do echo $i > /data/local/tmp/freeze_beat_p4.log; i=$((i+1)); sleep 0.1; done' &
P4_PID=$!
echo "$P4_PID" > "$P4_DIR/cgroup.procs"

sleep 0.5
P4_RUN1="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
sleep 1
P4_RUN2="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
echo "Running: $P4_RUN1 -> $P4_RUN2" > "$RES_DIR/criterion4_freeze_behavior.txt"

echo 1 > "$P4_DIR/cgroup.freeze"
sleep 0.3
P4_WCHAN="$(cat /proc/$P4_PID/wchan 2>/dev/null || echo unknown)"
P4_STATE="$(cat /proc/$P4_PID/stat 2>/dev/null | cut -d' ' -f3 || echo unknown)"
P4_FROZEN1="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
sleep 2
P4_FROZEN2="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
echo "cgroup.freeze=1" >> "$RES_DIR/criterion4_freeze_behavior.txt"
echo "Frozen window (2s): $P4_FROZEN1 -> $P4_FROZEN2 (state=$P4_STATE wchan=$P4_WCHAN)" >> "$RES_DIR/criterion4_freeze_behavior.txt"

echo 0 > "$P4_DIR/cgroup.freeze"
echo "cgroup.freeze=0" >> "$RES_DIR/criterion4_freeze_behavior.txt"
sleep 0.5
P4_RESUME1="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
sleep 1
P4_RESUME2="$(cat "$P4_BEAT" 2>/dev/null || echo 0)"
echo "Unfrozen window (1s): $P4_RESUME1 -> $P4_RESUME2" >> "$RES_DIR/criterion4_freeze_behavior.txt"

kill -9 "$P4_PID" 2>/dev/null || true
sleep 0.5
rmdir "$P4_DIR"
rm -f "$P4_BEAT"
echo "P4 Complete" >> "$RES_DIR/criterion4_freeze_behavior.txt"

# 5. UID 1000 消费者视角
echo "=== [Step 5] UID 1000 消费者视角 ==="
chmod 755 /data/local/tmp/cfv2_p5_uid1000.sh
su 1000 -c '/data/local/tmp/cfv2_p5_uid1000.sh' > "$RES_DIR/criterion5_uid1000_consumer.txt"

# 6. 墓碑模块与 UID 1000
echo "=== [Step 6] 墓碑模块与 UID 1000 ==="
{
  echo "=== Loaded KPM Modules ==="
  su 10198 -c '/data/adb/kpatch su kpm list 2>/dev/null || /data/adb/ap/bin/kpatch su kpm list 2>/dev/null'
  echo "=== KPM Info cgroupv2_freeze ==="
  su 10198 -c '/data/adb/kpatch su kpm info cgroupv2_freeze 2>/dev/null'
  echo "=== nep / freezer Processes in ps ==="
  ps -A | grep -E 'nep|timeline|freezer' || echo 'None running'
  echo "=== nep.timeline.freezer Package Dump ==="
  dumpsys package nep.timeline.freezer | grep -E 'userId|pkgFlags' || echo 'Package not found'
} > "$RES_DIR/tombstone_and_freezer_check.txt"

# 7. 全量日志收集
echo "=== [Step 7] 全量日志导出 ==="
dmesg > "$RES_DIR/dmesg_full.txt"

echo "=== [Runner] 全部测试项执行完毕 ==="
