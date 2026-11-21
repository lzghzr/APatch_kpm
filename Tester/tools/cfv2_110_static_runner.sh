#!/system/bin/sh
# Tester/tools/cfv2_110_static_runner.sh
# 运行在真机 Android 环境下的静态版测试执行器 (cgroupv2_freeze 1.1.0 静态基线打表版)
# 依据 1.1.0 测试任务书 7 条判据 (5 标准 + 2 静态专有)

set -e

RES_DIR="/data/local/tmp/cfv2_110_static_results"
rm -rf "$RES_DIR"
mkdir -p "$RES_DIR"

echo "=== [Runner] 开始执行 cgroupv2_freeze 1.1.0 静态版真机测试 ==="

# 1. 上机字节与引导状态
echo "=== [Step 1] 上机字节与引导状态 ==="
sha256sum /data/local/tmp/cgroupv2_freeze_1.1.0_baselines.kpm > "$RES_DIR/kpm_sha256.txt" 2>&1 || true
stat -c '%s' /data/local/tmp/cgroupv2_freeze_1.1.0_baselines.kpm > "$RES_DIR/kpm_size.txt" 2>&1 || true
getprop sys.boot_completed > "$RES_DIR/boot_completed.txt"
cat /proc/sys/kernel/random/boot_id > "$RES_DIR/boot_id.txt"
cat /proc/uptime > "$RES_DIR/uptime.txt"
sha256sum /dev/block/bootdevice/by-name/boot_b > "$RES_DIR/boot_b_sha256.txt" 2>&1 || true

# 弱证据：内核崩溃统计
dmesg | grep -c "BUG:" > "$RES_DIR/bug_count.txt" || echo "0" > "$RES_DIR/bug_count.txt"
dmesg | grep -c "Kernel panic" > "$RES_DIR/panic_count.txt" || echo "0" > "$RES_DIR/panic_count.txt"

# 2. 引导期加载与事件日志
echo "=== [Step 2] 引导期加载与事件日志 ==="
dmesg | grep -E "cgroupv2_freeze|KP load kpm: cgroupv2_freeze" > "$RES_DIR/dmesg_boot_cfv2.txt" || true

# 3. 判据 1：带内容的挂载
echo "=== [Step 3] 判据 1：带内容的挂载 ==="
cat /proc/1/mountinfo > "$RES_DIR/proc_1_mountinfo.txt"
ls -1 /acct | wc -l > "$RES_DIR/acct_entry_count.txt"
ls -1 /sys/fs/cgroup | wc -l > "$RES_DIR/sys_cgroup_entry_count.txt"
ls -d1 /acct/uid_* 2>/dev/null | wc -l > "$RES_DIR/acct_uid_count.txt"
ls -d1 /sys/fs/cgroup/uid_* 2>/dev/null | wc -l > "$RES_DIR/sys_cgroup_uid_count.txt"

if [ -d "/sys/fs/cgroup/uid_0" ]; then
  echo "EXISTS" > "$RES_DIR/uid_0_exists.txt"
else
  echo "MISSING" > "$RES_DIR/uid_0_exists.txt"
fi

# 4. 判据 2：自建组与 freeze 文件
echo "=== [Step 4] 判据 2：自建组与 freeze 文件 ==="
stat -c '%u:%g %a %n' /sys/fs/cgroup/frozen > "$RES_DIR/stat_frozen_dir.txt"
stat -c '%u:%g %a %n' /sys/fs/cgroup/unfrozen > "$RES_DIR/stat_unfrozen_dir.txt"
stat -c '%u:%g %a %n' /sys/fs/cgroup/frozen/cgroup.freeze > "$RES_DIR/stat_frozen_freeze.txt"
stat -c '%u:%g %a %n' /sys/fs/cgroup/unfrozen/cgroup.freeze > "$RES_DIR/stat_unfrozen_freeze.txt"
cat /sys/fs/cgroup/frozen/cgroup.freeze > "$RES_DIR/val_frozen_freeze.txt"
cat /sys/fs/cgroup/unfrozen/cgroup.freeze > "$RES_DIR/val_unfrozen_freeze.txt"

stat -c '%u:%g %a %n' /sys/fs/cgroup/uid_0/cgroup.freeze > "$RES_DIR/stat_uid0_freeze.txt" 2>&1 || true
stat -c '%u:%g %a %n' /sys/fs/cgroup/uid_1000/cgroup.freeze > "$RES_DIR/stat_uid1000_freeze.txt" 2>&1 || true
stat -c '%u:%g %a %n' /sys/fs/cgroup/uid_9999/cgroup.freeze > "$RES_DIR/stat_uid9999_freeze.txt" 2>&1 || true

{
  echo "--- uid_9999 read/write test ---"
  echo "initial=$(cat /sys/fs/cgroup/uid_9999/cgroup.freeze 2>/dev/null || echo missing)"
  echo 1 > /sys/fs/cgroup/uid_9999/cgroup.freeze
  echo "after_1=$(cat /sys/fs/cgroup/uid_9999/cgroup.freeze)"
  echo 0 > /sys/fs/cgroup/uid_9999/cgroup.freeze
  echo "after_0=$(cat /sys/fs/cgroup/uid_9999/cgroup.freeze)"
} > "$RES_DIR/criterion2_rw_test.txt" 2>&1

# 5. 判据 3：零 cgroup_bpf AVC
echo "=== [Step 5] 判据 3：零 cgroup_bpf AVC ==="
getenforce > "$RES_DIR/getenforce.txt"
dmesg | grep -i avc | grep "cgroup_bpf" | wc -l > "$RES_DIR/dmesg_cgroup_bpf_avc_count.txt" || echo "0" > "$RES_DIR/dmesg_cgroup_bpf_avc_count.txt"
logcat -d | grep -i avc | grep "cgroup_bpf" | wc -l > "$RES_DIR/logcat_cgroup_bpf_avc_count.txt" || echo "0" > "$RES_DIR/logcat_cgroup_bpf_avc_count.txt"
dmesg | grep -i avc | grep "cgroup" > "$RES_DIR/dmesg_cgroup_avc_lines.txt" || true
logcat -d | grep -i avc | grep "cgroup" > "$RES_DIR/logcat_cgroup_avc_lines.txt" || true
dmesg | grep -i avc > "$RES_DIR/dmesg_all_avc_lines.txt" || true

# 6. 判据 4：冻结能力（双视角）
echo "=== [Step 6] 判据 4：冻结能力（双视角） ==="

# ① UID 1000 探针视角
chmod 755 /data/local/tmp/cfv2_110_uid1000_probe.sh
su 1000 -c '/data/local/tmp/cfv2_110_uid1000_probe.sh' > "$RES_DIR/criterion4_uid1000_probe.txt" 2>&1 || true

# ② 真实写者路径记录（system_server / 框架视角）
{
  echo "=== system_server cgroup inspection ==="
  SS_PID=$(pidof system_server || true)
  echo "system_server PID: $SS_PID"
  if [ -n "$SS_PID" ]; then
    echo "system_server context: $(cat /proc/$SS_PID/attr/current 2>/dev/null || echo unknown)"
    echo "system_server open fds pointing to cgroup:"
    ls -l /proc/$SS_PID/fd 2>/dev/null | grep -i cgroup || echo "None open"
  fi
  echo "use_freezer setting: $(cmd device_config get activity_manager_native_boot use_freezer 2>/dev/null || echo 'not supported')"
  echo "SELinux labels:"
  ls -Zd /sys/fs/cgroup /acct /dev/cg2_bpf /sys/fs/cgroup/frozen /sys/fs/cgroup/uid_0
} > "$RES_DIR/criterion4_real_writer_path.txt" 2>&1

# ③ 受控进程冻结验证 (Root perspective on test_freeze_ctrl)
{
  CTRL_DIR="/sys/fs/cgroup/test_freeze_ctrl"
  CTRL_BEAT="/data/local/tmp/freeze_beat_ctrl.log"
  rm -rf "$CTRL_DIR" "$CTRL_BEAT" 2>/dev/null || true
  mkdir "$CTRL_DIR"
  
  sh -c 'i=0; while true; do echo $i > /data/local/tmp/freeze_beat_ctrl.log; i=$((i+1)); sleep 0.1; done' &
  CTRL_PID=$!
  echo "$CTRL_PID" > "$CTRL_DIR/cgroup.procs"
  
  sleep 0.5
  R1="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  sleep 1
  R2="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  echo "Running heartbeat: $R1 -> $R2"
  
  echo 1 > "$CTRL_DIR/cgroup.freeze"
  sleep 0.3
  WCHAN="$(cat /proc/$CTRL_PID/wchan 2>/dev/null || echo unknown)"
  STATE="$(cat /proc/$CTRL_PID/stat 2>/dev/null | cut -d' ' -f3 || echo unknown)"
  F1="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  sleep 2
  F2="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  echo "cgroup.freeze=1 written"
  echo "Frozen window (2s): $F1 -> $F2 (state=$STATE wchan=$WCHAN)"
  
  echo 0 > "$CTRL_DIR/cgroup.freeze"
  echo "cgroup.freeze=0 written"
  sleep 0.5
  RES1="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  sleep 1
  RES2="$(cat "$CTRL_BEAT" 2>/dev/null || echo 0)"
  echo "Resumed window (1s): $RES1 -> $RES2"
  
  kill -9 "$CTRL_PID" 2>/dev/null || true
  sleep 0.5
  rmdir "$CTRL_DIR"
  rm -f "$CTRL_BEAT"
  echo "Controlled freeze test complete"
} > "$RES_DIR/criterion4_controlled_freeze.txt" 2>&1

# 7. 判据 5：引导链路
echo "=== [Step 7] 判据 5：引导链路 ==="
{
  echo "=== Pre-kernel-init / Post-kernel-init / Post-fs-data / Boot-completed Events ==="
  dmesg | grep -E "notify_modules_event.*cgroupv2_freeze|KP load kpm: cgroupv2_freeze|cgroupv2_freeze: UID tree ready" || true
} > "$RES_DIR/criterion5_boot_chain.txt" 2>&1

# 8. 判据 6（静态专有）：无 Static baseline: 拒载行
echo "=== [Step 8] 判据 6（静态专有）：检查 Static baseline 拒载行 ==="
dmesg | grep -i "Static baseline:" > "$RES_DIR/dmesg_static_baseline_rejection.txt" || true
STATIC_REJECT_COUNT=$(grep -c "Static baseline:" "$RES_DIR/dmesg_static_baseline_rejection.txt" || echo "0")
echo "$STATIC_REJECT_COUNT" > "$RES_DIR/static_reject_count.txt"

# 9. 判据 7（静态专有）：ctl0 事件链与卸载策略说明
echo "=== [Step 9] 判据 7（静态专有）：ctl0 事件链与模块信息 ==="
{
  echo "=== kpm info cgroupv2_freeze ==="
  su 10198 -c '/data/adb/kpatch su kpm info cgroupv2_freeze 2>/dev/null'
  echo "=== kpm ctl0 cgroupv2_freeze ping ==="
  su 10198 -c '/data/adb/kpatch su kpm ctl0 cgroupv2_freeze ping 2>/dev/null'
  echo "=== Unload policy note ==="
  echo "Policy: cgroup callbacks are persistent; do not unload; reboot to remove (恒返回 -EBUSY)"
} > "$RES_DIR/criterion7_ctl0_event_chain.txt" 2>&1

# 10. 导出完整日志与 pstore 检查
echo "=== [Step 10] 导出日志与 pstore ==="
dmesg > "$RES_DIR/dmesg_full.txt" 2>&1 || true
logcat -d > "$RES_DIR/logcat_full.txt" 2>&1 || true
if [ -f /sys/fs/pstore/console-ramoops ]; then
  cat /sys/fs/pstore/console-ramoops > "$RES_DIR/console-ramoops.txt" 2>&1 || true
fi

echo "=== [Runner] cgroupv2_freeze 1.1.0 静态版测试项执行完毕 ==="
