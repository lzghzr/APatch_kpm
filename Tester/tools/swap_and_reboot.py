#!/usr/bin/env python3
"""
swap_and_reboot.py: Safely replaces NoMount.kpm on Sony XQ-DQ72 and reboots once.
Role: Tester
"""

import os
import sys
import time
import subprocess
import argparse

TARGET_SERIAL = os.environ.get("ANDROID_SERIAL", "").strip()
if not TARGET_SERIAL:
    sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量 (例如: export ANDROID_SERIAL=...)")

def run_cmd(cmd: list, timeout: int = 60) -> str:
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed (rc={res.returncode}): {' '.join(cmd)}\nStderr: {res.stderr}")
    return res.stdout.strip()

def run_adb(shell_cmd: str, timeout: int = 60) -> str:
    prefix = ["adb"] + (["-s", TARGET_SERIAL] if TARGET_SERIAL else [])
    full = prefix + ["shell", f"su -c '{shell_cmd}'"]
    return run_cmd(full, timeout=timeout)

def main():
    parser = argparse.ArgumentParser(description="Replace NoMount.kpm and reboot device")
    parser.add_argument("--kpm", required=True, help="Path to local KPM file")
    parser.add_argument("--expected-sha", required=True, help="Expected SHA256 of the KPM")
    args = parser.parse_args()

    if not os.path.exists(args.kpm):
        raise FileNotFoundError(f"Local KPM not found: {args.kpm}")

    prefix = ["adb"] + (["-s", TARGET_SERIAL] if TARGET_SERIAL else [])

    # Check old boot_id and active KPM
    old_boot_id = run_adb("cat /proc/sys/kernel/random/boot_id")
    old_kpm_sha = run_adb("sha256sum /data/adb/ap/kpm/NoMount/NoMount.kpm").split()[0]
    print(f"Current boot_id: {old_boot_id}")
    print(f"Current active KPM SHA256: {old_kpm_sha}")

    # Push new KPM
    print(f"Pushing {args.kpm} -> /data/local/tmp/new_nomount.kpm ...")
    run_cmd(prefix + ["push", args.kpm, "/data/local/tmp/new_nomount.kpm"])

    # Overwrite in APatch directory
    print("Installing KPM to /data/adb/ap/kpm/NoMount/NoMount.kpm ...")
    run_adb("cp /data/local/tmp/new_nomount.kpm /data/adb/ap/kpm/NoMount/NoMount.kpm && chmod 644 /data/adb/ap/kpm/NoMount/NoMount.kpm && chown root:root /data/adb/ap/kpm/NoMount/NoMount.kpm && rm -f /data/local/tmp/new_nomount.kpm")

    # Verify SHA256 before reboot
    staged_sha = run_adb("sha256sum /data/adb/ap/kpm/NoMount/NoMount.kpm").split()[0]
    print(f"Staged KPM SHA256: {staged_sha}")
    if staged_sha != args.expected_sha:
        raise ValueError(f"Staged SHA256 mismatch! Expected {args.expected_sha}, got {staged_sha}")

    # Trigger planned single reboot
    print("Triggering single planned reboot (adb reboot)...")
    run_cmd(prefix + ["reboot"])

    # Wait for device to go down
    print("Waiting for device to disconnect...")
    time.sleep(5)

    # Wait for device to come back up
    print("Waiting for device to reconnect...")
    run_cmd(prefix + ["wait-for-device"], timeout=180)

    # Wait for sys.boot_completed
    print("Waiting for sys.boot_completed=1 ...")
    for _ in range(60):
        try:
            res = subprocess.run(prefix + ["shell", "getprop", "sys.boot_completed"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip() == "1":
                break
        except Exception:
            pass
        time.sleep(2)
    else:
        raise TimeoutError("Device did not report sys.boot_completed=1 within timeout!")

    # Wait a few seconds for system stabilization
    time.sleep(5)

    new_boot_id = run_adb("cat /proc/sys/kernel/random/boot_id")
    new_kpm_sha = run_adb("sha256sum /data/adb/ap/kpm/NoMount/NoMount.kpm").split()[0]
    rules_cnt = run_adb("/data/adb/ap/bin/nm rule list | wc -l").strip()

    print(f"Reboot successful!")
    print(f"New boot_id: {new_boot_id}")
    print(f"New KPM SHA256: {new_kpm_sha}")
    print(f"Current rules count: {rules_cnt}")

    if new_boot_id == old_boot_id:
        raise RuntimeError("boot_id did not change! Device did not reboot.")
    if new_kpm_sha != args.expected_sha:
        raise RuntimeError(f"Active KPM SHA256 mismatch after reboot! Expected {args.expected_sha}, got {new_kpm_sha}")
    if int(rules_cnt) != 47:
        raise RuntimeError(f"Expected 47 baseline rules after reboot, got {rules_cnt}!")

if __name__ == "__main__":
    main()
