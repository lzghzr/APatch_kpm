#!/usr/bin/env python3
"""
run_nmbench_point.py: Orchestrates NoMount ADD/DEL standalone point measurements on Sony XQ-DQ72.
Role: Tester
"""

import os
import sys
import time
import subprocess
import json
import hashlib
import shutil
import glob
import argparse
from typing import Dict, List, Any

TARGET_SERIAL = os.environ.get("ANDROID_SERIAL", "").strip()
if not TARGET_SERIAL:
    sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量 (例如: export ANDROID_SERIAL=...)")
DEVICE_DIR = "/data/local/tmp/nmbench"
LOCAL_RAW_DIR = "local/keep/evidence/tester-raw/nmbench/point"
RUNNER_SRC = "Tester/tools/nmbench_point_runner.c"
LOCAL_BIN = os.path.join(LOCAL_RAW_DIR, "nmbench_point_runner")

def find_ndk_clang() -> str:
    ndk = os.environ.get("ANDROID_NDK_ROOT") or os.environ.get("ANDROID_NDK_HOME")
    if ndk:
        cand = os.path.join(ndk, "toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang")
        if os.path.exists(cand):
            return cand
    cand = shutil.which("aarch64-linux-android34-clang")
    if cand:
        return cand
    home = os.path.expanduser("~")
    matches = glob.glob(os.path.join(home, "Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android34-clang"))
    if matches:
        return sorted(matches)[-1]
    return "aarch64-linux-android34-clang"

NDK_CLANG = find_ndk_clang()

def run_adb(cmd: str, timeout: int = 60) -> str:
    prefix = ["adb"] + (["-s", TARGET_SERIAL] if TARGET_SERIAL else [])
    full_cmd = prefix + ["shell", f"su -c '{cmd}'"]
    res = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f"ADB command failed (rc={res.returncode}): {cmd}\nStderr: {res.stderr}")
    return res.stdout.strip()

def adb_push(local: str, remote: str):
    prefix = ["adb"] + (["-s", TARGET_SERIAL] if TARGET_SERIAL else [])
    subprocess.run(prefix + ["push", local, remote], check=True, stdout=subprocess.PIPE)

def adb_pull(remote: str, local: str):
    prefix = ["adb"] + (["-s", TARGET_SERIAL] if TARGET_SERIAL else [])
    subprocess.run(prefix + ["pull", remote, local], check=True, stdout=subprocess.PIPE)

def get_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_rule_count() -> int:
    out = run_adb("/data/adb/ap/bin/nm rule list | wc -l")
    return int(out.strip())

def get_cur_freqs() -> Dict[str, str]:
    out = run_adb("for c in 0 1 2 3 4 5 6 7; do echo -n \"cpu$c:\"; cat /sys/devices/system/cpu/cpu$c/cpufreq/scaling_cur_freq 2>/dev/null; done")
    res = {}
    for line in out.splitlines():
        if ":" in line:
            parts = line.split(":")
            res[parts[0].strip()] = parts[1].strip()
    return res

def get_temperatures() -> Dict[str, str]:
    out = run_adb("for z in /sys/class/thermal/thermal_zone*; do type=$(cat $z/type 2>/dev/null); temp=$(cat $z/temp 2>/dev/null); echo \"$type:$temp\"; done")
    res = {}
    for line in out.splitlines():
        if ":" in line:
            parts = line.split(":")
            t_type, temp = parts[0].strip(), parts[1].strip()
            if any(k in t_type for k in ["cpu", "cpuss", "soc", "battery", "skin"]):
                res[t_type] = temp
    return res

def compile_runner():
    os.makedirs(LOCAL_RAW_DIR, exist_ok=True)
    cmd = [NDK_CLANG, "-O2", "-Wall", RUNNER_SRC, "-o", LOCAL_BIN]
    print(f"Compiling {RUNNER_SRC} -> {LOCAL_BIN}")
    subprocess.run(cmd, check=True)
    print(f"Compiled successfully. SHA256: {get_sha256(LOCAL_BIN)}")

def run_suite(label: str, run_p4: bool = False):
    print(f"\n========================================================")
    print(f"=== Starting NoMount Point Measurement: {label} ===")
    print(f"========================================================")
    os.makedirs(LOCAL_RAW_DIR, exist_ok=True)

    compile_runner()
    runner_c_sha = get_sha256(RUNNER_SRC)
    runner_bin_sha = get_sha256(LOCAL_BIN)
    script_sha = get_sha256(__file__)

    init_rules = get_rule_count()
    print(f"Initial rule count check: {init_rules}")
    if init_rules != 47:
        raise RuntimeError(f"Expected 47 baseline rules, but found {init_rules}!")

    run_adb(f"mkdir -p {DEVICE_DIR} && chmod 777 {DEVICE_DIR}")
    adb_push(LOCAL_BIN, f"{DEVICE_DIR}/nmbench_point_runner")
    run_adb(f"chmod 755 {DEVICE_DIR}/nmbench_point_runner")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner setup")

    device_csv = f"{DEVICE_DIR}/{label}.csv"
    run_adb(f"rm -f {device_csv}")

    boot_id = run_adb("cat /proc/sys/kernel/random/boot_id")
    kpm_sha = run_adb("sha256sum /data/adb/ap/kpm/NoMount/NoMount.kpm").split()[0]
    print(f"Device boot_id: {boot_id}")
    print(f"Active KPM sha256: {kpm_sha}")

    meta = {
        "session_label": label,
        "boot_id": boot_id,
        "kpm_sha256": kpm_sha,
        "timestamp_start": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "runner_c_sha": runner_c_sha,
        "runner_bin_sha": runner_bin_sha,
        "script_sha": script_sha,
        "init_rules": init_rules,
        "initial_freqs": get_cur_freqs(),
        "initial_temps": get_temperatures(),
        "phases": {}
    }

    # ----------------------------------------------------
    # P1: Pure ADD point test (47 scale and 500 scale)
    # ----------------------------------------------------
    print("\n>>> P1: Pure ADD Point Test <<<")

    # P1 at 47 scale
    print("P1: Adding 200 rules at 47 baseline scale...")
    t0 = time.time()
    out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p1 47 {device_csv}")
    t1 = time.time()
    print(out)
    cnt = get_rule_count()
    print(f"Rule count after P1(47): {cnt}")
    if cnt != 47:
        raise RuntimeError(f"Rule count after P1(47) not 47! Found {cnt}")
    meta["phases"]["P1_scale47"] = {"duration_s": t1 - t0}

    # P1 at 500 scale
    print("\nP1: Injecting 453 background rules to reach 500 scale...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner inject_bg 453")
    cnt500 = get_rule_count()
    print(f"Rule count before P1(500): {cnt500}")
    if cnt500 != 500:
        raise RuntimeError(f"Expected 500 rules, got {cnt500}!")

    print("P1: Adding 200 rules at 500 scale...")
    t0 = time.time()
    out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p1 500 {device_csv}")
    t1 = time.time()
    print(out)

    print("Cleaning 453 background rules...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner clean_bg 453")
    cnt = get_rule_count()
    print(f"Rule count after P1(500) cleanup: {cnt}")
    if cnt != 47:
        raise RuntimeError(f"Rule count after P1(500) cleanup not 47! Found {cnt}")
    meta["phases"]["P1_scale500"] = {"duration_s": t1 - t0}

    # ----------------------------------------------------
    # P2: Pure DEL point test (P2a Busy vs P2b Idle, 3 rounds each)
    # ----------------------------------------------------
    print("\n>>> P2: Pure DEL Point Test (Busy vs Idle) <<<")
    print("Setting up base 300 rules (injecting 253 bg rules)...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner inject_bg 253")
    cnt300 = get_rule_count()
    print(f"Base rule count: {cnt300}")
    if cnt300 != 300:
        raise RuntimeError(f"Expected 300 rules, got {cnt300}!")

    # P2a: Busy condition (3 rounds)
    print("\n--- P2a: Busy Condition (DEL immediately follows ADD) ---")
    for r in range(1, 4):
        print(f"P2a Busy - Round {r}/3...")
        t0 = time.time()
        out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p2a {r} {device_csv}")
        t1 = time.time()
        print(out)
        cnt = get_rule_count()
        if cnt != 300:
            raise RuntimeError(f"Rule count after P2a r{r} not 300! Found {cnt}")
        meta["phases"][f"P2a_busy_r{r}"] = {"duration_s": t1 - t0}

    # P2b: Idle condition (3 rounds)
    print("\n--- P2b: Idle Condition (Wait 0.2s queue drain before DEL) ---")
    for r in range(1, 4):
        print(f"P2b Idle - Round {r}/3...")
        t0 = time.time()
        out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p2b {r} {device_csv}")
        t1 = time.time()
        print(out)
        cnt = get_rule_count()
        if cnt != 300:
            raise RuntimeError(f"Rule count after P2b r{r} not 300! Found {cnt}")
        meta["phases"][f"P2b_idle_r{r}"] = {"duration_s": t1 - t0}

    print("Cleaning 253 background rules...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner clean_bg 253")
    cnt = get_rule_count()
    print(f"Rule count after P2 cleanup: {cnt}")
    if cnt != 47:
        raise RuntimeError(f"Rule count after P2 cleanup not 47! Found {cnt}")

    # ----------------------------------------------------
    # P3: Scale tiers (47, 200, 500)
    # ----------------------------------------------------
    print("\n>>> P3: Scale Tiers (47 / 200 / 500) <<<")

    # P3 at 47
    print("P3 Scale 47 (20 samples ADD + DEL)...")
    t0 = time.time()
    out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p3 47 {device_csv}")
    t1 = time.time()
    print(out)
    cnt = get_rule_count()
    if cnt != 47:
        raise RuntimeError(f"Rule count after P3(47) not 47! Found {cnt}")
    meta["phases"]["P3_scale47"] = {"duration_s": t1 - t0}

    # P3 at 200
    print("\nP3 Scale 200 (injecting 153 bg rules)...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner inject_bg 153")
    cnt200 = get_rule_count()
    if cnt200 != 200:
        raise RuntimeError(f"Expected 200 rules, got {cnt200}!")
    t0 = time.time()
    out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p3 200 {device_csv}")
    t1 = time.time()
    print(out)
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner clean_bg 153")
    cnt = get_rule_count()
    if cnt != 47:
        raise RuntimeError(f"Rule count after P3(200) cleanup not 47! Found {cnt}")
    meta["phases"]["P3_scale200"] = {"duration_s": t1 - t0}

    # P3 at 500
    print("\nP3 Scale 500 (injecting 453 bg rules)...")
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner inject_bg 453")
    cnt500 = get_rule_count()
    if cnt500 != 500:
        raise RuntimeError(f"Expected 500 rules, got {cnt500}!")
    t0 = time.time()
    out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p3 500 {device_csv}")
    t1 = time.time()
    print(out)
    run_adb(f"{DEVICE_DIR}/nmbench_point_runner clean_bg 453")
    cnt = get_rule_count()
    if cnt != 47:
        raise RuntimeError(f"Rule count after P3(500) cleanup not 47! Found {cnt}")
    meta["phases"]["P3_scale500"] = {"duration_s": t1 - t0}

    # ----------------------------------------------------
    # P4: Visibility & Interleaving (if requested)
    # ----------------------------------------------------
    if run_p4:
        print("\n>>> P4: Immediate Visibility & Held FD Across DEL/Re-Add <<<")
        t0 = time.time()
        out = run_adb(f"{DEVICE_DIR}/nmbench_point_runner p4 {device_csv}")
        t1 = time.time()
        print(out)
        cnt = get_rule_count()
        if cnt != 47:
            raise RuntimeError(f"Rule count after P4 not 47! Found {cnt}")
        meta["phases"]["P4"] = {"duration_s": t1 - t0}

    # ----------------------------------------------------
    # Post-flight verification & evidence pull
    # ----------------------------------------------------
    final_rules = get_rule_count()
    print(f"\nFinal rule count check: {final_rules}")
    if final_rules != 47:
        raise RuntimeError(f"Final rule count is {final_rules}, expected 47!")

    meta["timestamp_end"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    meta["final_rules"] = final_rules
    meta["final_freqs"] = get_cur_freqs()
    meta["final_temps"] = get_temperatures()

    local_csv = os.path.join(LOCAL_RAW_DIR, f"{label}.csv")
    adb_pull(device_csv, local_csv)
    meta["csv_sha256"] = get_sha256(local_csv)
    meta["csv_bytes"] = os.path.getsize(local_csv)
    print(f"Pulled {local_csv} ({meta['csv_bytes']} bytes, SHA256: {meta['csv_sha256']})")

    local_meta = os.path.join(LOCAL_RAW_DIR, f"{label}_meta.json")
    with open(local_meta, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved metadata to {local_meta}")

    run_adb(f"rm -rf {DEVICE_DIR}")
    print("Remote temporary directory cleaned up.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NoMount Point Benchmark Orchestrator")
    parser.add_argument("--label", required=True, help="Session label, e.g. candidate1, baseline, candidate2")
    parser.add_argument("--p4", action="store_true", help="Run P4 visibility & held fd verification")
    args = parser.parse_args()

    run_suite(args.label, run_p4=args.p4)
