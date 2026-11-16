#!/usr/bin/env python3
"""
run_nmbench.py: Orchestrates NoMount A/B/C performance baseline measurements on Sony XQ-DQ72.
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
LOCAL_RAW_DIR = "local/keep/evidence/tester-raw/nmbench"
REPORT_PATH = "Tester/reports/2026-11-15-nomount-perf-baseline.md"
RUNNER_SRC = "Tester/tools/nmbench_runner.c"
LOCAL_BIN = os.path.join(LOCAL_RAW_DIR, "nmbench_runner")

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

def batch_add_rules(rules: List[Any], chunk_size: int = 50):
    for i in range(0, len(rules), chunk_size):
        chunk = rules[i:i + chunk_size]
        args_str = " ".join([f"{v} {r}" for v, r in chunk])
        run_adb(f"/data/adb/ap/bin/nm rule add {args_str}")

def batch_del_rules(vpaths: List[str], chunk_size: int = 50):
    for i in range(0, len(vpaths), chunk_size):
        chunk = vpaths[i:i + chunk_size]
        args_str = " ".join(chunk)
        run_adb(f"/data/adb/ap/bin/nm rule del {args_str}")

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
    cmd = [NDK_CLANG, "-O2", "-Wall", "-pthread", RUNNER_SRC, "-o", LOCAL_BIN]
    print(f"Compiling {RUNNER_SRC} -> {LOCAL_BIN}")
    subprocess.run(cmd, check=True)
    print(f"Compiled successfully. SHA256: {get_sha256(LOCAL_BIN)}")

def main():
    parser = argparse.ArgumentParser(description="NoMount Performance Benchmark Orchestrator")
    parser.add_argument("--mode", choices=["full", "aba"], default="full", help="Benchmark mode: full or aba subset")
    parser.add_argument("--output-prefix", default="", help="Prefix for evidence files (e.g. baseline2)")
    args = parser.parse_args()

    print(f"=== NoMount Performance Benchmark Orchestrator (Mode: {args.mode}) ===")
    os.makedirs(LOCAL_RAW_DIR, exist_ok=True)

    # 1. Compile runner and push to device
    compile_runner()
    runner_c_sha = get_sha256(RUNNER_SRC)
    runner_bin_sha = get_sha256(LOCAL_BIN)
    script_sha = get_sha256(__file__)

    print(f"Runner C SHA256: {runner_c_sha}")
    print(f"Runner Bin SHA256: {runner_bin_sha}")
    print(f"Script SHA256: {script_sha}")

    # 2. Check rule baseline
    init_rules = get_rule_count()
    print(f"Initial rule count: {init_rules}")
    if init_rules != 47:
        raise RuntimeError(f"Expected 47 baseline rules, but found {init_rules}!")

    # 3. Setup device
    run_adb(f"mkdir -p {DEVICE_DIR} && chmod 777 {DEVICE_DIR}")
    adb_push(LOCAL_BIN, f"{DEVICE_DIR}/nmbench_runner")
    run_adb(f"chmod 755 {DEVICE_DIR}/nmbench_runner")
    run_adb(f"{DEVICE_DIR}/nmbench_runner setup")

    # Clean existing test CSV if any
    run_adb(f"rm -f {DEVICE_DIR}/bench.csv")

    boot_id = run_adb("cat /proc/sys/kernel/random/boot_id")
    kpm_sha = run_adb("sha256sum /data/adb/ap/kpm/NoMount/NoMount.kpm").split()[0]
    print(f"Device boot_id: {boot_id}")
    print(f"Active KPM sha256: {kpm_sha}")

    meta = {
        "mode": args.mode,
        "boot_id": boot_id,
        "kpm_sha256": kpm_sha,
        "timestamp_start": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "runner_c_sha": runner_c_sha,
        "runner_bin_sha": runner_bin_sha,
        "script_sha": script_sha,
        "init_rules": init_rules,
        "initial_freqs": get_cur_freqs(),
        "initial_temps": get_temperatures(),
        "rounds": {}
    }

    # ==========================================
    # SECTION A: File Materialization & Open Cost
    # ==========================================
    print("\n--- Starting Section A: File Materialization & Open Cost ---")
    run_adb(f"/data/adb/ap/bin/nm rule add /system/etc/nmbench_a_file {DEVICE_DIR}/backing_4k.bin")
    if get_rule_count() != 48:
        raise RuntimeError(f"Failed to add Section A virtual rule! Count={get_rule_count()}")

    for r in range(1, 4):
        print(f"Section A - Round {r}/3")
        f_before = get_cur_freqs()
        t0 = time.time()
        out = run_adb(f"{DEVICE_DIR}/nmbench_runner bench_a --round {r} --samples 1000 --csv {DEVICE_DIR}/bench.csv")
        t1 = time.time()
        f_after = get_cur_freqs()
        print(out)
        meta["rounds"][f"A_r{r}"] = {
            "duration_s": t1 - t0,
            "freq_before": f_before,
            "freq_after": f_after,
        }

    run_adb(f"/data/adb/ap/bin/nm rule del /system/etc/nmbench_a_file")
    cnt_after_a = get_rule_count()
    print(f"Rule count after Section A cleanup: {cnt_after_a}")
    if cnt_after_a != 47:
        raise RuntimeError(f"Rule count after Section A not 47! Found {cnt_after_a}")

    # ==========================================
    # SECTION B: Rule and Dentry Lookup Scaling
    # ==========================================
    print("\n--- Starting Section B: Rule and Dentry Lookup Scaling ---")

    # B Tiers: 50, 200, 500 rules
    # Injected counts: 50 -> 3; 200 -> 153; 500 -> 453
    tiers = [
        ("rules_50", 3, 50),
        ("rules_200", 153, 200),
        ("rules_500", 453, 500)
    ]

    for tier_name, inject_cnt, target_total in tiers:
        print(f"\nSection B Tier {tier_name} (injecting {inject_cnt} rules to reach {target_total})...")
        rules_to_add = [(f"/system/etc/nmbench_b_rule_{i:04d}", f"{DEVICE_DIR}/backing_4k.bin") for i in range(1, inject_cnt + 1)]
        batch_add_rules(rules_to_add)
        cur_cnt = get_rule_count()
        print(f"Injected rules. Current count: {cur_cnt}")
        if cur_cnt != target_total:
            raise RuntimeError(f"Expected {target_total} rules, got {cur_cnt}!")

        for r in range(1, 4):
            print(f"Section B Tier {tier_name} - Round {r}/3")
            f_before = get_cur_freqs()
            t0 = time.time()
            out = run_adb(f"{DEVICE_DIR}/nmbench_runner bench_b --tier {tier_name} --round {r} --samples 1000 --csv {DEVICE_DIR}/bench.csv")
            t1 = time.time()
            f_after = get_cur_freqs()
            print(out)
            meta["rounds"][f"B_{tier_name}_r{r}"] = {
                "duration_s": t1 - t0,
                "freq_before": f_before,
                "freq_after": f_after,
            }

        # Delete injected rules
        del_paths = [f"/system/etc/nmbench_b_rule_{i:04d}" for i in range(1, inject_cnt + 1)]
        batch_del_rules(del_paths)
        cnt_clean = get_rule_count()
        print(f"Cleaned {tier_name}. Rule count: {cnt_clean}")
        if cnt_clean != 47:
            raise RuntimeError(f"Rule count after {tier_name} cleanup not 47! Got {cnt_clean}")

    if args.mode != "aba":
        # B Directory Lookup: 10 entries vs 1000 entries (Full mode only)
        dir_tiers = [
            (10, "/system/etc/nmbench_dir/entry_0005"),
            (1000, "/system/etc/nmbench_dir/entry_0500")
        ]
        for d_cnt, target_path in dir_tiers:
            print(f"\nSection B Dir Lookup: {d_cnt} entries...")
            rules_to_add = [(f"/system/etc/nmbench_dir/entry_{i:04d}", f"{DEVICE_DIR}/backing_4k.bin") for i in range(1, d_cnt + 1)]
            batch_add_rules(rules_to_add)
            print(f"Added {d_cnt} dir entries. Total count: {get_rule_count()}")

            for r in range(1, 4):
                print(f"Section B Dir {d_cnt} - Round {r}/3")
                f_before = get_cur_freqs()
                t0 = time.time()
                out = run_adb(f"{DEVICE_DIR}/nmbench_runner bench_b_dir --entries {d_cnt} --target {target_path} --round {r} --samples 1000 --csv {DEVICE_DIR}/bench.csv")
                t1 = time.time()
                f_after = get_cur_freqs()
                print(out)
                meta["rounds"][f"B_dir_{d_cnt}_r{r}"] = {
                    "duration_s": t1 - t0,
                    "freq_before": f_before,
                    "freq_after": f_after,
                }

            del_paths = [f"/system/etc/nmbench_dir/entry_{i:04d}" for i in range(1, d_cnt + 1)]
            batch_del_rules(del_paths)
            cnt_clean = get_rule_count()
            print(f"Cleaned dir {d_cnt}. Rule count: {cnt_clean}")
            if cnt_clean != 47:
                raise RuntimeError(f"Rule count after dir {d_cnt} cleanup not 47! Got {cnt_clean}")

    # ==========================================
    # SECTION C: Management Operation Latency
    # ==========================================
    print("\n--- Starting Section C: Management Operation Latency ---")

    if args.mode == "aba":
        c_tiers = [
            (47, 0),
            (500, 453)
        ]
    else:
        c_tiers = [
            (47, 0),
            (200, 153),
            (500, 453)
        ]

    for target_total, inject_cnt in c_tiers:
        if inject_cnt > 0:
            print(f"\nInjecting {inject_cnt} rules for Section C Tier {target_total}...")
            rules_to_add = [(f"/system/etc/nmbench_c_bg_{i:04d}", f"{DEVICE_DIR}/backing_4k.bin") for i in range(1, inject_cnt + 1)]
            batch_add_rules(rules_to_add)
            cur_cnt = get_rule_count()
            print(f"Current rule count: {cur_cnt}")
            if cur_cnt != target_total:
                raise RuntimeError(f"Expected {target_total} rules, got {cur_cnt}!")

        # Sub-test 1: Idle (read_load = 0)
        print(f"\nSection C - Tier {target_total} Rules [IDLE]")
        for r in range(1, 4):
            print(f"Section C - Tier {target_total} [IDLE] - Round {r}/3")
            f_before = get_cur_freqs()
            t0 = time.time()
            out = run_adb(f"{DEVICE_DIR}/nmbench_runner bench_c --tier {target_total} --read-load 0 --round {r} --samples 1000 --csv {DEVICE_DIR}/bench.csv")
            t1 = time.time()
            f_after = get_cur_freqs()
            print(out)
            meta["rounds"][f"C_r{target_total}_idle_r{r}"] = {
                "duration_s": t1 - t0,
                "freq_before": f_before,
                "freq_after": f_after,
            }

        # Sub-test 2: Under Read Load (read_load = 1) - Full mode only
        if args.mode != "aba":
            print(f"\nSection C - Tier {target_total} Rules [UNDER READ LOAD]")
            for r in range(1, 4):
                print(f"Section C - Tier {target_total} [LOAD] - Round {r}/3")
                f_before = get_cur_freqs()
                t0 = time.time()
                out = run_adb(f"{DEVICE_DIR}/nmbench_runner bench_c --tier {target_total} --read-load 1 --round {r} --samples 1000 --csv {DEVICE_DIR}/bench.csv")
                t1 = time.time()
                f_after = get_cur_freqs()
                print(out)
                meta["rounds"][f"C_r{target_total}_load_r{r}"] = {
                    "duration_s": t1 - t0,
                    "freq_before": f_before,
                    "freq_after": f_after,
                }

        if inject_cnt > 0:
            del_paths = [f"/system/etc/nmbench_c_bg_{i:04d}" for i in range(1, inject_cnt + 1)]
            batch_del_rules(del_paths)
            cnt_clean = get_rule_count()
            print(f"Cleaned C {target_total}. Rule count: {cnt_clean}")
            if cnt_clean != 47:
                raise RuntimeError(f"Rule count after C {target_total} cleanup not 47! Got {cnt_clean}")

    # ==========================================
    # Post-Flight Verification & Evidence Pull
    # ==========================================
    final_rules = get_rule_count()
    print(f"\nFinal rule count check: {final_rules}")
    if final_rules != 47:
        raise RuntimeError(f"Final rule count is {final_rules}, expected 47!")

    meta["timestamp_end"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    meta["final_rules"] = final_rules
    meta["final_freqs"] = get_cur_freqs()
    meta["final_temps"] = get_temperatures()

    # Pull bench.csv
    run_adb(f"chmod 666 {DEVICE_DIR}/bench.csv")
    local_csv = os.path.join(LOCAL_RAW_DIR, "bench.csv")
    adb_pull(f"{DEVICE_DIR}/bench.csv", local_csv)
    print(f"Pulled raw data to {local_csv} (size: {os.path.getsize(local_csv)} bytes)")
    meta["csv_sha256"] = get_sha256(local_csv)

    if args.output_prefix:
        dest_csv = os.path.join(LOCAL_RAW_DIR, f"{args.output_prefix}.csv")
        shutil.copy2(local_csv, dest_csv)
        print(f"Copied to {dest_csv}")

    # Save metadata JSON
    meta_path = os.path.join(LOCAL_RAW_DIR, "meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved metadata to {meta_path}")

    if args.output_prefix:
        dest_meta = os.path.join(LOCAL_RAW_DIR, f"{args.output_prefix}_meta.json")
        with open(dest_meta, "w") as f:
            json.dump(meta, f, indent=2)
        print(f"Saved metadata to {dest_meta}")

    # Cleanup remote temporary directory
    run_adb(f"rm -rf {DEVICE_DIR}")
    print("Device temporary directory cleaned up.")

    print("\nBenchmark run completed successfully!")

if __name__ == "__main__":
    main()
