#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automated test runner for lz4 vs lz4-kpm alternating paired benchmark on zram block device.
Implements docs/records/2026-11-07-lz4-native-gap-request.md.
Device: device_a_6_12 (6.12.69)
6 cycles alternating lz4 and lz4-kpm (12 points total).
Measures compression/decompression throughput, compressed bytes, roundtrip sha256 integrity,
and cpu scaling frequencies before/after each point.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
SERIAL = os.environ.get("ANDROID_SERIAL")
DISKSIZE_BENCH = 1073741824  # 1 GiB
DISKSIZE_ORIG = 17179869184   # 16 GiB
CORPUS_PATH = "/data/local/tmp/corpus_256m.bin"
BENCH_BIN_PATH = "/data/local/tmp/zram_direct_bench"
ZRAM_DEV = "/dev/block/zram0"
TOTAL_BYTES = 268435456  # 256 MiB
CORPUS_EXPECTED_SHA = "9a0fc803babdae07b0dda1dce1ffe717c3b89e3567726155f8a0b58abd1f1b1e"
BENCH_EXPECTED_SHA = "a6edaace947aa2d2d0286bdf3e990bb79688b6f6b987c6595c7282f611cf24b8"


def run_adb(cmd_str: str, timeout: int = 60) -> str:
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")
    adb_cmd = ["adb", "-s", SERIAL, "shell", f"su -c '{cmd_str}'"]
    res = subprocess.run(adb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f"ADB command failed ({res.returncode}): {cmd_str}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res.stdout.strip()


def get_boot_id() -> str:
    return run_adb("cat /proc/sys/kernel/random/boot_id", timeout=10)


def get_uptime() -> float:
    out = run_adb("cat /proc/uptime", timeout=10)
    return float(out.split()[0])


def get_pstore() -> str:
    return run_adb("ls -A /sys/fs/pstore/ 2>/dev/null || true", timeout=10)


def get_cpu_freqs():
    """Read scaling_cur_freq for policy0 (little) and policy6 (big)."""
    try:
        p0 = run_adb("cat /sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq", timeout=5)
    except Exception:
        p0 = "N/A"
    try:
        p6 = run_adb("cat /sys/devices/system/cpu/cpufreq/policy6/scaling_cur_freq", timeout=5)
    except Exception:
        p6 = "N/A"
    return {"policy0_khz": p0, "policy6_khz": p6}


def restore_system(initial_algo: str = "lzo-rle"):
    print("[*] Performing teardown: restoring swap and zram configuration...")
    try:
        run_adb("swapoff /dev/block/zram0 || true", timeout=30)
        run_adb("echo 1 > /sys/block/zram0/reset", timeout=10)
        run_adb(f"echo {initial_algo} > /sys/block/zram0/comp_algorithm", timeout=10)
        run_adb(f"echo {DISKSIZE_ORIG} > /sys/block/zram0/disksize", timeout=10)
        run_adb("mkswap /dev/block/zram0", timeout=15)
        run_adb("swapon /dev/block/zram0", timeout=15)
        algo = run_adb("cat /sys/block/zram0/comp_algorithm", timeout=10)
        swaps = run_adb("cat /proc/swaps", timeout=10)
        lsmod = run_adb("lsmod", timeout=10)
        print(f"[+] Teardown complete. comp_algorithm: {algo}")
        print(f"[+] /proc/swaps:\n{swaps}")
        return {
            "comp_algorithm": algo,
            "swaps": swaps,
            "lsmod": lsmod,
            "restored": True,
        }
    except Exception as e:
        print(f"[-] Teardown failed: {e}", file=sys.stderr)
        return {"restored": False, "error": str(e)}


def run_single_point(algo: str, cycle: int, seq_in_cycle: int, corpus_path: str = CORPUS_PATH):
    print(f"\n========================================================")
    print(f"[*] Cycle {cycle}/6, Step {seq_in_cycle}/2: Algorithm [{algo}]")
    print(f"========================================================")

    freq_before = get_cpu_freqs()
    t_start = time.time()

    # 1. swapoff if active
    run_adb("swapoff /dev/block/zram0 || true", timeout=30)

    # 2. reset
    run_adb("echo 1 > /sys/block/zram0/reset", timeout=10)
    disksize_after_reset = run_adb("cat /sys/block/zram0/disksize", timeout=10)
    reset_ok = (disksize_after_reset == "0")
    if not reset_ok:
        raise RuntimeError(f"Reset failed: disksize is {disksize_after_reset}, expected 0")

    # 3. set comp_algorithm
    run_adb(f"echo {algo} > /sys/block/zram0/comp_algorithm", timeout=10)
    cur_algo = run_adb("cat /sys/block/zram0/comp_algorithm", timeout=10)
    if f"[{algo}]" not in cur_algo:
        raise RuntimeError(f"Failed to set algorithm {algo}. sysfs report: {cur_algo}")

    # 4. set disksize 1 GiB
    run_adb(f"echo {DISKSIZE_BENCH} > /sys/block/zram0/disksize", timeout=10)
    cur_disksize = run_adb("cat /sys/block/zram0/disksize", timeout=10)
    if cur_disksize != str(DISKSIZE_BENCH):
        raise RuntimeError(f"Failed to set disksize. Expected {DISKSIZE_BENCH}, got {cur_disksize}")

    # 5. mkswap (without swapon)
    mkswap_out = run_adb("mkswap /dev/block/zram0", timeout=15)

    # 6. Run zram_direct_bench
    bench_cmd = f"{BENCH_BIN_PATH} --corpus {corpus_path} --device {ZRAM_DEV} --size {TOTAL_BYTES}"
    bench_raw = run_adb(bench_cmd, timeout=60)

    # 7. Frequency after
    freq_after = get_cpu_freqs()
    t_end = time.time()

    # Extract JSON part
    json_start = bench_raw.find("{")
    json_end = bench_raw.rfind("}")
    if json_start == -1 or json_end == -1:
        raise RuntimeError(f"Could not find JSON in benchmark output: {bench_raw}")

    result = json.loads(bench_raw[json_start : json_end + 1])
    result["algo"] = algo
    result["cycle"] = cycle
    result["seq_in_cycle"] = seq_in_cycle
    result["freq_before"] = freq_before
    result["freq_after"] = freq_after
    result["elapsed_wall_sec"] = round(t_end - t_start, 3)
    result["reset_ok"] = reset_ok
    result["algo_selected"] = cur_algo

    print(f"[+] Output: comp={result['compress_mib_s']:.2f} MiB/s, "
          f"decomp={result['decompress_mib_s']:.2f} MiB/s, "
          f"compr_size={result['compr_data_size']} B, "
          f"ratio={result['compression_ratio']:.4f}:1, "
          f"integrity={result['integrity_match']}")
    print(f"    Freq: before=(p0:{freq_before['policy0_khz']}, p6:{freq_before['policy6_khz']}) -> "
          f"after=(p0:{freq_after['policy0_khz']}, p6:{freq_after['policy6_khz']})")

    return result


def main():
    global SERIAL
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=SERIAL, help="Target device serial (defaults to ANDROID_SERIAL)")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    SERIAL = args.serial
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")

    results_dir = REPO / "local" / "tester-raw"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_json = Path(args.out) if args.out else (results_dir / "lz4_native_gap_results.json")

    # 1. Preflight baseline checks
    print("=== Step 1: Preflight Baselines ===")
    dev_sha8 = hashlib.sha256(args.serial.encode()).hexdigest()[:8]
    print(f"Device serial hash: {dev_sha8}")
    initial_boot_id = get_boot_id()
    initial_uptime = get_uptime()
    pstore = get_pstore()
    if pstore:
        raise RuntimeError(f"Preflight FAILED: pstore is not empty! Content: {pstore}")
    print(f"[+] Baseline ok: boot_id={initial_boot_id}, uptime={initial_uptime:.2f} s, pstore empty")

    cur_algos = run_adb("cat /sys/block/zram0/comp_algorithm", timeout=10)
    print(f"[+] Current comp_algorithm: {cur_algos}")
    if "lz4" not in cur_algos or "lz4-kpm" not in cur_algos:
        raise RuntimeError(f"Preflight FAILED: required algorithms missing in sysfs: {cur_algos}")

    # Check corpus sha256 on device
    corpus_sha_actual = run_adb(f"sha256sum {CORPUS_PATH}", timeout=15).split()[0]
    if corpus_sha_actual != CORPUS_EXPECTED_SHA:
        raise RuntimeError(f"Corpus SHA-256 mismatch! expected={CORPUS_EXPECTED_SHA}, actual={corpus_sha_actual}")
    print(f"[+] Corpus verified: {corpus_sha_actual}")

    # Check bench binary sha256 on device
    bench_sha_actual = run_adb(f"sha256sum {BENCH_BIN_PATH}", timeout=10).split()[0]
    if bench_sha_actual != BENCH_EXPECTED_SHA:
        raise RuntimeError(f"Bench binary SHA-256 mismatch! expected={BENCH_EXPECTED_SHA}, actual={bench_sha_actual}")
    print(f"[+] Bench binary verified: {bench_sha_actual}")

    # 2. Cycles definition
    # 6 cycles, alternating order:
    # Cycle 1: lz4 -> lz4-kpm
    # Cycle 2: lz4-kpm -> lz4
    # Cycle 3: lz4 -> lz4-kpm
    # Cycle 4: lz4-kpm -> lz4
    # Cycle 5: lz4 -> lz4-kpm
    # Cycle 6: lz4-kpm -> lz4
    cycles_plan = [
        (1, ["lz4", "lz4-kpm"]),
        (2, ["lz4-kpm", "lz4"]),
        (3, ["lz4", "lz4-kpm"]),
        (4, ["lz4-kpm", "lz4"]),
        (5, ["lz4", "lz4-kpm"]),
        (6, ["lz4-kpm", "lz4"]),
    ]

    raw_points = []
    cycle_records = []
    expected_sizes = {}  # algo -> int
    teardown_record = None

    try:
        for cycle_idx, algo_pair in cycles_plan:
            print(f"\n==================================================================")
            print(f"=== Starting Cycle {cycle_idx} / 6: Order = {' -> '.join(algo_pair)} ===")
            print(f"==================================================================")
            cycle_data = {"cycle": cycle_idx, "order": algo_pair, "points": {}}

            for step_idx, algo in enumerate(algo_pair, 1):
                pt = run_single_point(algo, cycle_idx, step_idx)
                raw_points.append(pt)
                cycle_data["points"][algo] = pt

                # Verification 1: Integrity match
                if not pt.get("integrity_match", False):
                    raise RuntimeError(f"CRITICAL: Integrity match FAILED for {algo} at Cycle {cycle_idx} Step {step_idx}!")

                # Verification 2: Deterministic compression size across runs for each algo
                compr_bytes = pt["compr_data_size"]
                if algo not in expected_sizes:
                    expected_sizes[algo] = compr_bytes
                else:
                    if compr_bytes != expected_sizes[algo]:
                        raise RuntimeError(f"CRITICAL: Compression size inconsistent for {algo}! "
                                           f"Expected {expected_sizes[algo]}, got {compr_bytes} at cycle {cycle_idx}")

                # Check device survival
                cur_boot_id = get_boot_id()
                cur_uptime = get_uptime()
                if cur_boot_id != initial_boot_id:
                    raise RuntimeError(f"CRITICAL: Device rebooted! (boot_id changed: {initial_boot_id} -> {cur_boot_id})")

                # Settle pause
                time.sleep(2)

            cycle_records.append(cycle_data)

    finally:
        teardown_record = restore_system("lzo-rle")

    # 3. Statistical Analysis of Paired Differences
    # diff = lz4-kpm - lz4
    paired_decomp_diffs = []
    paired_comp_diffs = []

    print("\n=================== PAIR ANALYSIS ===================")
    for c in cycle_records:
        c_idx = c["cycle"]
        p_lz4 = c["points"]["lz4"]
        p_kpm = c["points"]["lz4-kpm"]

        d_decomp = p_kpm["decompress_mib_s"] - p_lz4["decompress_mib_s"]
        d_comp = p_kpm["compress_mib_s"] - p_lz4["compress_mib_s"]
        pct_decomp = (d_decomp / p_lz4["decompress_mib_s"]) * 100.0
        pct_comp = (d_comp / p_lz4["compress_mib_s"]) * 100.0

        c["decomp_diff_mib_s"] = round(d_decomp, 2)
        c["decomp_diff_pct"] = round(pct_decomp, 2)
        c["comp_diff_mib_s"] = round(d_comp, 2)
        c["comp_diff_pct"] = round(pct_comp, 2)

        paired_decomp_diffs.append(d_decomp)
        paired_comp_diffs.append(d_comp)

        order_str = f"{c['order'][0]} -> {c['order'][1]}"
        print(f"Cycle {c_idx} ({order_str:16s}): "
              f"lz4 decomp={p_lz4['decompress_mib_s']:7.2f}, kpm decomp={p_kpm['decompress_mib_s']:7.2f} | "
              f"diff = {d_decomp:+7.2f} MiB/s ({pct_decomp:+5.2f}%) | "
              f"comp diff = {d_comp:+6.2f} MiB/s ({pct_comp:+5.2f}%)")

    # Calculate mean, median, dispersion for paired decompression differences
    mean_decomp_diff = statistics.mean(paired_decomp_diffs)
    median_decomp_diff = statistics.median(paired_decomp_diffs)
    stdev_decomp_diff = statistics.stdev(paired_decomp_diffs)
    range_decomp_diff = max(paired_decomp_diffs) - min(paired_decomp_diffs)

    mean_comp_diff = statistics.mean(paired_comp_diffs)
    median_comp_diff = statistics.median(paired_comp_diffs)
    stdev_comp_diff = statistics.stdev(paired_comp_diffs)
    range_comp_diff = max(paired_comp_diffs) - min(paired_comp_diffs)

    # Check judgment rule:
    # - 若配对差值中位数同号且绝对值 > 离散度，判为「真实差距存在」，给出幅度；
    # - 若差值在 0 附近摆动、正负交替且 < 离散度，判为「无法判定，属噪声」；
    all_same_sign = (all(d > 0 for d in paired_decomp_diffs) or all(d < 0 for d in paired_decomp_diffs))
    abs_median = abs(median_decomp_diff)
    
    # Dispersion criteria: compare abs(median) against std dev and range
    # In strict terms: if all same sign and abs(median) > stdev
    if all_same_sign and abs_median > stdev_decomp_diff:
        verdict = "真实差距存在"
    elif not all_same_sign or abs_median < stdev_decomp_diff:
        verdict = "无法判定，属噪声"
    else:
        verdict = "边界区间（需审视离散度判据）"

    stats_summary = {
        "paired_decomp_diffs": [round(x, 2) for x in paired_decomp_diffs],
        "mean_decomp_diff_mib_s": round(mean_decomp_diff, 2),
        "median_decomp_diff_mib_s": round(median_decomp_diff, 2),
        "stdev_decomp_diff_mib_s": round(stdev_decomp_diff, 2),
        "range_decomp_diff_mib_s": round(range_decomp_diff, 2),
        "all_same_sign": all_same_sign,
        "judgment": verdict,
        "paired_comp_diffs": [round(x, 2) for x in paired_comp_diffs],
        "mean_comp_diff_mib_s": round(mean_comp_diff, 2),
        "median_comp_diff_mib_s": round(median_comp_diff, 2),
        "stdev_comp_diff_mib_s": round(stdev_comp_diff, 2),
        "range_comp_diff_mib_s": round(range_comp_diff, 2),
        "compression_sizes": expected_sizes,
    }

    full_output = {
        "timestamp": datetime.datetime.now().isoformat(),
        "device": SERIAL,
        "dev_fingerprint_sha8": dev_sha8,
        "candidate": {
            "source_commit": "251240cf7e530ae7224141b552a39f808c59fcb8",
            "instance_id": "zram_zstd-1.3.0+g1b12e49c5159.rf073d150.kpb51197a.ndk26.3.11579264#1",
            "kpm_sha256": "30f138a1d50d00f5aae44030c89ec718da642efce5b54de22949142395fd4566",
        },
        "initial_baseline": {
            "boot_id": initial_boot_id,
            "uptime": initial_uptime,
            "pstore_empty": True,
        },
        "final_baseline": {
            "boot_id": get_boot_id(),
            "uptime": get_uptime(),
        },
        "teardown": teardown_record,
        "stats_summary": stats_summary,
        "cycle_records": cycle_records,
        "raw_points": raw_points,
    }

    out_json.write_text(json.dumps(full_output, indent=2))
    print(f"\n[+] Full raw test results saved to: {out_json}")

    print("\n=================== FINAL METRICS ===================")
    print(f"Paired Decomp Diffs (lz4-kpm - lz4): {stats_summary['paired_decomp_diffs']} MiB/s")
    print(f"Mean Decomp Diff:   {mean_decomp_diff:+.2f} MiB/s")
    print(f"Median Decomp Diff: {median_decomp_diff:+.2f} MiB/s")
    print(f"Std Dev:            {stdev_decomp_diff:.2f} MiB/s")
    print(f"Range (Max - Min):  {range_decomp_diff:.2f} MiB/s")
    print(f"All Same Sign:      {all_same_sign}")
    print(f"Judgment:           {verdict}")
    print(f"Compressed Bytes:   lz4={expected_sizes.get('lz4')}, lz4-kpm={expected_sizes.get('lz4-kpm')}")
    print(f"Teardown Restored:  {teardown_record.get('restored')}")


if __name__ == "__main__":
    main()
