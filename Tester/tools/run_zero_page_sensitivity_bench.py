#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automated test runner for Zero-Page Sensitivity comparison on /dev/block/zram0.

Evaluates 7 algorithms (lzo-rle, lzo, lz4, zstd, lz4-kpm, zstd-kpm, lz4kd-kpm)
across two derived corpora (Z0: natural zero pages preserved, Z1: 0 zero pages).
Direct block I/O with O_DIRECT | O_SYNC, 1 GiB disksize, 3-round median.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
SERIAL = os.environ.get("ANDROID_SERIAL")
DISKSIZE_BENCH = 1073741824  # 1 GiB
DISKSIZE_ORIG = 17179869184   # 16 GiB
BENCH_BIN_PATH = "/data/local/tmp/zram_direct_bench"
ZRAM_DEV = "/dev/block/zram0"

CORPUS_Z0_PATH = "/data/local/tmp/corpus_z0_228m.bin"
CORPUS_Z1_PATH = "/data/local/tmp/corpus_z1_228m.bin"
CORPUS_Z0_SHA = "034b34a0f274fdc38fd6505c75cbc4cc84629d7b650072978fe5d301c86a5261"
CORPUS_Z1_SHA = "81457f3374e3f5cee0b6aa045fa462040bb88381a2fd5ce6b4a9ca1ce67cfb36"
TOTAL_BYTES = 228941824  # 55,894 * 4096 = 228,941,824 B

CODECS = [
    "lzo-rle",
    "lzo",
    "lz4",
    "zstd",
    "lz4-kpm",
    "zstd-kpm",
    "lz4kd-kpm",
]


def run_adb(cmd_str: str, timeout: int = 60) -> str:
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")
    adb_cmd = ["adb", "-s", SERIAL, "shell", f"su -c '{cmd_str}'"]
    res = subprocess.run(
        adb_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"ADB command failed ({res.returncode}): {cmd_str}\n"
            f"Stdout: {res.stdout}\nStderr: {res.stderr}"
        )
    return res.stdout.strip()


def get_boot_id() -> str:
    return run_adb("cat /proc/sys/kernel/random/boot_id", timeout=10)


def get_uptime() -> float:
    out = run_adb("cat /proc/uptime", timeout=10)
    return float(out.split()[0])


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


def run_single_round(algo: str, round_idx: int, corpus_path: str, expected_sha: str, total_bytes: int):
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
    bench_cmd = f"{BENCH_BIN_PATH} --corpus {corpus_path} --device {ZRAM_DEV} --size {total_bytes}"
    bench_raw = run_adb(bench_cmd, timeout=60)

    # Extract JSON part
    json_start = bench_raw.find("{")
    json_end = bench_raw.rfind("}")
    if json_start == -1 or json_end == -1:
        raise RuntimeError(f"Could not find JSON in benchmark output: {bench_raw}")

    result = json.loads(bench_raw[json_start : json_end + 1])
    result["reset_ok"] = reset_ok
    result["algo_selected"] = cur_algo
    result["disksize"] = cur_disksize

    # Validate integrity match and sha256
    if not result.get("integrity_match", False):
        raise RuntimeError(f"Data integrity mismatch in {algo} round {round_idx}!")
    if result.get("corpus_sha256") != expected_sha:
        raise RuntimeError(
            f"Corpus SHA mismatch: got {result.get('corpus_sha256')}, expected {expected_sha}"
        )

    return result


def benchmark_corpus(corpus_name: str, corpus_path: str, expected_sha: str, rounds: int, initial_boot_id: str):
    print(f"\n========================================================")
    print(f"[*] Starting Evaluation on Corpus {corpus_name}")
    print(f"[*] Path: {corpus_path} ({TOTAL_BYTES} bytes)")
    print(f"[*] Expected SHA-256: {expected_sha}")
    print(f"========================================================")

    corpus_data = {}
    for algo in CODECS:
        corpus_data[algo] = {
            "rounds": [],
            "errors": [],
        }
        print(f"\n---> Benchmarking {algo} (3 rounds)...")
        for r in range(1, rounds + 1):
            try:
                res = run_single_round(algo, r, corpus_path, expected_sha, TOTAL_BYTES)
                corpus_data[algo]["rounds"].append(res)
                print(
                    f"     [Round {r}/{rounds}] Ratio: {res['compression_ratio']:.4f}:1 | "
                    f"Comp: {res['compress_mib_s']:6.2f} MiB/s | "
                    f"Decomp: {res['decompress_mib_s']:7.2f} MiB/s | Integrity: PASS"
                )
            except Exception as e:
                err_msg = str(e)
                print(f"     [-] Error in {algo} round {r}: {err_msg}", file=sys.stderr)
                corpus_data[algo]["errors"].append({"round": r, "error": err_msg})
                break

            # Check device survival
            cur_boot_id = get_boot_id()
            cur_uptime = get_uptime()
            if cur_boot_id != initial_boot_id:
                raise RuntimeError(
                    f"CRITICAL: Device rebooted! (boot_id changed: {initial_boot_id} -> {cur_boot_id})"
                )

    # Compute summary
    summary = {}
    for algo, item in corpus_data.items():
        r_list = item["rounds"]
        if not r_list or len(r_list) < rounds:
            summary[algo] = {"status": "FAIL", "reason": f"Only {len(r_list)}/{rounds} rounds completed"}
            continue

        ratios = [r["compression_ratio"] for r in r_list]
        comp_tps = [r["compress_mib_s"] for r in r_list]
        decomp_tps = [r["decompress_mib_s"] for r in r_list]
        compr_bytes = [r["compr_data_size"] for r in r_list]
        mem_used = [r["mem_used_total"] for r in r_list]
        matches = [r["integrity_match"] for r in r_list]

        summary[algo] = {
            "status": "PASS" if all(matches) and len(r_list) == rounds else "FAIL",
            "rounds_completed": len(r_list),
            "integrity_all_pass": all(matches),
            "orig_bytes": r_list[0]["orig_data_size"],
            "compr_bytes_median": int(statistics.median(compr_bytes)),
            "compr_bytes_raw": compr_bytes,
            "mem_used_median": int(statistics.median(mem_used)),
            "ratio_median": round(statistics.median(ratios), 6),
            "ratio_raw": ratios,
            "comp_mib_s_median": round(statistics.median(comp_tps), 2),
            "comp_mib_s_raw": comp_tps,
            "decomp_mib_s_median": round(statistics.median(decomp_tps), 2),
            "decomp_mib_s_raw": decomp_tps,
        }

    return {"summary": summary, "raw_data": corpus_data}


def main():
    global SERIAL
    parser = argparse.ArgumentParser(description="Zero-Page Sensitivity Block Device Benchmark")
    parser.add_argument("--serial", default=SERIAL, help="Target device serial (defaults to ANDROID_SERIAL)")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()

    SERIAL = args.serial
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")

    results_dir = REPO / "local" / "tester-raw"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_json = Path(args.out) if args.out else (results_dir / "zero_page_sensitivity_results.json")

    initial_boot_id = get_boot_id()
    initial_uptime = get_uptime()
    print(f"[*] Preflight baseline: boot_id={initial_boot_id}, uptime={initial_uptime:.2f} s")

    all_results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "device": SERIAL,
        "kernel_version": run_adb("uname -r"),
        "fingerprint": run_adb("getprop ro.build.fingerprint"),
        "initial_baseline": {
            "boot_id": initial_boot_id,
            "uptime": initial_uptime,
        },
        "corpora": {
            "Z0": {
                "path": CORPUS_Z0_PATH,
                "sha256": CORPUS_Z0_SHA,
                "total_bytes": TOTAL_BYTES,
                "pages": 55894,
                "zero_pages": 9591,
                "zero_page_pct": 17.1593,
            },
            "Z1": {
                "path": CORPUS_Z1_PATH,
                "sha256": CORPUS_Z1_SHA,
                "total_bytes": TOTAL_BYTES,
                "pages": 55894,
                "zero_pages": 0,
                "zero_page_pct": 0.0,
            },
        },
    }

    teardown_record = None

    try:
        # Benchmark Z0
        z0_results = benchmark_corpus(
            "Z0 (Natural Zero Pages, 17.16% zeros)",
            CORPUS_Z0_PATH,
            CORPUS_Z0_SHA,
            args.rounds,
            initial_boot_id,
        )
        all_results["Z0"] = z0_results

        # Benchmark Z1
        z1_results = benchmark_corpus(
            "Z1 (Zero Pages Stripped, strictly 0 zeros)",
            CORPUS_Z1_PATH,
            CORPUS_Z1_SHA,
            args.rounds,
            initial_boot_id,
        )
        all_results["Z1"] = z1_results

    finally:
        teardown_record = restore_system("lzo-rle")
        all_results["teardown"] = teardown_record
        all_results["final_baseline"] = {
            "boot_id": get_boot_id(),
            "uptime": get_uptime(),
        }

    # Save results to json
    out_json.write_text(json.dumps(all_results, indent=2))
    print(f"\n[+] Raw results saved to {out_json}")

    # Generate printout tables and determinations
    print("\n" + "=" * 90)
    print("                      Z0 vs Z1 ZERO-PAGE SENSITIVITY BENCHMARK REPORT")
    print("=" * 90)

    z0_sum = all_results["Z0"]["summary"]
    z1_sum = all_results["Z1"]["summary"]

    print("\n### 表 1：Z0 / Z1 压缩率与内存占用对照表")
    print(f"{'算法':12s} | {'类别':8s} | {'Z0 压缩后大小':14s} | {'Z0 压缩率':10s} | {'Z1 压缩后大小':14s} | {'Z1 压缩率':10s} | {'压缩率变化 (Z1-Z0)':16s} | {'相对降幅 %':10s}")
    print("-" * 110)

    for algo in CODECS:
        cat = "原生" if "-kpm" not in algo else "KPM"
        if algo == "lzo-rle":
            cat = "原生对照"
        
        s0 = z0_sum.get(algo, {})
        s1 = z1_sum.get(algo, {})
        r0 = s0.get("ratio_median", 0.0)
        r1 = s1.get("ratio_median", 0.0)
        b0 = s0.get("compr_bytes_median", 0)
        b1 = s1.get("compr_bytes_median", 0)
        delta_r = r1 - r0
        pct_change = ((r1 - r0) / r0 * 100.0) if r0 else 0.0

        print(
            f"{algo:12s} | {cat:8s} | {b0:12,d} B | {r0:8.4f} : 1 | {b1:12,d} B | {r1:8.4f} : 1 | "
            f"{delta_r:+8.4f} ({delta_r/r0*100:+.2f}%)   | {pct_change:+.2f}%"
        )

    print("\n### 表 2：Z0 / Z1 压缩与解压吞吐对照表")
    print(f"{'算法':12s} | {'类别':8s} | {'Z0 压缩 (MiB/s)':16s} | {'Z1 压缩 (MiB/s)':16s} | {'压缩变化 %':10s} | {'Z0 解压 (MiB/s)':16s} | {'Z1 解压 (MiB/s)':16s} | {'解压变化 %':10s}")
    print("-" * 115)

    for algo in CODECS:
        cat = "原生" if "-kpm" not in algo else "KPM"
        if algo == "lzo-rle":
            cat = "原生对照"

        s0 = z0_sum.get(algo, {})
        s1 = z1_sum.get(algo, {})
        c0 = s0.get("comp_mib_s_median", 0.0)
        c1 = s1.get("comp_mib_s_median", 0.0)
        d0 = s0.get("decomp_mib_s_median", 0.0)
        d1 = s1.get("decomp_mib_s_median", 0.0)
        c_pct = ((c1 - c0) / c0 * 100.0) if c0 else 0.0
        d_pct = ((d1 - d0) / d0 * 100.0) if d0 else 0.0

        print(
            f"{algo:12s} | {cat:8s} | {c0:14.2f}   | {c1:14.2f}   | {c_pct:+8.2f}%  | "
            f"{d0:14.2f}   | {d1:14.2f}   | {d_pct:+8.2f}%"
        )

    # Key determination
    r0_lzorle = z0_sum["lzo-rle"]["ratio_median"]
    r0_lz4 = z0_sum["lz4"]["ratio_median"]
    r1_lzorle = z1_sum["lzo-rle"]["ratio_median"]
    r1_lz4 = z1_sum["lz4"]["ratio_median"]

    adv_z0_abs = r0_lzorle - r0_lz4
    adv_z0_pct = (r0_lzorle - r0_lz4) / r0_lz4 * 100.0

    adv_z1_abs = r1_lzorle - r1_lz4
    adv_z1_pct = (r1_lzorle - r1_lz4) / r1_lz4 * 100.0

    print("\n### 关键判定：lzo-rle 相对 lz4 压缩率优势分析")
    print(f"Z0（自然含零页 17.16%）:")
    print(f"  lzo-rle 压缩率: {r0_lzorle:.4f} : 1")
    print(f"  lz4     压缩率: {r0_lz4:.4f} : 1")
    print(f"  lzo-rle 相对 lz4 优势: {adv_z0_abs:+.4f} ({adv_z0_pct:+.2f}%)")

    print(f"\nZ1（严格去零页 0.00%）:")
    print(f"  lzo-rle 压缩率: {r1_lzorle:.4f} : 1")
    print(f"  lz4     压缩率: {r1_lz4:.4f} : 1")
    print(f"  lzo-rle 相对 lz4 优势: {adv_z1_abs:+.4f} ({adv_z1_pct:+.2f}%)")

    if adv_z1_pct >= 1.0:
        determination = "真实分布优势，与零页无关"
    elif adv_z1_pct <= 0.0 or adv_z1_abs <= 0.0:
        determination = "优势主要来自零页（在 Z1 下优势消失或反转）"
    else:
        determination = f"优势大幅收窄（仅剩 {adv_z1_pct:+.2f}%，优势主要由零页贡献）"

    print(f"\n判定结论: 【{determination}】")


if __name__ == "__main__":
    main()
