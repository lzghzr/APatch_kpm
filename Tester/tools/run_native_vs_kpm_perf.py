#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automated test runner for Native vs KPM zram codec performance comparison.
Direct block I/O on /dev/block/zram0 bypassing swap.
Measures lzo-rle (control), lz4, zstd, lz4-kpm, zstd-kpm on 256 MiB fixed corpus.
"""
import argparse
import datetime
import hashlib
import json
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

CODECS = [
    "lzo-rle",
    "lzo",
    "lz4",
    "zstd",
    "lz4-kpm",
    "zstd-kpm",
    "lz4kd-kpm",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def run_single_round(algo: str, round_idx: int, corpus_path: str = CORPUS_PATH):
    print(f"\n========================================================")
    print(f"[*] Starting Algorithm: {algo} | Round {round_idx}/3 | Corpus: {corpus_path}")
    print(f"========================================================")

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
    print(f"[+] mkswap: {mkswap_out}")

    # 6. Run zram_direct_bench
    bench_cmd = f"{BENCH_BIN_PATH} --corpus {corpus_path} --device {ZRAM_DEV} --size {TOTAL_BYTES}"
    bench_raw = run_adb(bench_cmd, timeout=60)
    print(f"[+] Benchmark output:\n{bench_raw}")

    # Extract JSON part
    json_start = bench_raw.find("{")
    json_end = bench_raw.rfind("}")
    if json_start == -1 or json_end == -1:
        raise RuntimeError(f"Could not find JSON in benchmark output: {bench_raw}")

    result = json.loads(bench_raw[json_start : json_end + 1])
    result["reset_ok"] = reset_ok
    result["algo_selected"] = cur_algo
    result["disksize"] = cur_disksize
    return result


def main():
    global SERIAL
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=SERIAL, help="Target device serial (defaults to ANDROID_SERIAL)")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--corpus", type=str, default=CORPUS_PATH)
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()

    SERIAL = args.serial
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")

    results_dir = REPO / "local" / "tester-raw"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_json = Path(args.out) if args.out else (results_dir / "native_vs_kpm_results.json")

    initial_boot_id = get_boot_id()
    initial_uptime = get_uptime()
    print(f"[*] Preflight baseline: boot_id={initial_boot_id}, uptime={initial_uptime:.2f}")

    all_data = {}
    teardown_record = None

    try:
        for algo in CODECS:
            all_data[algo] = {
                "rounds": [],
                "errors": [],
            }
            for r in range(1, args.rounds + 1):
                try:
                    res = run_single_round(algo, r, corpus_path=args.corpus)
                    all_data[algo]["rounds"].append(res)
                    if not res.get("integrity_match", False):
                        print(f"[-] INTEGRITY MISMATCH in {algo} round {r}!", file=sys.stderr)
                        # Preserve scene and continue next algo
                        break
                except Exception as e:
                    err_msg = str(e)
                    print(f"[-] Error in {algo} round {r}: {err_msg}", file=sys.stderr)
                    all_data[algo]["errors"].append({
                        "round": r,
                        "error": err_msg,
                    })

                # Check device survival
                cur_boot_id = get_boot_id()
                cur_uptime = get_uptime()
                if cur_boot_id != initial_boot_id:
                    raise RuntimeError(f"CRITICAL: Device rebooted! (boot_id changed: {initial_boot_id} -> {cur_boot_id})")
                print(f"[+] Round {r} completed successfully. Device uptime: {cur_uptime:.2f} s")

    finally:
        teardown_record = restore_system("lzo-rle")

    # Compute summary statistics
    summary = {}
    for algo, item in all_data.items():
        rounds = item["rounds"]
        if not rounds:
            summary[algo] = {"status": "FAIL", "reason": "No successful rounds"}
            continue

        ratios = [r["compression_ratio"] for r in rounds]
        comp_tps = [r["compress_mib_s"] for r in rounds]
        decomp_tps = [r["decompress_mib_s"] for r in rounds]
        compr_bytes = [r["compr_data_size"] for r in rounds]
        matches = [r["integrity_match"] for r in rounds]

        summary[algo] = {
            "status": "PASS" if all(matches) and len(rounds) == args.rounds else "FAIL",
            "rounds_completed": len(rounds),
            "integrity_all_pass": all(matches),
            "orig_bytes": rounds[0]["orig_data_size"],
            "compr_bytes_median": int(statistics.median(compr_bytes)),
            "compr_bytes_raw": compr_bytes,
            "ratio_median": statistics.median(ratios),
            "ratio_raw": ratios,
            "comp_mib_s_median": statistics.median(comp_tps),
            "comp_mib_s_raw": comp_tps,
            "decomp_mib_s_median": statistics.median(decomp_tps),
            "decomp_mib_s_raw": decomp_tps,
        }

    full_output = {
        "timestamp": datetime.datetime.now().isoformat(),
        "device": SERIAL,
        "initial_baseline": {
            "boot_id": initial_boot_id,
            "uptime": initial_uptime,
        },
        "final_baseline": {
            "boot_id": get_boot_id(),
            "uptime": get_uptime(),
        },
        "teardown": teardown_record,
        "summary": summary,
        "raw_data": all_data,
    }

    out_json.write_text(json.dumps(full_output, indent=2))
    print(f"\n[+] Raw results saved to {out_json}")

    print("\n=================== SUMMARY ===================")
    for algo, s in summary.items():
        print(f"Algorithm: {algo:10s} | Ratio: {s.get('ratio_median', 0.0):.4f}:1 | "
              f"Comp: {s.get('comp_mib_s_median', 0.0):7.2f} MiB/s {s.get('comp_mib_s_raw', [])} | "
              f"Decomp: {s.get('decomp_mib_s_median', 0.0):7.2f} MiB/s {s.get('decomp_mib_s_raw', [])} | "
              f"Integrity: {s.get('integrity_all_pass', False)}")


if __name__ == "__main__":
    main()
