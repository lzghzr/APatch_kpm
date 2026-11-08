#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Device-side userspace benchmark runner for 4 KiB zram codec comparison.
Runs 3 algorithms (zstd-kpm, lz4-kpm, lz4kd-kpm) on both Synthetic and Real corpora across 3 trials with rotating order.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
FROZEN_COMMIT = "251240cf7e530ae7224141b552a39f808c59fcb8"
INSTANCE_ID = "zram_zstd-1.3.0+g1b12e49c5159.rf073d150.kpb51197a.ndk26.3.11579264#1"
SERIAL = os.environ.get("ANDROID_SERIAL")

SYNTH_CASES = ["source_text", "integers", "mixed_binary", "random"]
REAL_CASES = [
    "anon_system_server",
    "anon_surfaceflinger",
    "anon_systemui",
    "anon_launcher",
    "anon_ime",
    "anon_app",
    "file_apk",
    "file_vdex_dex",
    "file_native_so",
    "file_sqlite_db",
    "file_text_config",
    "file_image",
    "real_composite",
]

CODECS = ["zstd-kpm", "lz4-kpm", "lz4kd-kpm"]


def run_adb(shell_cmd, timeout=60):
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")
    cmd = ["adb", "-s", SERIAL, "shell", shell_cmd]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f"ADB command failed ({res.returncode}): {shell_cmd}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res.stdout.strip()


def run_corpus_suite(corpus_name: str, cases: list, file_pattern: str, trials: int = 3):
    print(f"\n========================================================")
    print(f"[*] Running A-Group Userspace Suite on: {corpus_name} ({len(cases)} cases, {trials} trials)")
    print(f"========================================================")

    results = {case: {algo: [] for algo in CODECS} for case in cases}

    for trial in range(trials):
        rotated_cases = cases[trial:] + cases[:trial]
        rotated_codecs = CODECS[trial:] + CODECS[:trial]
        print(f"\n--- Starting Trial {trial + 1}/{trials} for {corpus_name} ---")

        for case in rotated_cases:
            file_path = file_pattern.format(case=case)
            for codec in rotated_codecs:
                algo_idx = CODECS.index(codec)
                cmd = f"/data/local/tmp/zram_codec_bench {algo_idx} {file_path}"
                raw = run_adb(cmd, timeout=30)
                try:
                    data = json.loads(raw)
                except Exception as e:
                    raise RuntimeError(f"Failed to parse JSON from {cmd}: {raw}") from e

                assert data["roundtrip_ok"] is True, f"Roundtrip failed for {case} {codec}"
                results[case][codec].append(data)
                print(
                    f"  [{case:20s} | {codec:10s}] clen={data['compressed_bytes']:7d} B "
                    f"ratio={data['compression_ratio']:6.4f} "
                    f"comp={data['compress_mib_s']:8.2f} MiB/s decomp={data['decompress_mib_s']:8.2f} MiB/s"
                )

    # Calculate medians
    medians = {}
    for case, algos in results.items():
        medians[case] = {}
        for codec, trial_list in algos.items():
            sizes = {r["compressed_bytes"] for r in trial_list}
            assert len(sizes) == 1, f"Compressed size varied across trials: {sizes}"
            c_bytes = trial_list[0]["compressed_bytes"]
            c_ratio = trial_list[0]["compression_ratio"]
            c_mibs = [r["compress_mib_s"] for r in trial_list]
            d_mibs = [r["decompress_mib_s"] for r in trial_list]
            medians[case][codec] = {
                "compressed_bytes": c_bytes,
                "compression_ratio": c_ratio,
                "compress_mib_s_median": round(statistics.median(c_mibs), 2),
                "decompress_mib_s_median": round(statistics.median(d_mibs), 2),
                "raw_compress_mib_s": [round(x, 2) for x in c_mibs],
                "raw_decompress_mib_s": [round(x, 2) for x in d_mibs],
            }

    return {"trials": results, "medians": medians}


def main():
    global SERIAL
    parser = argparse.ArgumentParser(description="Device-side userspace benchmark runner for 4 KiB zram codec comparison.")
    parser.add_argument("--serial", default=SERIAL, help="Target device serial (defaults to ANDROID_SERIAL)")
    args = parser.parse_args()

    SERIAL = args.serial
    if not SERIAL:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")

    raw_dir = REPO / "local/tester-raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 1. Ensure synthetic corpus is in /data/local/tmp
    synth_dir = raw_dir / "zram-throughput/corpus"
    for case in SYNTH_CASES:
        src = synth_dir / f"{case}.bin"
        if src.exists():
            subprocess.run(["adb", "-s", SERIAL, "push", str(src), f"/data/local/tmp/{case}.bin"], check=True)

    # 2. Run synthetic suite
    synth_results = run_corpus_suite("Synthetic", SYNTH_CASES, "/data/local/tmp/{case}.bin", trials=3)

    # 3. Run real suite
    real_results = run_corpus_suite("Real", REAL_CASES, "/data/local/tmp/corpus_real/{case}.bin", trials=3)

    out_file = raw_dir / "group_a_bench_results.json"
    full_output = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_commit": FROZEN_COMMIT,
        "instance_id": INSTANCE_ID,
        "synthetic": synth_results,
        "real": real_results,
    }
    out_file.write_text(json.dumps(full_output, indent=2) + "\n")
    print(f"\n[+] Group A Results saved to {out_file}")


if __name__ == "__main__":
    main()
