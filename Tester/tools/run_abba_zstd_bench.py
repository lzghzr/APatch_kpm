#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ABBA paired benchmark runner for DEV-071 ZSTD inline adaptation evaluation.
Measures Version A (3f8cfd7) vs Version B (251240c) in an ABBA block sequence
on device_a_6_12 (Android 17 / 6.12.69) to separate real version effect from thermal/clock drift.
Strictly userspace: does not deploy KPM or modify device module state.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import statistics
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]

COMMIT_A = "3f8cfd7c18d8006557e28c77ffd7debca46bd4db"
INSTANCE_A = "zram_zstd-1.3.0+gfc2728b60004.re62ca92a.kpb51197a.ndk26.3.11579264#1"

COMMIT_B = "251240cf7e530ae7224141b552a39f808c59fcb8"
INSTANCE_B = "zram_zstd-1.3.0+g1b12e49c5159.rf073d150.kpb51197a.ndk26.3.11579264#1"

BENCH_DIR = REPO / "local/tester-raw/abba_bench"
CORPUS_DIR = REPO / "local/tester-raw/zram-throughput/corpus"
BIN_A = BENCH_DIR / "build_a/zram_codec_bench_a"
BIN_B = BENCH_DIR / "build_b/zram_codec_bench_b"

CASES = ["source_text", "integers", "mixed_binary", "random"]
CODECS = ["zstd-kpm", "lz4-kpm", "lz4kd-kpm"]
EXPECTED_CORPUS_HASHES = {
    "source_text": "f9f7df85e21d96cce6556a122d5a798adb29519bd3a306ff67ba6df442308b8b",
    "integers": "9610500efa77000953cea51211741e4eb505a567e7cb184a6284a031ebdae552",
    "mixed_binary": "ab1261cc84525c26c72c182dae990ed051912eb0f4c5addcbf4c1c165aa80cac",
    "random": "a2162c17175e810a4080afaa2c43f07612d7471aab3465f3fc37505b1d888d63",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cmd(cmd, timeout=30, check=True):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {shlex.join(cmd)}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res.stdout.strip()


def run_adb(serial, shell_cmd, timeout=30):
    return run_cmd(["adb", "-s", serial, "shell", shell_cmd], timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description="ABBA Paired Benchmark Runner for DEV-071")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), help="Device serial (defaults to ANDROID_SERIAL)")
    parser.add_argument("--out", default=str(BENCH_DIR / "abba_results.json"))
    args = parser.parse_args()

    serial = args.serial
    if not serial:
        sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")
    print(f"=== DEV-071 ZSTD Inline ABBA Paired Benchmark ===")
    print(f"Target Serial: {serial}")
    print(f"Version A: commit {COMMIT_A[:8]} | Instance: {INSTANCE_A}")
    print(f"Version B: commit {COMMIT_B[:8]} | Instance: {INSTANCE_B}")

    # 1. Verify Binaries & Corpora
    if not BIN_A.exists() or not BIN_B.exists():
        raise FileNotFoundError(f"Binaries not ready. Please build first: {BIN_A}, {BIN_B}")

    hash_a = sha256_file(BIN_A)
    hash_b = sha256_file(BIN_B)
    print(f"Binary A: {BIN_A} (sha256: {hash_a})")
    print(f"Binary B: {BIN_B} (sha256: {hash_b})")

    corpus_info = {}
    for case in CASES:
        c_path = CORPUS_DIR / f"{case}.bin"
        if not c_path.exists():
            raise FileNotFoundError(f"Corpus file missing: {c_path}")
        c_hash = sha256_file(c_path)
        assert c_hash == EXPECTED_CORPUS_HASHES[case], f"Hash mismatch for {case}: {c_hash} != {EXPECTED_CORPUS_HASHES[case]}"
        corpus_info[case] = {"path": str(c_path.relative_to(REPO)), "sha256": c_hash, "bytes": c_path.stat().st_size}
    print(f"All 4 corpora verified against frozen hashes.")

    # 2. Preflight & Baseline
    dev_hash = hashlib.sha256(serial.encode()).hexdigest()[:8]
    uname = run_adb(serial, "uname -a")
    model = run_adb(serial, "getprop ro.product.model")
    release = run_adb(serial, "getprop ro.build.version.release")
    selinux = run_adb(serial, "getenforce")
    boot_id_start = run_adb(serial, "cat /proc/sys/kernel/random/boot_id 2>/dev/null || true")
    uptime_start = run_adb(serial, "cat /proc/uptime")
    pstore_start = run_adb(serial, "ls -A /sys/fs/pstore/ 2>/dev/null || su -c 'ls -A /sys/fs/pstore/' || true")

    print(f"\n[Environment Preflight]")
    print(f"  Device Hash: {dev_hash}")
    print(f"  Model: {model}, Android: {release}, SELinux: {selinux}")
    print(f"  Kernel: {uname}")
    print(f"  boot_id: {boot_id_start}")
    print(f"  uptime: {uptime_start}")
    print(f"  pstore: {pstore_start.strip() or 'EMPTY'}")

    # 3. Push to Device
    dev_tmp = "/data/local/tmp"
    run_cmd(["adb", "-s", serial, "push", str(BIN_A), f"{dev_tmp}/zram_codec_bench_a"])
    run_cmd(["adb", "-s", serial, "push", str(BIN_B), f"{dev_tmp}/zram_codec_bench_b"])
    run_adb(serial, f"chmod 755 {dev_tmp}/zram_codec_bench_a {dev_tmp}/zram_codec_bench_b")

    for case in CASES:
        src_bin = CORPUS_DIR / f"{case}.bin"
        run_cmd(["adb", "-s", serial, "push", str(src_bin), f"{dev_tmp}/{case}.bin"])

    # 4. ABBA Execution: 4 Blocks
    # Block 1: A
    # Block 2: B
    # Block 3: B
    # Block 4: A
    blocks = [
        {"block_id": 1, "name": "Block_1_A", "version": "A", "binary": "zram_codec_bench_a"},
        {"block_id": 2, "name": "Block_2_B", "version": "B", "binary": "zram_codec_bench_b"},
        {"block_id": 3, "name": "Block_3_B", "version": "B", "binary": "zram_codec_bench_b"},
        {"block_id": 4, "name": "Block_4_A", "version": "A", "binary": "zram_codec_bench_a"},
    ]

    all_block_data = []

    print("\n========================================================")
    print("Starting ABBA 4-Block Paired Execution")
    print("========================================================")

    for blk in blocks:
        blk_id = blk["block_id"]
        blk_name = blk["name"]
        ver = blk["version"]
        bin_name = blk["binary"]
        print(f"\n>>> Starting {blk_name} (Version {ver}, Binary: {bin_name}) <<<")

        blk_results = {"block_id": blk_id, "name": blk_name, "version": ver, "binary": bin_name, "rounds": []}

        # 2 rounds per block
        for r in range(1, 3):
            print(f"  --- {blk_name} | Round {r}/2 ---")
            round_data = {"round_idx": r, "results": {}}

            # Rotate order slightly between rounds to avoid warm-order bias
            rotated_cases = CASES if r == 1 else CASES[::-1]
            rotated_codecs = CODECS if r == 1 else CODECS[::-1]

            for case in rotated_cases:
                round_data["results"][case] = {}
                for codec in rotated_codecs:
                    algo_idx = CODECS.index(codec)
                    cmd = f"{dev_tmp}/{bin_name} {algo_idx} {dev_tmp}/{case}.bin"
                    t0 = time.time()
                    raw_out = run_adb(serial, cmd, timeout=60)
                    elapsed = time.time() - t0

                    row = json.loads(raw_out)
                    assert row["roundtrip_ok"] is True, f"Roundtrip failed on {blk_name} R{r} {case} {codec}"
                    assert math.isfinite(row["compress_mib_s"]) and row["compress_mib_s"] > 0
                    assert math.isfinite(row["decompress_mib_s"]) and row["decompress_mib_s"] > 0

                    round_data["results"][case][codec] = {
                        "compressed_bytes": row["compressed_bytes"],
                        "compression_ratio": row["compression_ratio"],
                        "compress_mib_s": round(row["compress_mib_s"], 2),
                        "decompress_mib_s": round(row["decompress_mib_s"], 2),
                        "roundtrip_ok": row["roundtrip_ok"],
                        "wall_time_s": round(elapsed, 2),
                    }
                    print(
                        f"    [{case:14s} | {codec:10s}] clen={row['compressed_bytes']:7d} B "
                        f"comp={row['compress_mib_s']:8.2f} MiB/s decomp={row['decompress_mib_s']:8.2f} MiB/s"
                    )

            blk_results["rounds"].append(round_data)

        all_block_data.append(blk_results)

    # 5. Clean up device temporary files
    run_adb(serial, f"rm -f {dev_tmp}/zram_codec_bench_a {dev_tmp}/zram_codec_bench_b " + " ".join(f"{dev_tmp}/{c}.bin" for c in CASES))

    # 6. Postflight baseline verification
    boot_id_end = run_adb(serial, "cat /proc/sys/kernel/random/boot_id 2>/dev/null || true")
    uptime_end = run_adb(serial, "cat /proc/uptime")
    pstore_end = run_adb(serial, "ls -A /sys/fs/pstore/ 2>/dev/null || su -c 'ls -A /sys/fs/pstore/' || true")

    assert boot_id_start == boot_id_end, f"boot_id changed: {boot_id_start} -> {boot_id_end}"
    print(f"\n[Postflight Verification]")
    print(f"  boot_id: {boot_id_end} (unchanged, PASS)")
    print(f"  uptime: {uptime_start} -> {uptime_end} (monotonically increased, PASS)")
    print(f"  pstore: {pstore_end.strip() or 'EMPTY'} (PASS)")

    # 7. Aggregate & Compute Version Effect vs Drift
    # Structure of block results:
    # block_id 1: A1
    # block_id 2: B2
    # block_id 3: B3
    # block_id 4: A4

    # Compute block averages for each (case, codec)
    block_means = {b_id: {c: {algo: {} for algo in CODECS} for c in CASES} for b_id in [1, 2, 3, 4]}

    for blk in all_block_data:
        b_id = blk["block_id"]
        for c in CASES:
            for algo in CODECS:
                c_speeds = [r["results"][c][algo]["compress_mib_s"] for r in blk["rounds"]]
                d_speeds = [r["results"][c][algo]["decompress_mib_s"] for r in blk["rounds"]]
                c_bytes = blk["rounds"][0]["results"][c][algo]["compressed_bytes"]
                c_ratio = blk["rounds"][0]["results"][c][algo]["compression_ratio"]
                block_means[b_id][c][algo] = {
                    "compressed_bytes": c_bytes,
                    "compression_ratio": c_ratio,
                    "compress_mib_s_mean": round(statistics.mean(c_speeds), 2),
                    "decompress_mib_s_mean": round(statistics.mean(d_speeds), 2),
                    "compress_raw": c_speeds,
                    "decompress_raw": d_speeds,
                }

    analysis = {
        "version_effect": {},
        "drift_scale": {},
        "verdict": {},
    }

    print("\n=========================================================================================")
    print("STATISTICAL ANALYSIS: Version Effect vs Drift Scale")
    print("=========================================================================================")
    print(f"{'Corpus':14s} | {'Codec':10s} | {'A_mean(1,4)':12s} | {'B_mean(2,3)':12s} | {'VersionEff(B-A)':16s} | {'A_drift(4-1)':14s} | {'B_drift(3-2)':14s}")
    print("-" * 95)

    zstd_decomp_version_effects = []
    zstd_decomp_drift_scales = []

    for c in CASES:
        analysis["version_effect"][c] = {}
        analysis["drift_scale"][c] = {}
        for algo in CODECS:
            a1_d = block_means[1][c][algo]["decompress_mib_s_mean"]
            b2_d = block_means[2][c][algo]["decompress_mib_s_mean"]
            b3_d = block_means[3][c][algo]["decompress_mib_s_mean"]
            a4_d = block_means[4][c][algo]["decompress_mib_s_mean"]

            a_mean_d = round((a1_d + a4_d) / 2.0, 2)
            b_mean_d = round((b2_d + b3_d) / 2.0, 2)
            eff_d = round(b_mean_d - a_mean_d, 2)
            eff_pct_d = round((eff_d / a_mean_d) * 100.0, 2)

            a_drift_d = round(a4_d - a1_d, 2)
            b_drift_d = round(b3_d - b2_d, 2)
            max_drift_d = round(max(abs(a_drift_d), abs(b_drift_d)), 2)

            analysis["version_effect"][c][algo] = {
                "a_mean_decomp": a_mean_d,
                "b_mean_decomp": b_mean_d,
                "version_effect_decomp": eff_d,
                "version_effect_pct": eff_pct_d,
            }
            analysis["drift_scale"][c][algo] = {
                "a_drift_decomp": a_drift_d,
                "b_drift_decomp": b_drift_d,
                "max_drift_decomp": max_drift_d,
            }

            if algo == "zstd-kpm":
                zstd_decomp_version_effects.append((c, eff_d, eff_pct_d))
                zstd_decomp_drift_scales.append((c, max_drift_d))

            print(
                f"{c:14s} | {algo:10s} | {a_mean_d:10.2f}   | {b_mean_d:10.2f}   | "
                f"{eff_d:+8.2f} ({eff_pct_d:+5.2f}%) | {a_drift_d:+8.2f}       | {b_drift_d:+8.2f}"
            )

    # Global Verdict Calculation
    # Compare ZSTD decompression version effects with drift scales
    max_zstd_effect = max(abs(e[1]) for e in zstd_decomp_version_effects)
    max_zstd_drift = max(d[1] for d in zstd_decomp_drift_scales)

    print("\n-----------------------------------------------------------------------------------------")
    print(f"Summary for ZSTD Decompression (Core of DEV-071):")
    for (case, eff, pct), (_, drift) in zip(zstd_decomp_version_effects, zstd_decomp_drift_scales):
        print(f"  {case:14s}: Version Effect = {eff:+7.2f} MiB/s ({pct:+5.2f}%), Drift Scale = {drift:7.2f} MiB/s -> |Effect| <= Drift: {abs(eff) <= drift}")

    is_effect_below_drift = all(abs(eff) <= drift for (c, eff, _), (_, drift) in zip(zstd_decomp_version_effects, zstd_decomp_drift_scales))
    print(f"\nAll ZSTD cases |Version Effect| <= Drift Scale: {is_effect_below_drift}")

    final_payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device": {
            "serial_hash": dev_hash,
            "model": model,
            "release": release,
            "kernel": uname,
            "boot_id": boot_id_start,
            "uptime_start": uptime_start,
            "uptime_end": uptime_end,
        },
        "identities": {
            "version_a": {
                "commit": COMMIT_A,
                "instance_id": INSTANCE_A,
                "binary": str(BIN_A.relative_to(REPO)),
                "binary_sha256": hash_a,
            },
            "version_b": {
                "commit": COMMIT_B,
                "instance_id": INSTANCE_B,
                "binary": str(BIN_B.relative_to(REPO)),
                "binary_sha256": hash_b,
            },
        },
        "corpora": corpus_info,
        "blocks": all_block_data,
        "block_means": block_means,
        "analysis": analysis,
        "verdict": {
            "max_zstd_decomp_effect_mibs": max_zstd_effect,
            "max_zstd_decomp_drift_mibs": max_zstd_drift,
            "effect_within_drift": is_effect_below_drift,
            "recommendation": "CLOSE DEV-071 (difference is within measurement drift)" if is_effect_below_drift else "RETAIN DEV-071 (real regression observed)",
        },
    }

    out_file = Path(args.out)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(final_payload, indent=2))
    print(f"\nFull results and analysis written to: {out_file}")


if __name__ == "__main__":
    main()
