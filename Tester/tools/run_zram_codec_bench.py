#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Device-side userspace benchmark runner for 4 KiB zram codec comparison.
Measures zstd-kpm, lz4-kpm, and lz4kd-kpm on identical 4 KiB corpus data.
Strictly userspace: does not tamper with KPM bytes or boot.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shlex
import statistics
import struct
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
FROZEN_COMMIT = "251240cf7e530ae7224141b552a39f808c59fcb8"
INSTANCE_ID = "zram_zstd-1.3.0+g1b12e49c5159.rf073d150.kpb51197a.ndk26.3.11579264#1"
NDK_VERSION = "26.3.11579264"
NDK_ROOT = Path(os.environ.get("ANDROID_NDK") or (Path.home() / "Library/Android/sdk/ndk" / NDK_VERSION))
NDK_BIN = NDK_ROOT / "toolchains/llvm/prebuilt/darwin-x86_64/bin"
CLANG = NDK_BIN / "aarch64-linux-android31-clang"
SYSROOT = NDK_BIN.parent / "sysroot"

CASES = ["source_text", "integers", "mixed_binary", "random"]
CODECS = ["zstd-kpm", "lz4-kpm", "lz4kd-kpm"]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cmd(cmd, timeout=30, check=True):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {shlex.join(cmd)}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res.stdout.strip()


def run_adb(serial, shell_cmd, timeout=30):
    return run_cmd(["adb", "-s", serial, "shell", shell_cmd], timeout=timeout)


def generate_corpus(corpus_dir: Path):
    corpus_dir.mkdir(parents=True, exist_ok=True)
    module = REPO / "zram_zstd"
    rng = random.Random(0x16b10c)
    text_paths = ["zram_zstd.c", "zs_offsets.c", "zs_display.c", "upstream/lz4/lz4.c"]
    text = b"\n".join((module / name).read_bytes() for name in text_paths)
    result = {name: bytearray() for name in CASES}
    for page in range(64):
        start = page * 977 % len(text)
        result["source_text"].extend((text + text)[start : start + 4096])
        for word in range(1024):
            value = word // 8 + page * 17 if word % 8 < 3 else 0 if word % 8 < 6 else (word * 31) % 251
            result["integers"].extend(struct.pack("<I", value))
        binary = bytearray(rng.randbytes(4096))
        for at in range(0, 4096, 256):
            binary[at : at + 40] = bytes(40)
            binary[at + 40 : at + 44] = struct.pack("<I", page * 16 + at // 256)
        result["mixed_binary"].extend(binary)
        result["random"].extend(rng.randbytes(4096))

    files = {}
    for name in CASES:
        assert len(result[name]) == 262144
        out_path = corpus_dir / f"{name}.bin"
        out_path.write_bytes(bytes(result[name]))
        files[name] = {
            "path": str(out_path.relative_to(REPO)),
            "bytes": 262144,
            "sha256": sha256_file(out_path),
        }
    return {name: bytes(result[name]) for name in CASES}, files


def build_bench(build_dir: Path, gen_dir: Path):
    build_dir.mkdir(parents=True, exist_ok=True)
    flags = [
        "-Wall",
        "-O2",
        "-fno-strict-aliasing",
        "-fno-PIC",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-common",
        "-mgeneral-regs-only",
        "-mno-outline-atomics",
        "-ffixed-x18",
        "-fno-builtin",
    ]
    common_cmd = [str(CLANG), "--target=aarch64-linux-android31", f"--sysroot={SYSROOT}",
                  "-I" + str(REPO / "zram_zstd"), "-I" + str(gen_dir), *flags]

    # 1. lz4.o
    lz4_o = build_dir / "lz4.o"
    cmd1 = [
        *common_cmd,
        "-O3",
        "-include",
        str(REPO / "zram_zstd/zs_lz4_config.h"),
        "-I" + str(REPO / "zram_zstd/upstream/lz4"),
        "-c",
        str(REPO / "zram_zstd/upstream/lz4/lz4.c"),
        "-o",
        str(lz4_o),
    ]
    run_cmd(cmd1)

    # 2. lz4kd_encode.o
    lz4kd_o = build_dir / "lz4kd_encode.o"
    cmd2 = [
        *common_cmd,
        "-include",
        str(REPO / "zram_zstd/zs_lz4kd_config.h"),
        "-I" + str(REPO / "zram_zstd/compat"),
        "-I" + str(REPO / "zram_zstd/upstream/lz4kd"),
        "-c",
        str(REPO / "zram_zstd/zs_lz4kd_encode.c"),
        "-o",
        str(lz4kd_o),
    ]
    run_cmd(cmd2)

    # 2b. lz4kd_decode.o
    lz4kd_dec_o = build_dir / "lz4kd_decode.o"
    cmd2b = [
        *common_cmd,
        "-include",
        str(REPO / "zram_zstd/zs_lz4kd_config.h"),
        "-I" + str(REPO / "zram_zstd/compat"),
        "-I" + str(REPO / "zram_zstd/upstream/lz4kd"),
        "-I" + str(REPO / "zram_zstd"),
        "-c",
        str(REPO / "zram_zstd/zs_lz4kd_decode.c"),
        "-o",
        str(lz4kd_dec_o),
    ]
    run_cmd(cmd2b)

    # 3. ZSTD objs
    zstd_flags = [
        "-DXXH_NO_STDLIB",
        "-DXXH_STATIC_LINKING_ONLY=",
        "-I" + str(REPO / "zram_zstd/compat"),
        "-I" + str(gen_dir),
        "-I" + str(gen_dir / "common"),
    ]
    zstd_objs = []
    for c in sorted(gen_dir.rglob("*.c")):
        rel = c.relative_to(gen_dir)
        obj = build_dir / f"zstd_{rel.stem}.o"
        cmd = [*common_cmd, *zstd_flags, "-c", str(c), "-o", str(obj)]
        run_cmd(cmd)
        zstd_objs.append(obj)

    # 4. bridge.o
    bridge_o = build_dir / "bridge.o"
    cmd4 = [
        *common_cmd,
        *zstd_flags,
        "-I" + str(REPO / "Tester/tools"),
        "-I" + str(REPO / "zram_zstd"),
        "-I" + str(REPO / "zram_zstd/upstream/lz4"),
        "-I" + str(REPO / "zram_zstd/upstream/lz4kd"),
        "-c",
        str(REPO / "Tester/tools/zram_codec_bench_bridge.c"),
        "-o",
        str(bridge_o),
    ]
    run_cmd(cmd4)

    # 5. runner.o
    runner_o = build_dir / "runner.o"
    cmd5 = [
        str(CLANG),
        "--target=aarch64-linux-android31",
        f"--sysroot={SYSROOT}",
        "-O2",
        "-fno-strict-aliasing",
        "-I" + str(REPO / "Tester/tools"),
        "-c",
        str(REPO / "Tester/tools/zram_codec_bench_runner.c"),
        "-o",
        str(runner_o),
    ]
    run_cmd(cmd5)

    # Bind production KP-pointer memory adapters to libc for this userspace instrument.
    memory_o = build_dir / "host_memory.o"
    run_cmd([*common_cmd, "-c", str(REPO / "zram_zstd/tools/host_memory.c"), "-o", str(memory_o)])

    # 6. static link
    binary = build_dir / "zram_codec_bench"
    all_objs = [runner_o, bridge_o, lz4_o, lz4kd_o, lz4kd_dec_o, memory_o, *zstd_objs]
    cmd6 = [
        str(CLANG),
        "--target=aarch64-linux-android31",
        f"--sysroot={SYSROOT}",
        "-static",
        *map(str, all_objs),
        "-lm",
        "-o",
        str(binary),
    ]
    run_cmd(cmd6)

    return {
        "binary_path": str(binary.relative_to(REPO)),
        "binary_sha256": sha256_file(binary),
        "binary_bytes": binary.stat().st_size,
        "runner_obj_sha256": sha256_file(runner_o),
        "bridge_obj_sha256": sha256_file(bridge_o),
        "lz4_obj_sha256": sha256_file(lz4_o),
        "lz4kd_obj_sha256": sha256_file(lz4kd_o),
        "lz4kd_dec_obj_sha256": sha256_file(lz4kd_dec_o),
        "host_memory_obj_sha256": sha256_file(memory_o),
    }


def test_device(serial: str, dev_label: str, binary_path: Path, raw_dir: Path):
    dev_raw = raw_dir / dev_label
    dev_raw.mkdir(parents=True, exist_ok=True)
    dev_hash = hashlib.sha256(serial.encode()).hexdigest()[:8]

    # Preflight inspection
    uname = run_adb(serial, "uname -a")
    model = run_adb(serial, "getprop ro.product.model")
    release = run_adb(serial, "getprop ro.build.version.release")
    pagesize = run_adb(serial, "getconf PAGE_SIZE")
    boot_id = run_adb(serial, "cat /proc/sys/kernel/random/boot_id 2>/dev/null || true")
    uptime = run_adb(serial, "cat /proc/uptime")

    print(f"\n==========================================")
    print(f"Device: {dev_label} (hash: {dev_hash})")
    print(f"Model: {model}, Android: {release}, PAGE_SIZE: {pagesize}")
    print(f"Kernel: {uname}")
    print(f"==========================================")

    # Push binary and corpora to /data/local/tmp
    dev_tmp = "/data/local/tmp"
    run_cmd(["adb", "-s", serial, "push", str(binary_path), f"{dev_tmp}/zram_codec_bench"])
    run_adb(serial, f"chmod 755 {dev_tmp}/zram_codec_bench")

    for name in CASES:
        src_bin = raw_dir / "corpus" / f"{name}.bin"
        run_cmd(["adb", "-s", serial, "push", str(src_bin), f"{dev_tmp}/{name}.bin"])

    trials_results = {c: {algo: [] for algo in CODECS} for c in CASES}

    # 3 trials with rotating order
    for trial in range(3):
        rotated_cases = CASES[trial:] + CASES[:trial]
        rotated_codecs = CODECS[trial:] + CODECS[:trial]
        print(f"\n--- Starting Trial {trial + 1}/3 for {dev_label} ---")
        for case in rotated_cases:
            for codec in rotated_codecs:
                algo_idx = CODECS.index(codec)
                cmd = f"{dev_tmp}/zram_codec_bench {algo_idx} {dev_tmp}/{case}.bin"
                raw_out = run_adb(serial, cmd, timeout=60)
                row = json.loads(raw_out)
                assert row["roundtrip_ok"] is True
                assert math.isfinite(row["compress_mib_s"]) and row["compress_mib_s"] > 0
                assert math.isfinite(row["decompress_mib_s"]) and row["decompress_mib_s"] > 0
                trials_results[case][codec].append(row)
                print(
                    f"  [{case:14s} | {codec:10s}] clen={row['compressed_bytes']:7d} B "
                    f"comp={row['compress_mib_s']:8.2f} MiB/s decomp={row['decompress_mib_s']:8.2f} MiB/s"
                )

    # Clean up device /data/local/tmp
    run_adb(serial, f"rm -f {dev_tmp}/zram_codec_bench " + " ".join(f"{dev_tmp}/{c}.bin" for c in CASES))

    # Compute medians
    medians = {}
    for case, c_dict in trials_results.items():
        medians[case] = {}
        for codec, trials in c_dict.items():
            sizes = {r["compressed_bytes"] for r in trials}
            assert len(sizes) == 1, f"Compressed size changed across trials: {sizes}"
            c_bytes = trials[0]["compressed_bytes"]
            c_ratio = trials[0]["compression_ratio"]
            c_mib_med = statistics.median(r["compress_mib_s"] for r in trials)
            d_mib_med = statistics.median(r["decompress_mib_s"] for r in trials)
            medians[case][codec] = {
                "compressed_bytes": c_bytes,
                "compression_ratio": c_ratio,
                "compress_mib_s_median": round(c_mib_med, 2),
                "decompress_mib_s_median": round(d_mib_med, 2),
                "raw_compress_mib_s": [round(r["compress_mib_s"], 2) for r in trials],
                "raw_decompress_mib_s": [round(r["decompress_mib_s"], 2) for r in trials],
            }

    return {
        "device_serial_hash": dev_hash,
        "model": model,
        "release": release,
        "kernel": uname,
        "boot_id": boot_id,
        "uptime": uptime,
        "medians": medians,
        "trials_results": trials_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Device-side userspace benchmark runner for 4 KiB zram codec comparison.")
    parser.add_argument("--device", default=None, help="Device serial, label (e.g. device_a_6_12), or 'all' (default: first device)")
    parser.add_argument("--devices", nargs="*", default=None, help="Device serials to benchmark (defaults to ANDROID_SERIAL)")
    args = parser.parse_args()

    cli_serials = args.devices
    if cli_serials:
        raw_serials = cli_serials
    else:
        env_serial = os.environ.get("ANDROID_SERIAL")
        if not env_serial:
            sys.exit("错误: 请设置 ANDROID_SERIAL 环境变量")
        raw_serials = [s.strip() for s in re.split(r"[,;\s]+", env_serial) if s.strip()]
        if os.environ.get("ANDROID_SERIAL_B") and os.environ.get("ANDROID_SERIAL_B").strip() not in raw_serials:
            raw_serials.append(os.environ.get("ANDROID_SERIAL_B").strip())

    default_labels = ["device_a_6_12", "device_b_4_4"]
    all_devs = []
    for idx, s in enumerate(raw_serials):
        lbl = default_labels[idx] if idx < len(default_labels) else f"device_{chr(ord('a') + idx)}"
        all_devs.append((s, lbl))

    target = args.device
    if target == "all":
        devices = all_devs
    elif target:
        devices = [d for d in all_devs if d[0] == target or d[1] == target]
        if not devices:
            devices = [(target, default_labels[0])]
    else:
        # Default to first device, preserving original behavior
        devices = [all_devs[0]]

    raw_dir = REPO / "local/tester-raw/zram-throughput"
    build_dir = raw_dir / "build"
    gen_dir = raw_dir / "codec/generated"

    # Step 1: Generate freestanding codec if not present
    if not (gen_dir / "MANIFEST.json").exists():
        print("Generating freestanding ZSTD codec...")
        cmd = [sys.executable, str(REPO / "zram_zstd/tools/prepare_codec.py"), "--output", str(gen_dir)]
        run_cmd(cmd)

    # Step 2: Build benchmark
    print("Building zram_codec_bench...")
    build_info = build_bench(build_dir, gen_dir)
    print(f"Built {build_info['binary_path']} (SHA-256: {build_info['binary_sha256']})")

    # Step 3: Generate corpus
    print("Generating 4 KiB corpora...")
    _, corpus_files = generate_corpus(raw_dir / "corpus")

    # Step 4: Run benchmarks on requested devices
    all_results = {
        "benchmark": "4KiB_production_zram_codecs",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_commit": FROZEN_COMMIT,
        "instance_id": INSTANCE_ID,
        "ndk_version": NDK_VERSION,
        "build_info": build_info,
        "corpus_files": corpus_files,
        "devices": {},
    }

    for serial, dev_label in devices:
        res = test_device(serial, dev_label, REPO / build_info["binary_path"], raw_dir)
        all_results["devices"][dev_label] = res

    out_json = raw_dir / "results.json"
    out_json.write_text(json.dumps(all_results, indent=2) + "\n")
    print(f"\nSaved all results to {out_json}")


if __name__ == "__main__":
    main()
