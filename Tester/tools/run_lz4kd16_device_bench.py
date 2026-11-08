#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Device-side userspace benchmark runner for experimental 16 KiB LZ4KD.
Pure userspace: no KPM loading, no boot modification, no zram tampering.
Binds to frozen commit 19819b86ebb78a99d4ec797097e39baeec2651ce.
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
FROZEN_COMMIT = '19819b86ebb78a99d4ec797097e39baeec2651ce'
NDK_VERSION = '26.3.11579264'
NDK_ROOT = Path(os.environ.get('ANDROID_NDK') or (Path.home() / 'Library/Android/sdk/ndk' / NDK_VERSION))
NDK_BIN = NDK_ROOT / 'toolchains/llvm/prebuilt/darwin-x86_64/bin'
CLANG = NDK_BIN / 'aarch64-linux-android31-clang'
SYSROOT = NDK_BIN.parent / 'sysroot'

FROZEN_INPUTS = [
    'zram_zstd/experimental/lz4kd16.c',
    'zram_zstd/experimental/lz4kd16.h',
    'zram_zstd/tools/lz4kd16_fixture.c',
    'zram_zstd/tools/lz4kd16_legacy_fixture.h',
    'zram_zstd/zs_lz4kd_config.h',
    'zram_zstd/zs_lz4kd.c',
    'zram_zstd/upstream/lz4kd/lz4kd_encode.c',
    'zram_zstd/upstream/lz4kd/lz4kd.h',
    'zram_zstd/upstream/lz4/lz4.c',
    'zram_zstd/upstream/lz4/lz4.h',
    'Tester/tools/lz4kd16_device_bridge.h',
    'Tester/tools/lz4kd16_device_bridge.c',
    'Tester/tools/lz4kd16_device_runner.c',
]

CASES = ['source_text', 'integers', 'mixed_binary', 'random', 'repeat4k', 'repeat8k']
CODECS = ['lz4kd16', 'lz4kd4_chunks', 'lz4']


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_decode(data: bytes):
    """Bytewise reference parser, separate from the C encoder and optimized decoder."""
    if data[0] == 0x10:
        off_bits, literal_bits, block = 14, 5, 16384
    elif data[0] == 0:
        off_bits, literal_bits, block = 12, 6, 4096
    else:
        raise ValueError(f'unknown block header 0x{data[0]:02x}')
    repeat_bits = 24 - off_bits - literal_bits
    literal_mask, repeat_mask = (1 << literal_bits) - 1, (1 << repeat_bits) - 1
    pos, maximum_offset = 1, 0
    output = bytearray()

    def extended(base):
        nonlocal pos
        while True:
            if pos >= len(data):
                raise ValueError('truncated extension')
            value = data[pos]
            pos += 1
            base += value
            if base > block:
                raise ValueError('length exceeds block')
            if value != 255:
                return base

    while pos < len(data):
        if len(data) - pos < 3:
            raise ValueError('truncated tag')
        tag = int.from_bytes(data[pos:pos + 3], 'little')
        pos += 3
        offset = tag & ((1 << off_bits) - 1)
        literal = tag >> (off_bits + repeat_bits)
        repeat = (tag >> off_bits) & repeat_mask
        if literal == literal_mask:
            literal = extended(literal)
        if pos + literal > len(data):
            raise ValueError('truncated literals')
        output.extend(data[pos:pos + literal])
        pos += literal
        if repeat == repeat_mask:
            repeat = extended(repeat + 4) - 4
        repeat += 4
        if not offset:
            if not literal or repeat != 4 or pos != len(data):
                raise ValueError('invalid terminal tag')
        else:
            if offset > len(output):
                raise ValueError('invalid back reference')
            maximum_offset = max(maximum_offset, offset)
            for _ in range(repeat):
                output.append(output[-offset])
        if len(output) > block:
            raise ValueError('output exceeds block')
    if not output:
        raise ValueError('empty block')
    return bytes(output), maximum_offset


def verify_export(path: Path, expected: bytes, chunked: bool):
    raw, pos, maximum_offset, pages = path.read_bytes(), 0, 0, 0
    while pos < len(raw):
        length = int.from_bytes(raw[pos:pos + 4], 'little')
        pos += 4
        assert length and pos + length <= len(raw)
        data = raw[pos:pos + length]
        pos += length
        if chunked:
            assert data[:2] == b'\xc1\x04', f"bad chunk header: {data[:2].hex()}"
            sizes = struct.unpack('<4H', data[2:10])
            assert sum(sizes) + 10 == length, f"size mismatch: {sum(sizes)+10} vs {length}"
            at, decoded = 10, bytearray()
            for size in sizes:
                block, offset = reference_decode(data[at:at + size])
                assert len(block) == 4096
                decoded.extend(block)
                maximum_offset = max(maximum_offset, offset)
                at += size
        else:
            decoded, offset = reference_decode(data)
            maximum_offset = max(maximum_offset, offset)
        assert decoded == expected[pages * 16384:(pages + 1) * 16384], f"decoded mismatch on page {pages}"
        pages += 1
    assert pages == 64, f"expected 64 pages, got {pages}"
    return {'pages': pages, 'maximum_offset': maximum_offset}


def generate_corpus(corpus_dir: Path):
    corpus_dir.mkdir(parents=True, exist_ok=True)
    module = REPO / 'zram_zstd'
    rng = random.Random(0x16b10c)
    text_paths = ['zram_zstd.c', 'zs_offsets.c', 'zs_display.c', 'upstream/lz4/lz4.c']
    text = b'\n'.join((module / name).read_bytes() for name in text_paths)
    result = {name: bytearray() for name in CASES}
    for page in range(64):
        start = page * 977 % len(text)
        result['source_text'].extend((text + text)[start:start + 16384])
        for word in range(4096):
            value = word // 8 + page * 17 if word % 8 < 3 else 0 if word % 8 < 6 else (word * 31) % 251
            result['integers'].extend(struct.pack('<I', value))
        binary = bytearray(rng.randbytes(16384))
        for at in range(0, 16384, 256):
            binary[at:at + 40] = bytes(40)
            binary[at + 40:at + 44] = struct.pack('<I', page * 64 + at // 256)
        result['mixed_binary'].extend(binary)
        result['random'].extend(rng.randbytes(16384))
        result['repeat4k'].extend(rng.randbytes(4096) * 4)
        result['repeat8k'].extend(rng.randbytes(8192) * 2)

    files = {}
    for name in CASES:
        assert len(result[name]) == 1048576
        out_path = corpus_dir / f'{name}.bin'
        out_path.write_bytes(bytes(result[name]))
        files[name] = {
            'path': str(out_path.relative_to(REPO)),
            'bytes': 1048576,
            'sha256': sha256_file(out_path)
        }
    return {name: bytes(result[name]) for name in CASES}, files


def run_cmd(cmd, timeout=30, check=True):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {shlex.join(cmd)}\nStdout: {res.stdout}\nStderr: {res.stderr}")
    return res.stdout.strip()


def run_adb(serial, shell_cmd, timeout=30):
    return run_cmd(['adb', '-s', serial, 'shell', shell_cmd], timeout=timeout)


def build_bench(build_dir: Path):
    build_dir.mkdir(parents=True, exist_ok=True)
    flags = [
        '-Wall', '-O2', '-fno-strict-aliasing', '-fno-PIC',
        '-fno-asynchronous-unwind-tables', '-fno-stack-protector', '-fno-common',
        '-mgeneral-regs-only', '-mno-outline-atomics', '-ffixed-x18', '-fno-builtin'
    ]
    includes = [
        '-I' + str(REPO / 'zram_zstd/compat'),
        '-I' + str(REPO / 'zram_zstd'),
        '-I' + str(REPO / 'zram_zstd/upstream/lz4')
    ]

    # 1. lz4kd16.o
    lz4kd16_o = build_dir / 'lz4kd16.o'
    cmd1 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        *flags, '-ffreestanding', *includes,
        '-c', str(REPO / 'zram_zstd/experimental/lz4kd16.c'), '-o', str(lz4kd16_o)
    ]
    run_cmd(cmd1)
    lz4kd16_sha = sha256_file(lz4kd16_o)
    expected_obj_sha = 'bf15d7d4e45f75d15019761af7af3b81fc027016d393cd5bd71f3baf7c709586'
    assert lz4kd16_sha == expected_obj_sha, f"lz4kd16.o sha256 mismatch: {lz4kd16_sha} vs {expected_obj_sha}"

    # 2. lz4kd.o
    lz4kd_o = build_dir / 'lz4kd.o'
    cmd2 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        *flags, *includes, '-include', str(REPO / 'zram_zstd/zs_lz4kd_config.h'),
        '-c', str(REPO / 'zram_zstd/upstream/lz4kd/lz4kd_encode.c'), '-o', str(lz4kd_o)
    ]
    run_cmd(cmd2)

    # 3. lz4.o
    lz4_o = build_dir / 'lz4.o'
    cmd3 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        '-O3', '-mgeneral-regs-only', '-ffixed-x18', '-fno-strict-aliasing',
        *includes, '-include', str(REPO / 'zram_zstd/zs_lz4_config.h'),
        '-c', str(REPO / 'zram_zstd/upstream/lz4/lz4.c'), '-o', str(lz4_o)
    ]
    run_cmd(cmd3)

    # 4. lz4kd16_device_bridge.o
    bridge_o = build_dir / 'lz4kd16_device_bridge.o'
    cmd4 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        *flags, *includes,
        '-c', str(REPO / 'Tester/tools/lz4kd16_device_bridge.c'), '-o', str(bridge_o)
    ]
    run_cmd(cmd4)

    # 5. lz4kd16_device_runner.o
    runner_o = build_dir / 'lz4kd16_device_runner.o'
    cmd5 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        '-O2', '-fno-strict-aliasing', '-I' + str(REPO / 'Tester/tools'),
        '-c', str(REPO / 'Tester/tools/lz4kd16_device_runner.c'), '-o', str(runner_o)
    ]
    run_cmd(cmd5)

    # 6. Static link
    binary = build_dir / 'lz4kd16_bench'
    cmd6 = [
        str(CLANG), '--target=aarch64-linux-android31', f'--sysroot={SYSROOT}',
        '-static',
        str(runner_o), str(bridge_o), str(lz4kd16_o), str(lz4kd_o), str(lz4_o),
        '-o', str(binary)
    ]
    run_cmd(cmd6)

    return {
        'binary_path': binary,
        'binary_sha256': sha256_file(binary),
        'binary_bytes': binary.stat().st_size,
        'lz4kd16_obj_sha256': lz4kd16_sha,
        'compile_commands': [
            shlex.join(cmd1), shlex.join(cmd2), shlex.join(cmd3),
            shlex.join(cmd4), shlex.join(cmd5), shlex.join(cmd6)
        ]
    }


def test_device(serial: str, dev_label: str, binary_path: Path, corpus_bytes: dict, raw_dir: Path):
    dev_raw = raw_dir / dev_label
    dev_raw.mkdir(parents=True, exist_ok=True)
    dev_hash = hashlib.sha256(serial.encode()).hexdigest()[:8]

    # Preflight inspection
    uname = run_adb(serial, 'uname -a')
    model = run_adb(serial, 'getprop ro.product.model')
    release = run_adb(serial, 'getprop ro.build.version.release')
    pagesize = run_adb(serial, 'getconf PAGE_SIZE')
    boot_id = run_adb(serial, 'cat /proc/sys/kernel/random/boot_id 2>/dev/null || true')
    uptime = run_adb(serial, 'cat /proc/uptime')

    print(f"\n==========================================")
    print(f"Device: {dev_label} (hash: {dev_hash})")
    print(f"Model: {model}, Android: {release}, PAGE_SIZE: {pagesize}")
    print(f"Kernel: {uname}")
    print(f"==========================================")

    # Push binary and corpora to /data/local/tmp
    dev_tmp = '/data/local/tmp'
    run_cmd(['adb', '-s', serial, 'push', str(binary_path), f'{dev_tmp}/lz4kd16_bench'])
    run_adb(serial, f'chmod 755 {dev_tmp}/lz4kd16_bench')

    for name in CASES:
        src_bin = raw_dir / 'corpus' / f'{name}.bin'
        run_cmd(['adb', '-s', serial, 'push', str(src_bin), f'{dev_tmp}/{name}.bin'])

    trials_results = {c: {algo: [] for algo in CODECS} for c in CASES}
    ref_checks = {c: {} for c in CASES}

    # 3 trials with rotating order
    for trial in range(3):
        rotated_cases = CASES[trial:] + CASES[:trial]
        rotated_codecs = CODECS[trial:] + CODECS[:trial]
        print(f"\n--- Starting Trial {trial} for {dev_label} ---")
        for case in rotated_cases:
            for codec in rotated_codecs:
                algo_idx = CODECS.index(codec)
                remote_blocks = f'{dev_tmp}/{case}-{codec}-t{trial}.blocks'
                local_blocks = dev_raw / f'{case}-{codec}-t{trial}.blocks'
                cmd = f'{dev_tmp}/lz4kd16_bench {algo_idx} {dev_tmp}/{case}.bin {remote_blocks}'
                raw_out = run_adb(serial, cmd, timeout=60)
                row = json.loads(raw_out)
                assert row['roundtrip_ok'] is True
                assert math.isfinite(row['compress_mib_s']) and row['compress_mib_s'] > 0
                assert math.isfinite(row['decompress_mib_s']) and row['decompress_mib_s'] > 0
                trials_results[case][codec].append(row)

                # Pull blocks on trial 0 for reference parsing
                if trial == 0 and codec in ('lz4kd16', 'lz4kd4_chunks'):
                    run_cmd(['adb', '-s', serial, 'pull', remote_blocks, str(local_blocks)])
                    ref = verify_export(local_blocks, corpus_bytes[case], codec == 'lz4kd4_chunks')
                    ref_checks[case][codec] = ref
                    print(f"  [{case} | {codec}] clen={row['compressed_bytes']} comp={row['compress_mib_s']:.1f} MB/s decomp={row['decompress_mib_s']:.1f} MB/s max_offset={ref['maximum_offset']}")
                else:
                    print(f"  [{case} | {codec}] clen={row['compressed_bytes']} comp={row['compress_mib_s']:.1f} MB/s decomp={row['decompress_mib_s']:.1f} MB/s")

                # Remove remote blocks file
                run_adb(serial, f'rm -f {remote_blocks}')

    # Validate offsets on positive controls
    assert ref_checks['repeat4k']['lz4kd16']['maximum_offset'] >= 4096
    assert ref_checks['repeat8k']['lz4kd16']['maximum_offset'] >= 8192

    # Clean up device /data/local/tmp
    run_adb(serial, f"rm -f {dev_tmp}/lz4kd16_bench " + " ".join(f"{dev_tmp}/{c}.bin" for c in CASES))

    # Compute medians
    medians = {}
    for case, c_dict in trials_results.items():
        medians[case] = {}
        for codec, trials in c_dict.items():
            sizes = {r['compressed_bytes'] for r in trials}
            assert len(sizes) == 1, f"Compressed size changed across trials: {sizes}"
            c_bytes = trials[0]['compressed_bytes']
            c_mib_med = statistics.median(r['compress_mib_s'] for r in trials)
            d_mib_med = statistics.median(r['decompress_mib_s'] for r in trials)
            medians[case][codec] = {
                'input_bytes': 1048576,
                'compressed_bytes': c_bytes,
                'ratio': round(1048576.0 / c_bytes, 4),
                'compress_mib_s': round(c_mib_med, 3),
                'decompress_mib_s': round(d_mib_med, 3),
                'compression_workspace': trials[0]['compression_workspace'],
                'decompression_workspace': trials[0]['decompression_workspace'],
                'roundtrip_ok': True,
                'trials_compress': [round(r['compress_mib_s'], 3) for r in trials],
                'trials_decompress': [round(r['decompress_mib_s'], 3) for r in trials]
            }

    return {
        'device_serial_hash': dev_hash,
        'label': dev_label,
        'uname': uname,
        'model': model,
        'release': release,
        'pagesize': pagesize,
        'boot_id': boot_id,
        'uptime_before': uptime,
        'ref_checks': ref_checks,
        'medians': medians,
        'trials': trials_results
    }


def main():
    parser = argparse.ArgumentParser(description="Device-side userspace benchmark runner for experimental 16 KiB LZ4KD.")
    parser.add_argument("--device", default="all", help="Device serial, label (e.g. device_a_6_12), or 'all' (default: all)")
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

    if args.device == "all":
        devices = all_devs
    else:
        devices = [d for d in all_devs if d[0] == args.device or d[1] == args.device]
        if not devices:
            devices = [(args.device, default_labels[0])]

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    raw_dir = REPO / 'local/tester-raw/lz4kd16-bench'
    raw_dir.mkdir(parents=True, exist_ok=True)

    print("Step 1: Check source files SHA-256")
    src_hashes = {p: sha256_file(REPO / p) for p in FROZEN_INPUTS}

    print("Step 2: Generate and verify corpus")
    corpus_bytes, corpus_files = generate_corpus(raw_dir / 'corpus')

    print("Step 3: Compile ARM64 static benchmark executable")
    build_info = build_bench(raw_dir / 'build')
    print(f"Compiled binary: {build_info['binary_path']} ({build_info['binary_bytes']} bytes, sha256={build_info['binary_sha256']})")

    # Devices configuration (from CLI or ANDROID_SERIAL)

    all_results = {}
    for serial, dev_label in devices:
        res = test_device(serial, dev_label, build_info['binary_path'], corpus_bytes, raw_dir)
        all_results[serial] = res

    # Write raw output json
    receipt = {
        'timestamp': timestamp,
        'frozen_commit': FROZEN_COMMIT,
        'ndk_version': NDK_VERSION,
        'clang_version': run_cmd([str(CLANG), '--version']).splitlines()[0],
        'source_files': src_hashes,
        'corpus_files': corpus_files,
        'build': {
            'binary_bytes': build_info['binary_bytes'],
            'binary_sha256': build_info['binary_sha256'],
            'lz4kd16_obj_sha256': build_info['lz4kd16_obj_sha256'],
            'commands': build_info['compile_commands']
        },
        'devices': all_results
    }
    raw_json = raw_dir / f'results-{timestamp}.json'
    raw_json.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f"\nSaved raw results to {raw_json}")


if __name__ == '__main__':
    main()
