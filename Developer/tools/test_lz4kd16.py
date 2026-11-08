#!/usr/bin/env python3
"""Build and compare the experimental native 16 KiB LZ4KD window; host evidence only."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shlex
import statistics
import struct
import subprocess


def reference_decode(data):
    """Bytewise reference parser, separate from the C encoder and optimized decoder."""
    if data[0] == 0x10:
        off_bits, literal_bits, block = 14, 5, 16384
    elif data[0] == 0:
        off_bits, literal_bits, block = 12, 6, 4096
    else:
        raise ValueError('unknown block header')
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


def verify_export(path, expected, chunked):
    raw, pos, maximum_offset, pages = path.read_bytes(), 0, 0, 0
    while pos < len(raw):
        length = int.from_bytes(raw[pos:pos + 4], 'little')
        pos += 4
        assert length and pos + length <= len(raw)
        data = raw[pos:pos + length]
        pos += length
        if chunked:
            assert data[:2] == b'\xc1\x04'
            sizes = struct.unpack('<4H', data[2:10])
            assert sum(sizes) + 10 == length
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
        assert decoded == expected[pages * 16384:(pages + 1) * 16384]
        pages += 1
    assert pages == 64
    return {'pages': pages, 'maximum_offset': maximum_offset}


def corpus(module):
    rng = random.Random(0x16b10c)
    text_paths = ['zram_zstd.c', 'zs_offsets.c', 'zs_display.c', 'upstream/lz4/lz4.c']
    text = b'\n'.join((module / name).read_bytes() for name in text_paths)
    result = {name: bytearray() for name in ('source_text', 'integers', 'mixed_binary', 'random', 'repeat4k', 'repeat8k')}
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
    assert all(len(value) == 1048576 for value in result.values())
    return {name: bytes(value) for name, value in result.items()}, text_paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True, help='Android NDK clang')
    parser.add_argument('--sdk', type=Path, required=True, help='macOS SDK for host linking')
    parser.add_argument('--output', type=Path, required=True, help='new, immutable experiment directory')
    parser.add_argument('--allow-dirty', action='store_true', help='exploration only, not frozen evidence')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('timing comparison requires ARM64 macOS; no device operations')
    root = Path(__file__).resolve().parents[2]
    module = root / 'zram_zstd'
    inputs = [*sorted((module / 'experimental').glob('*.[ch]')),
              *sorted((module / 'upstream/lz4kd').glob('*.[ch]')),
              *sorted((module / 'compat').rglob('*.h')),
              *[module / name for name in ('Makefile', 'zram_zstd.c', 'zs_offsets.c', 'zs_display.c', 'zs_lz4kd.c',
                                          'zs_lz4kd_config.h', 'zs_lz4_config.h', 'upstream/lz4/lz4.c', 'upstream/lz4/lz4.h',
                                          'tools/prepare_codec.py', 'tools/check_binary.py', 'tools/lz4kd16_fixture.c',
                                          'tools/lz4kd16_legacy_fixture.h')],
              Path(__file__).resolve(), *[Path(__file__).with_name(name) for name in
                                         ('lz4kd16_benchmark.c', 'lz4kd16_benchmark.h', 'lz4kd16_bridge.c')]]
    relative_inputs = [str(path.relative_to(root)) for path in inputs]
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all', '--',
                                      *relative_inputs, str(module / 'upstream/zstd')], cwd=root, text=True)
    tracked = set(subprocess.check_output(['git', 'ls-files', '--', *relative_inputs], cwd=root, text=True).splitlines())
    unfrozen = bool(status) or bool(set(relative_inputs) - tracked)
    if unfrozen and not args.allow_dirty:
        raise RuntimeError('experiment inputs are not frozen; commit them or use --allow-dirty for exploration')
    frozen = {path: path.read_bytes() for path in inputs}
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    build_id = 'lz4kd16-exp-' + commit[:12] + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    args.output.mkdir(parents=True, exist_ok=False)
    log = args.output / 'commands.log'

    def run(command, env=None):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, env=env)
        with log.open('a') as stream:
            stream.write(shlex.join(list(map(str, command))) + '\n' + result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'command failed ({result.returncode}): {result.stderr}')
        return result.stdout

    includes = ['-I' + str(module / 'compat'), '-I' + str(module), '-I' + str(module / 'upstream/lz4')]
    sanitizer = args.output / 'sanitizer'
    run(['/usr/bin/clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-fno-strict-aliasing',
         '-fsanitize=address,undefined', '-fno-omit-frame-pointer', *includes,
         '-include', module / 'zs_lz4kd_config.h', module / 'tools/lz4kd16_fixture.c',
         module / 'experimental/lz4kd16.c', module / 'upstream/lz4kd/lz4kd_encode.c', '-o', sanitizer])
    sanitizer_stdout = run([sanitizer], env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})
    (args.output / 'sanitizer.log').write_text(sanitizer_stdout)

    # Compile the actual experiment for Android separately, then decode every instruction.
    flags = shlex.split(re.search(r'^CFLAGS = (.+)$', (module / 'Makefile').read_text(), re.M).group(1))
    android_object = args.output / 'lz4kd16-android.o'
    run([args.clang, '--target=aarch64-linux-android31', '--sysroot=' + str(args.clang.parent.parent / 'sysroot'),
         *flags, '-ffreestanding', *includes, '-c', module / 'experimental/lz4kd16.c', '-o', android_object])
    assembly = run([args.clang.parent / 'llvm-objdump', '-d', '--disassemble-zeroes', '--no-show-raw-insn', android_object])
    (args.output / 'lz4kd16-android.asm').write_text(assembly)
    instructions = re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+(\S+)[ \t]*(.*)$', assembly, re.M)
    data = android_object.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == 183
    shoff = int.from_bytes(data[40:48], 'little')
    shentsize, shnum = struct.unpack_from('<HH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    executable_bytes = sum(section[5] for section in sections if section[2] & 4)
    assert executable_bytes and len(instructions) * 4 == executable_bytes
    spec = importlib.util.spec_from_file_location('binary_policy', module / 'tools/check_binary.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    assert not [(mnemonic, operands) for mnemonic, operands in instructions if policy.forbidden(mnemonic, operands)]
    imports = sorted(line.split()[-1] for line in run([args.clang.parent / 'llvm-nm', '--undefined-only', android_object]).splitlines())
    assert set(imports) <= {'memcpy', 'memset'}, imports

    spec = importlib.util.spec_from_file_location('prepare_zstd', module / 'tools/prepare_codec.py')
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    generated = args.output / 'generated'
    prepare.prepare(module, generated)
    includes += ['-I' + str(generated), '-I' + str(generated / 'common')]
    prefix = [args.clang, '--target=arm64-apple-macos11', '-isysroot', args.sdk]
    objects = []
    for i, source in enumerate(sorted(generated.rglob('*.c'))):
        obj = args.output / f'zstd-{i}.o'
        run([*prefix, *flags, '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', *includes, '-c', source, '-o', obj])
        objects.append(obj)
    for name, source, options in [
            ('lz4', module / 'upstream/lz4/lz4.c', ['-O3', '-include', module / 'zs_lz4_config.h']),
            ('lz4kd', module / 'upstream/lz4kd/lz4kd_encode.c', ['-include', module / 'zs_lz4kd_config.h']),
            ('lz4kd16', module / 'experimental/lz4kd16.c', [])]:
        obj = args.output / (name + '.o')
        run([*prefix, *flags, *options, *includes, '-c', source, '-o', obj])
        objects.append(obj)
    production = (module / 'zram_zstd.c').read_text()
    params = production[production.index('static ZSTD_parameters zstd_params'):production.index('static int zstd_prepare')]
    encode = production[production.index('static size_t zstd_encode'):production.index('static int zstd_compress')]
    bridge = args.output / 'bridge.c'
    bridge.write_text(Path(__file__).with_name('lz4kd16_bridge.c').read_text().replace('/* PRODUCTION_ZSTD */', params + encode))
    bridge_object = args.output / 'bridge.o'
    driver_includes = [*includes, '-I' + str(Path(__file__).parent)]
    run([*prefix, *flags, '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', *driver_includes,
         '-c', bridge, '-o', bridge_object])
    driver_object = args.output / 'benchmark.o'
    run([*prefix, '-O2', '-fno-strict-aliasing', '-c', Path(__file__).with_name('lz4kd16_benchmark.c'), '-o', driver_object])
    binary = args.output / 'benchmark'
    run(['/usr/bin/clang', '-arch', 'arm64', '-isysroot', args.sdk, '-mmacosx-version-min=11',
         driver_object, bridge_object, *objects, '-o', binary])
    corpus_values, text_paths = corpus(module)
    cases = list(corpus_values)
    for name, value in corpus_values.items():
        (args.output / (name + '.bin')).write_bytes(value)
    codecs = ['lz4kd16', 'lz4kd4_chunks', 'lz4', 'zstd']
    results = {name: {codec: [] for codec in codecs} for name in cases}
    reference_checks = {name: {} for name in cases}
    for trial in range(3):
        for case in cases[trial:] + cases[:trial]:
            for codec in codecs[trial:] + codecs[:trial]:
                exported = args.output / f'{case}-{codec}-{trial}.blocks'
                row = json.loads(run([binary, codecs.index(codec), args.output / (case + '.bin'), exported]))
                assert all(math.isfinite(row[key]) and row[key] > 0 for key in ('compress_mib_s', 'decompress_mib_s'))
                results[case][codec].append(row)
                if codec in codecs[:2] and trial == 0:
                    reference_checks[case][codec] = verify_export(exported, corpus_values[case], codec == 'lz4kd4_chunks')
    assert reference_checks['repeat4k']['lz4kd16']['maximum_offset'] >= 4096
    assert reference_checks['repeat8k']['lz4kd16']['maximum_offset'] >= 8192
    medians = {}
    for case, values in results.items():
        medians[case] = {}
        for codec, trials in values.items():
            assert len({row['compressed_bytes'] for row in trials}) == 1
            row = dict(trials[0])
            row.pop('checksum')
            for key in ('compress_mib_s', 'decompress_mib_s'):
                row[key] = statistics.median(item[key] for item in trials)
            row['ratio'] = row['input_bytes'] / row['compressed_bytes']
            medians[case][codec] = row
    assert all(path.read_bytes() == original for path, original in frozen.items()), 'source changed during experiment'
    artifacts = {name: {'file': path.name, 'bytes': path.stat().st_size,
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                 for name, path in [('android_object', android_object), ('host_benchmark', binary), ('host_sanitizer', sanitizer)]}
    receipt = {
        'scope': 'Developer experiment: native 16 KiB window; host ASan/UBSan, Android object inspection, ARM64 macOS timing',
        'source_commit': commit, 'source_dirty': unfrozen, 'source_inputs': relative_inputs,
        'build_id': build_id, 'instance_id': build_id + '#1', 'artifacts': artifacts,
        'compiler': run([args.clang, '--version']).splitlines()[0], 'target': 'arm64-apple-macos11',
        'format': {'header': 16, 'offset_bits': 14, 'repeat_bits': 5, 'literal_bits': 5,
                   'maximum_input': 16384, 'maximum_encoded': 16453,
                   'context_bytes': medians['source_text']['lz4kd16']['compression_workspace']},
        'sanitizer': {'result': 'PASS', 'stdout': sanitizer_stdout},
        'android_object': {'instructions': len(instructions), 'executable_bytes': executable_bytes,
                           'imports': imports, 'fp_simd_sve_x18': 0, 'undecoded': 0},
        'corpus': {'pages_per_case': 64, 'page_bytes': 16384, 'text_sources': text_paths,
                   'general_cases': cases[:4], 'cross_window_positive_controls': cases[4:],
                   'seed': '0x16b10c', 'generator': 'Python random.Random.randbytes, integers, fixed source slices'},
        'chunk_container_overhead': 10, 'reference_checks': reference_checks,
        'trials': results, 'medians': medians,
        'not_covered': ['independent audit', 'native Crypto API registration', '16 KiB kernel zram',
                        'kernel concurrency/reclaim', 'Android ARM performance', '64 KiB blocks']}
    (args.output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(sanitizer_stdout, end='')
    print(json.dumps(medians, indent=2))


if __name__ == '__main__':
    main()
