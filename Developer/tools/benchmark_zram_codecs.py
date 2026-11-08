#!/usr/bin/env python3
"""Same NDK compiler, ARM64 macOS ABI: 4 KiB O2/O3 and ZSTD parameter comparison."""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import re
import shlex
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True, help='NDK clang used for all C compilation')
    parser.add_argument('--sdk', type=Path, required=True, help='macOS SDK, linking host executables only')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('This host benchmark requires ARM64 macOS; KPM checks are separate')
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    module = root / 'zram_zstd'
    spec = importlib.util.spec_from_file_location('prepare_zstd', module / 'tools/prepare_codec.py')
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    generated = args.output / 'generated'
    prepare.prepare(module, generated)
    log = args.output / 'commands.log'

    def run(command):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True)
        with log.open('a') as out:
            out.write(shlex.join(list(map(str, command))) + '\n' + result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout

    prefix = [args.clang, '--target=arm64-apple-macos11', '-isysroot', args.sdk]
    flags = shlex.split(re.search(r'^CFLAGS = (.+)$', (module / 'Makefile').read_text(), re.M).group(1))
    includes = ['-I' + str(module / 'compat'), '-I' + str(generated), '-I' + str(generated / 'common'),
                '-I' + str(module / 'upstream/lz4')]
    zstd_sources = sorted(generated.rglob('*.c'))
    codec_objects = {}
    for optimization in ('O2', 'O3'):
        directory = args.output / optimization
        directory.mkdir()
        zstd_objects = []
        for i, source in enumerate(zstd_sources):
            obj = directory / f'zstd-{i}.o'
            run([*prefix, *flags, '-' + optimization, '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=',
                 *includes, '-c', source, '-o', obj])
            zstd_objects.append(obj)
        lz4_obj = directory / 'lz4.o'
        run([*prefix, *flags, '-' + optimization, '-include', module / 'zs_lz4_config.h',
             '-c', module / 'upstream/lz4/lz4.c', '-o', lz4_obj])
        codec_objects[optimization] = {'zstd': zstd_objects, 'lz4': [lz4_obj]}
    production = (module / 'zram_zstd.c').read_text()
    params = production[production.index('static ZSTD_parameters zstd_params'):production.index('static int zstd_prepare')]
    encode = production[production.index('static size_t zstd_encode'):production.index('static int zstd_compress')]
    source = (Path(__file__).with_name('zram_codec_benchmark.c')).read_text()
    profiles = [('zstd_auto_O2', 'zstd', 'O2', '-DCODEC_ZSTD_AUTO'),
                ('zstd_native_O2', 'zstd', 'O2', '-DCODEC_ZSTD_NATIVE'),
                ('zstd_native_O3', 'zstd', 'O3', '-DCODEC_ZSTD_NATIVE'),
                ('lz4_O2', 'lz4', 'O2', '-DCODEC_LZ4'), ('lz4_O3', 'lz4', 'O3', '-DCODEC_LZ4')]
    binaries = {}
    for name, codec, optimization, define in profiles:
        driver = args.output / (name + '.c')
        driver.write_text(source.replace('/* PRODUCTION_ZSTD */', params + encode if codec == 'zstd' else ''))
        obj = args.output / (name + '.o')
        run([*prefix, '-O2', '-fno-strict-aliasing', *includes, define, '-c', driver, '-o', obj])
        binary = args.output / name
        run(['/usr/bin/clang', '-arch', 'arm64', '-isysroot', args.sdk, '-mmacosx-version-min=11',
             obj, *codec_objects[optimization][codec], '-o', binary])
        binaries[name] = binary
    results = {name: [] for name in binaries}
    names = list(binaries)
    for trial in range(3):
        for name in names[trial:] + names[:trial]:
            results[name].append(json.loads(run([binaries[name]])))
    medians = {}
    for name, values in results.items():
        assert len({v['compressed_bytes'] for v in values}) == 1
        medians[name] = {key: statistics.median(v[key] for v in values)
                         for key in ('compress_mib_s', 'decompress_mib_s')}
        medians[name]['compressed_bytes'] = values[0]['compressed_bytes']
    for codec in ('zstd_native', 'lz4'):
        assert medians[codec + '_O2']['compressed_bytes'] == medians[codec + '_O3']['compressed_bytes']
    receipt = {'scope': 'Developer host-only benchmark; NDK-compiled codec objects, ARM64 macOS ABI, not Android kernel throughput',
               'compiler': subprocess.check_output([args.clang, '--version'], text=True).splitlines()[0],
               'target': 'arm64-apple-macos11', 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
               'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
               'corpus': '256 synthetic 4096-byte pages: text, integers, structured binary, pseudorandom; no same-filled pages',
               'trials': results, 'medians': medians}
    (args.output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(medians, indent=2))


if __name__ == '__main__':
    main()
