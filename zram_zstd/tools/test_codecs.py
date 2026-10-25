#!/usr/bin/env python3
"""Developer host selfcheck of production registrations, display and both codecs."""
import argparse
import ctypes.util
import json
from pathlib import Path
import re
import subprocess
from prepare_codec import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lz4-library', help='independently installed liblz4')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    prelude = (module / 'tools/selfcheck_fixture.c').read_text().split('/* ENTRIES */')[0]
    prelude = prelude[:prelude.index('static void* display_lookup')]
    prelude = prelude.replace('static void test_display(void);', '')
    production = (module / 'zram_zstd.c').read_text()
    for name in ('zs_structs.h', 'zs_offsets.c', 'zs_btf.c', 'zs_display.c', 'zs_lz4_config.h'):
        production = production.replace(f'#include "{name}"', (module / name).read_text())
    production = re.sub(r'^#include .*\n', '', production, flags=re.M)
    production = production.replace('__attribute__((section(".data.re_offsets"), used))', '')
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    source = (module / 'tools/codec_fixture.c').read_text()
    source = source.replace('/* UTILITIES */', common).replace('/* BTF */', (module / 'tools/btf_fixture.h').read_text())
    source = prelude + source.replace('/* PRODUCTION */', production)
    path = args.output / 'fixture.c'
    path.write_text(source)
    generated = args.output / 'codec'
    prepare(module, generated)
    binary = args.output / 'fixture'
    cmd = ['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-pragma-once-outside-header',
           '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', '-fno-strict-aliasing',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
           '-I' + str(module / 'compat'), '-I' + str(generated), '-I' + str(generated / 'common'),
           '-I' + str(module / 'upstream/lz4'), '-include', str(module / 'zs_lz4_config.h'),
           str(path), *map(str, sorted(generated.rglob('*.c'))), str(module / 'upstream/lz4/lz4.c'), '-o', str(binary)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    library = args.lz4_library or ctypes.util.find_library('lz4')
    if not library:
        raise RuntimeError('independent liblz4 unavailable')
    zstd_library = ctypes.util.find_library('zstd')
    if not zstd_library:
        raise RuntimeError('independent libzstd unavailable')
    result = subprocess.run([str(binary), library, zstd_library], text=True, capture_output=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    if result.stderr:
        raise RuntimeError(result.stderr)
    receipt = {'scope': 'Developer ASan/UBSan production codec/registration/display host contracts; not native Crypto/zram proof',
               'assert_sites': len(re.findall(r'\bassert\s*\(', (module / 'tools/codec_fixture.c').read_text())),
               'library': str(library), 'zstd_library': str(zstd_library), 'result': 'PASS', 'stdout': result.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(result.stdout)


if __name__ == '__main__':
    main()
