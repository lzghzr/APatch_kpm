#!/usr/bin/env python3
"""开发自检：实际镜像入口、生产编解码及独立 libzstd 互解。"""
import argparse
import ctypes.util
import hashlib
import json
from pathlib import Path
import re
import subprocess
from prepare_codec import prepare


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_fixture(args, module):
    root = module.parent
    data = args.image.read_bytes()
    symbols = {name: off for off, _, name in json.loads(args.symbols.read_text())}
    # 直接提供实际入口字节，执行生产 C 推导，不重写一份 Python 算法。
    windows = {'crypto_register_alg': 32, 'crypto_compress': 16, 'crypto_create_tfm': 32, 'lzo_init': 16,
               'crypto_check_alg': 16, 'crypto_mod_get': 8}
    entries = {}
    declarations = []
    for name, count in windows.items():
        off = symbols[name]
        raw = data[off:off + count * 4]
        assert len(raw) == count * 4
        words = [int.from_bytes(raw[i:i + 4], 'little') for i in range(0, len(raw), 4)]
        declarations.append(f'static uint32_t {name}_entry[] = {{' + ','.join(hex(w) for w in words) + '};')
        entries[name] = {'image_offset': off, 'window_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    lookup = '\n'.join(f'  if (!strcmp(name, "{name}")) return {name}_entry;' for name in windows)
    production = (module / 'zram_zstd.c').read_text().replace('#include "zs_offsets.c"', (module / 'zs_offsets.c').read_text())
    production = production.replace('#include "zs_structs.h"', (module / 'zs_structs.h').read_text())
    for name in ('zs_btf.c', 'zs_display.c'):
        production = production.replace(f'#include "{name}"', (module / name).read_text())
    production = re.sub(r'^#include .*\n', '', production, flags=re.M)
    production = production.replace('__attribute__((section(".data.re_offsets"), used))', '')
    utilities = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    fixture = (module / 'tools/selfcheck_fixture.c').read_text()
    fixture = fixture.replace('/* ENTRIES */', '\n'.join(declarations)).replace('/* LOOKUP */', lookup)
    fixture = fixture.replace('/* BTF_FIXTURE */', (module / 'tools/btf_fixture.h').read_text())
    fixture = fixture.replace('/* UTILITIES */', utilities).replace('/* PRODUCTION */', production)
    if args.reference:
        reference = json.loads(args.reference.read_text())
        if reference['image_sha256'] != sha(args.image):
            raise ValueError('独立布局参考与目标镜像哈希不一致')
        fields = ('crypto_alg_flags', 'crypto_alg_name', 'crypto_alg_compress',
                  'crypto_alg_init', 'crypto_tfm_ctx', 'crypto_alg_driver_name')
        checks = '\n'.join(f'  assert(struct_offset.{name} == {int(reference["offsets"][name])});' for name in fields)
        fixture = re.sub(r'/\* REFERENCE_BEGIN \*/.*?/\* REFERENCE_END \*/', checks, fixture, flags=re.S)
    return fixture, entries


def run_fixture(args, module, fixture):
    source = args.output / 'selfcheck.c'
    source.write_text(fixture)
    binary = args.output / 'selfcheck'
    generated = args.output / 'codec'
    upstream = prepare(module, generated)
    codec = sorted(generated.rglob('*.c'))
    compiled = subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                               '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', '-fno-strict-aliasing', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                               '-I' + str(module / 'compat'), '-I' + str(generated),
                               '-I' + str(generated / 'common'), str(source), *map(str, codec), '-o', str(binary)],
                              text=True, capture_output=True)
    log = args.output / 'compile.log'
    log.write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f'宿主编译失败（{compiled.returncode}），日志见 {log}\n'
                           + compiled.stdout + compiled.stderr)
    library = ctypes.util.find_library('zstd')
    if not library:
        raise RuntimeError('缺少独立 libzstd；互解自检未执行')
    result = subprocess.run([str(binary), str(args.image), library], text=True, capture_output=True)
    (args.output / 'stdout.txt').write_text(result.stdout)
    (args.output / 'stderr.txt').write_text(result.stderr)
    result.check_returncode()
    if result.stderr:
        raise RuntimeError('自检产生诊断，查看 stderr.txt')
    print(result.stdout, end='')
    return upstream, generated, library, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, help='该镜像的独立布局参考；缺省保留原 4.4 判据')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    fixture, entries = build_fixture(args, module)
    upstream, generated, library, result = run_fixture(args, module, fixture)
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer host selfcheck; not kernel registration, concurrency or device proof',
        'image_sha256': sha(args.image), 'symbols_sha256': sha(args.symbols), 'entries': entries,
        'independent_library_sha256': sha(Path(library)), 'stdout': result.stdout,
        'reference_sha256': sha(args.reference) if args.reference else None,
        'zstd_source_commit': subprocess.check_output(
            ['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip(),
        'generated_codec_manifest_sha256': sha(generated / 'MANIFEST.json'),
        'fixture_sha256': sha(args.output / 'selfcheck.c'),
        'sources': {str(p.relative_to(root)): sha(p) for p in
                    [module / 'zram_zstd.c', module / 'zs_structs.h', module / 'zs_offsets.c', module / 'zs_btf.c', module / 'zs_display.c', root / 'kpm_utils.h', Path(__file__),
                     module / 'tools/prepare_codec.py', module / 'tools/selfcheck_fixture.c', module / 'tools/btf_fixture.h']},
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
