#!/usr/bin/env python3
"""执行目标入口的生产函数推导，要求绑定镜像的另一来源布局参考。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    module = root / 'zram_zstd'
    reference = json.loads(args.reference.read_text())
    assert reference['image_sha256'] == sha(args.image)
    image = args.image.read_bytes()
    symbols = {name: off for off, _, name in json.loads(args.symbols.read_text())}
    windows = {'crypto_register_alg': 32, 'crypto_check_alg': 16, 'crypto_compress': 16,
               'crypto_comp_compress': 16, 'crypto_mod_get': 8, 'lzo_init': 16,
               'crypto_cts_exit_tfm': 8}
    declarations, lookups, entries = [], [], {}
    for name, count in windows.items():
        actual = name if name in symbols else next((n for n in symbols if n.startswith(name + '$')
                                                    and not n.endswith('.cfi_jt')), None)
        if actual is None:
            continue
        off = symbols[actual]
        raw = image[off:off + count * 4]
        assert len(raw) == count * 4
        words = [int.from_bytes(raw[i:i + 4], 'little') for i in range(0, len(raw), 4)]
        declarations.append('static uint32_t ' + name + '_entry[] = {' + ','.join(map(str, words)) + '};')
        lookups.append(f'if (!strcmp(name, "{name}")) return {name}_entry;')
        entries[name] = {'symbol': actual, 'offset': off, 'window': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    if 'crypto_cts_exit_tfm' in entries:
        destroy = symbols['crypto_destroy_tfm']
        relative = destroy - entries['crypto_cts_exit_tfm']['offset']
        # 宿主数组保留原 BL 立即数；只将查询到的目标地址平移同一个基址。
        lookups.append(f'if (!strcmp(name, "crypto_destroy_tfm")) return (void*)((uintptr_t)crypto_cts_exit_tfm_entry + ({relative}));')
    assert 'crypto_register_alg' in entries
    prelude = (module / 'tools/selfcheck_fixture.c').read_text().split('/* ENTRIES */')[0]
    prelude = prelude.replace('#include "linux/zstd.h"', '')
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    source = (module / 'zs_structs.h').read_text() + (module / 'zs_offsets.c').read_text()
    for name in ('zs_btf.c',):
        source = source.replace(f'#include "{name}"', (module / name).read_text())
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    fields = re.findall(r'int16_t (\w+);', source)
    checks = '\n'.join(f'assert(struct_offset.{name} == {reference["offsets"][name]});' for name in fields)
    fixture = prelude + '\n'.join(declarations)
    fixture += '\nstatic void* lookup(const char* name) {' + '\n'.join(lookups) + 'return NULL;}\n'
    fixture += 'static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { return (uintptr_t)lookup(name); }\n'
    fixture += '#define logkm printf\nstatic unsigned char zstd_alg[1024];\nstatic int (*kf_crypto_register_alg)(void*);\n'
    fixture += common + source
    fixture += 'int main(void) { kf_crypto_register_alg = (typeof(kf_crypto_register_alg))crypto_register_alg_entry;\n'
    fixture += 'assert(calculate_offsets() == 0);\n' + checks
    fixture += '\nputs("PASS: production short-function offsets match target reference"); return 0;}\n'
    path = args.output / 'target.c'
    path.write_text(fixture)
    binary = args.output / 'target'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(path), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
    assert not result.stderr, result.stderr
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer actual-entry host selfcheck; not runtime registration or device proof',
        'image_sha256': sha(args.image), 'symbols_sha256': sha(args.symbols),
        'reference_sha256': sha(args.reference), 'entries': entries, 'stdout': result.stdout,
        'sources': {str(p.relative_to(root)): sha(p) for p in
                    [Path(__file__), module / 'zs_structs.h', module / 'zs_offsets.c', module / 'zs_btf.c', 
                     module / 'tools/selfcheck_fixture.c', root / 'kpm_utils.h']},
    }, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
