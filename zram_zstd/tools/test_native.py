#!/usr/bin/env python3
"""Developer native-zcomp host tests using the selected kernel's actual base and split BTF."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
from prepare_codec import prepare
from host_native import native_source, hook_frame


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--btf', type=Path, required=True)
    p.add_argument('--module-btf', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    spec = importlib.util.spec_from_file_location('btf_host', root / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    def parts(path):
        data = path.read_bytes()
        _, _, _, h, t, n, s, z = struct.unpack_from('<HBBIIIII', data)
        return data[h+t:h+t+n], data[h+s:h+s+z]
    bt, bs = parts(a.btf)
    mt, ms = parts(a.module_btf)
    # Split-BTF names and type references already use base-global offsets/IDs.
    types, strings = bt + mt, bs + ms
    data = struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings
    (a.output / 'input.btf').write_bytes(data)
    records, string_start = host.index_btf(data)
    prelude = (module / 'tools/selfcheck_fixture.c').read_text().split('/* ENTRIES */')[0]
    prelude = prelude[:prelude.index('static void* display_lookup')]
    prelude = prelude.replace('static void test_display(void);', '')
    prelude += 'static void* lookup(const char*);\n'
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    production = native_source(module, (module / 'zram_zstd.c').read_text())
    for name in ('zs_structs.h', 'zs_offsets.c', 'zs_btf.c', 'zs_display.c', 'zs_lz4_config.h', 'zs_lz4kd.c'):
        production = production.replace(f'#include "{name}"', (module / name).read_text())
    production = re.sub(r'^#include (?!"zs_zstd_config.h").*\n', '', production, flags=re.M)
    production = production.replace('__attribute__((section(".data.re_offsets"), used))', '')
    declarations = ('#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n#define ERR_PTR(e) ((void*)(intptr_t)(e))\n'
                    'static const unsigned int records[] = {' + ','.join(map(str, records)) + '};\n'
                    f'static const unsigned int string_start = {string_start}, string_length = {len(strings)};\n')
    # Kernel btf_type_by_id returns NULL for unknown IDs; only this new generated fixture is adapted.
    btf_host = host.HOST.replace('assert(btf == &object && id < ARRAY_SIZE(records));',
                                'assert(btf == &object); if (id >= ARRAY_SIZE(records)) return NULL;')
    fixture = (module / 'tools/native_front_fixture.c').read_text()
    source = hook_frame(prelude + declarations + common + btf_host + fixture, native_fixture=True)
    source = source.replace('/* PRODUCTION */', production)
    path = a.output / 'fixture.c'
    path.write_text(source)
    generated = a.output / 'codec'
    prepare(module, generated)
    flags = ['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-pragma-once-outside-header',
             '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', '-fno-strict-aliasing',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
             '-I' + str(module), '-I' + str(module / 'compat'), '-I' + str(generated), '-I' + str(generated / 'common'),
             '-I' + str(module / 'upstream/lz4'), '-I' + str(module / 'upstream/lz4kd'),
             '-include', str(module / 'zs_lz4_config.h'), '-include', str(module / 'zs_lz4kd_config.h'),
             '-include', str(module / 'upstream/lz4kd/lz4kd.h')]
    obj = a.output / 'lz4.o'
    run = subprocess.run([*flags, '-O3', '-c', str(module / 'upstream/lz4/lz4.c'), '-o', str(obj)], capture_output=True, text=True)
    log = run.stdout + run.stderr
    (a.output / 'compile.log').write_text(log)
    run.check_returncode()
    binary = a.output / 'fixture'
    run = subprocess.run([*flags, str(path), *map(str, sorted(generated.rglob('*.c'))), str(obj),
                          str(module / 'zs_lz4kd_encode.c'), str(module / 'tools/host_memory.c'), str(module / 'zs_lz4kd_decode.c'), '-o', str(binary)], capture_output=True, text=True)
    (a.output / 'compile.log').write_text(log + run.stdout + run.stderr)
    if run.returncode:
        raise RuntimeError(run.stderr)
    run = subprocess.run([str(binary), str(a.output / 'input.btf')], capture_output=True, text=True)
    (a.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    assert not run.stderr, run.stderr
    receipt = dict(source_commit=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                   scope='Developer ASan/UBSan real-BTF native-zcomp host model; not native execution',
                   base_types=len(host.index_btf(a.btf.read_bytes())[0])-1, module_types=len(records)-1-(len(host.index_btf(a.btf.read_bytes())[0])-1),
                   assert_sites=len(re.findall(r'\bassert\s*\(', fixture)), result='PASS', stdout=run.stdout)
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout)


if __name__ == '__main__':
    main()
