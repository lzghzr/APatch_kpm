#!/usr/bin/env python3
"""在目标 BTF 上执行生产偏移查询，参考值由独立离线解析提供。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--btf', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    module = root / 'zram_zstd'
    helper = root / 're_kernel/tools/test_btf.py'
    spec = importlib.util.spec_from_file_location('host_btf', helper)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    data = args.btf.read_bytes()
    reference = json.loads(args.reference.read_text())
    assert reference['btf_sha256'] == sha(args.btf)
    records, strings = host.index_btf(data)
    source = (module / 'zs_structs.h').read_text() + (module / 'zs_offsets.c').read_text()
    for name in ('zs_btf.c',):
        source = source.replace(f'#include "{name}"', (module / name).read_text())
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    fields = re.findall(r'int16_t (\w+);', source)
    checks = '\n'.join(f'assert(struct_offset.{name} == {reference["offsets"][name]});' for name in fields)
    prelude = (module / 'tools/selfcheck_fixture.c').read_text().split('/* ENTRIES */')[0]
    prelude = prelude.replace('#include "linux/zstd.h"', '')
    prelude = prelude.replace('#define kfunc_lookup_name(name) kf_##name = (typeof(kf_##name))lookup(#name)',
                              '#define kfunc_lookup_name(name) ((void)0)')
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    fixture = prelude + '''
#define ERR_PTR(value) ((void*)(intptr_t)(value))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define logkm printf
static unsigned char zstd_alg[1024];
static int (*kf_crypto_register_alg)(void*);
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { assert(0); return 0; }
'''
    fixture += common + source
    fixture += 'static const u32 records[] = {' + ','.join(map(str, records)) + '};\n'
    fixture += f'static const u32 string_start = {strings}, string_length = {len(data) - strings};\n'
    fixture += host.HOST + r'''
int main(int argc, char** argv) {
  assert(argc == 2);
  FILE* f = fopen(argv[1], "rb"); assert(f);
  assert(!fseek(f, 0, SEEK_END)); long len = ftell(f); assert(len > 0); rewind(f);
  blob = malloc(len); assert(blob);
  assert(fread(blob, 1, len, f) == (size_t)len && !fclose(f));
  kfunc(bpf_get_btf_vmlinux) = host_get;
  kfunc(btf_type_by_id) = host_type;
  kfunc(btf_find_by_name_kind) = host_find;
  kfunc(btf_name_by_offset) = host_name;
  kfunc(btf_resolve_size) = host_size;
  assert(calculate_offsets() == 0);
''' + checks + r'''
  free(blob);
  puts("PASS: production BTF offsets and storage contract match target reference");
}
'''
    path = args.output / 'target.c'
    path.write_text(fixture)
    binary = args.output / 'target'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(module / 'compat'), str(path), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary), str(args.btf)], text=True, capture_output=True, check=True)
    assert not result.stderr, result.stderr
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer target BTF host selfcheck; not runtime registration or device proof',
        'btf_sha256': sha(args.btf), 'reference_sha256': sha(args.reference), 'stdout': result.stdout,
        'sources': {str(p.relative_to(root)): sha(p) for p in
                    [Path(__file__), helper, module / 'zs_structs.h', module / 'zs_offsets.c', module / 'zs_btf.c',
                     module / 'tools/selfcheck_fixture.c', root / 'kpm_utils.h']},
    }, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
