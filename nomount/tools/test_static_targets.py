#!/usr/bin/env python3
"""对所选配置执行生产布局校验及 KPM JSON/blob 往返；不证明目标运行行为。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--configs', nargs='+', type=Path, required=True)
    p.add_argument('--baselines', type=Path, required=True)
    p.add_argument('--layout', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('offset_tool', root / 'patch_offsets.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    raw = a.baselines.read_bytes()
    at, size, abi = tool.sections(raw)
    layout = tool.read_layout(a.layout, raw, at, size, abi)
    fields = tool.source_fields(root / 'nomount/nm_offsets.c')
    assert layout['fields'] == fields
    source = (root / 'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    c = '''#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
'''
    c += (root / 'nomount/nm_structs.h').read_text() + source + '\nint main(void){\n'
    a.output.mkdir(parents=True, exist_ok=False)
    records = []
    for n, config in enumerate(a.configs):
        values = json.loads(config.read_text())['offsets']
        assert set(values) == set(fields)
        c += 'struct_offset=(struct struct_offset){' + ','.join(f'.{k}={v}' for k, v in values.items()) + '};\n'
        c += '''assert(!validate_offsets());
assert(!nm_validate_file_offsets((const void*)&struct_offset));
assert(!nm_validate_inode_offsets((const void*)&struct_offset));
assert(!nm_validate_directory_offsets((const void*)&struct_offset));
assert(!nm_validate_control_layout());
{struct struct_offset saved=struct_offset;
 struct_offset.fop_open=struct_offset.file_ops_size;assert(nm_validate_file_offsets((const void*)&struct_offset)<0);
 struct_offset=saved;struct_offset.sop_evict_inode=struct_offset.super_ops_size;assert(nm_validate_inode_offsets((const void*)&struct_offset)<0);
 struct_offset=saved;struct_offset.dop_release=struct_offset.dentry_ops_size;assert(nm_validate_directory_offsets((const void*)&struct_offset)<0);
 struct_offset=saved;struct_offset.key_callbacks=struct_offset.key_type_size;assert(nm_validate_control_layout()<0);
 struct_offset=saved;}
'''
        out = a.output / str(n)
        out.mkdir()
        target, blob, by_blob, restored = [out / name for name in ('target.kpm', 'offsets.bin', 'blob.kpm', 'restored.kpm')]
        commands = [
            ['patch', str(a.baselines), '--layout', str(a.layout), '--offsets', str(config), '--output', str(target)],
            ['dump', str(target), '--output', str(blob)],
            ['patch', str(a.baselines), '--layout', str(a.layout), '--blob', str(blob), '--output', str(by_blob)],
            ['patch', str(target), '--offsets', str(a.layout), '--output', str(restored)],
        ]
        for index, command in enumerate(commands):
            r = subprocess.run([sys.executable, str(root / 'patch_offsets.py')] + command, capture_output=True, text=True)
            (out / f'{index}.log').write_text(r.stdout + r.stderr)
            r.check_returncode()
        patched = target.read_bytes()
        assert len(patched) == len(raw) and patched[:at] == raw[:at] and patched[at+size:] == raw[at+size:]
        assert patched[at:at+size] == tool.encode_offsets(config, fields)
        assert by_blob.read_bytes() == patched and restored.read_bytes() == raw
        records.append({'config': str(config.relative_to(root)) if config.is_absolute() else str(config),
                        'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
                        'derived_sha256': hashlib.sha256(patched).hexdigest(), 'table_size': size})
    c += 'puts("PASS: selected static layouts and callback range refusal");return 0;}\n'
    path = a.output / 'layouts.c'
    path.write_text(c)
    r = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-g', str(path), '-o', str(a.output / 'layouts')], capture_output=True, text=True)
    (a.output / 'compile.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    r = subprocess.run([str(a.output / 'layouts')], capture_output=True, text=True)
    (a.output / 'run.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    receipt = {'scope': 'Developer host validators and configuration-only binary roundtrip; no layout derivation or native execution',
               'base_sha256': hashlib.sha256(raw).hexdigest(), 'records': records, 'result': r.stdout.strip()}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'{len(records)} selected configs: validators and JSON/blob roundtrip PASS')


if __name__ == '__main__':
    main()
