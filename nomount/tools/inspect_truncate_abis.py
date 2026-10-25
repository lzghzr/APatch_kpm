#!/usr/bin/env python3
"""离线列出所选BTF的具名截断原型；FUNC缺失不等于内核无符号/无功能。"""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 're_kernel/tools'))
from test_btf import index_btf

NAMES = ('vfs_truncate', 'do_truncate', 'do_truncate2', 'do_sys_ftruncate',
         'vfs_ftruncate', 'file_truncate', 'handle_truncate', 'security_file_truncate',
         'security_path_truncate', 'locks_verify_truncate', 'locks_verify_locked',
         'get_write_access', 'mnt_want_write', '__mnt_is_readonly')


def inspect(path):
    data = path.read_bytes()
    records, strings = index_btf(data)

    def string(off):
        return data[strings+off:data.index(b'\0', strings+off)].decode()

    def record(id):
        return struct.unpack_from('<III', data, records[id]) if id else (0, 0, 0)

    def describe(id, depth=0):
        if not id:
            return 'void'
        if depth >= 32:
            raise ValueError('BTF type chain exceeds 32')
        name, info, type = record(id)
        kind = info >> 24 & 31
        if kind in (8, 9, 10, 11, 18):
            return {8: '', 9: 'volatile ', 10: 'const ', 11: 'restrict ', 18: ''}[kind] + describe(type, depth+1)
        if kind == 2:
            return describe(type, depth+1) + '*'
        if kind in (4, 5, 7):
            return ('union ' if kind == 5 else 'struct ') + string(name)
        if kind in (1, 6, 19):
            return f'{string(name)}[{type}B]'
        return f'kind{kind}:{string(name)}'

    found = {}
    for id in range(1, len(records)):
        name, info, type = record(id)
        if info >> 24 & 31 != 12 or string(name) not in NAMES:
            continue
        _, proto_info, ret = record(type)
        if proto_info >> 24 & 31 != 13:
            raise ValueError('FUNC does not reference FUNC_PROTO')
        params = [struct.unpack_from('<II', data, records[type]+12+8*j) for j in range(proto_info & 65535)]
        found.setdefault(string(name), []).append({'return': describe(ret), 'parameters': [
            {'name': string(n), 'type': describe(t)} for n, t in params]})
    return {'functions': found, 'missing_func_records': sorted(set(NAMES)-found.keys())}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--blobs', type=Path, nargs='+', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for i, blob in enumerate(a.blobs):
        row = {'fixture': i, **inspect(blob)}
        rows.append(row)
        for name in ('vfs_truncate', 'do_truncate', 'do_truncate2', 'handle_truncate'):
            print(i, name, row['functions'].get(name, 'no FUNC record'))
    result = {'scope': 'Developer offline BTF FUNC/FUNC_PROTO inspection; no symbol resolution, CFI address or runtime call validation', 'fixtures': rows}
    (a.output / 'receipt.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
