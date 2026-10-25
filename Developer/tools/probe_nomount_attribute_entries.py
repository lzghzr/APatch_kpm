#!/usr/bin/env python3
"""离线记录属性入口的 BTF 声明；不判断其锁、freeze 或路径覆盖。"""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 're_kernel/tools'))
from test_btf import index_btf

ENTRIES = {'chmod_common', 'chown_common', 'vfs_fchmod', 'vfs_fchown', 'vfs_utimes', 'do_utimes'}


def probe(path):
    data = path.read_bytes()
    records, strings = index_btf(data)

    def name(offset):
        at = strings + offset
        return data[at:data.index(0, at)].decode()

    def head(type_id):
        n, info, value = struct.unpack_from('<III', data, records[type_id])
        return name(n), (info >> 24) & 31, info & 65535, value

    def describe(type_id, depth=0):
        if not type_id:
            return 'void'
        assert depth < 32
        n, kind, _, value = head(type_id)
        if kind == 2:
            return describe(value, depth + 1) + '*'
        if kind in (8, 9, 10, 11, 18):
            return describe(value, depth + 1)
        return n or f'kind{kind}'

    result = []
    for type_id in range(1, len(records)):
        n, kind, _, value = head(type_id)
        if kind != 12 or n not in ENTRIES:
            continue
        _, proto_kind, count, ret = head(value)
        assert proto_kind == 13
        params = [struct.unpack_from('<II', data, records[value] + 12 + i * 8) for i in range(count)]
        result.append({'name': n, 'return': describe(ret),
                       'parameters': [{'name': name(p), 'type': describe(t)} for p, t in params]})
    return {'blob': str(path), 'declarations': result,
            'missing': sorted(ENTRIES - {item['name'] for item in result})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--btf', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Exclusive creation: evidence from a previous invocation remains intact.
    with args.output.open('x') as output:
        json.dump({'scope': 'BTF declarations only; body order, CFI and native syscall coverage unverified',
                   'targets': [probe(path) for path in args.btf]}, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
