#!/usr/bin/env python3
"""把46字段的既有NoMount配置显式迁移到新基线；原文件与原字段保持。"""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
EXTENSIONS = {'file_layout': 0, 'file_operations': 0, 'file_path': 0, 'inode_times_layout': 0, 'fop_io_bias': 0}


def migrate(document):
    source = (ROOT / 'nomount/nm_offsets.c').read_text().split('};', 1)[0]
    fields = re.findall(r'int16_t\s+(\w+);', source)
    values = document['offsets']
    original = set(fields) - set(EXTENSIONS)
    if set(values) not in (original, set(fields)):
        raise ValueError('expected complete 46-field legacy or 51-field current configuration')
    if any(type(v) is not int or not -32768 <= v <= 32767 for v in values.values()):
        raise ValueError('offset values must be int16 integers')
    converted = {**EXTENSIONS, **values}
    assert all(converted[name] == value for name, value in values.items())
    result = {**document, 'nomount_layout_version': 5, 'offsets': {name: converted[name] for name in fields}}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = migrate(json.loads(args.input.read_text()))
    with args.output.open('x') as output:
        output.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
