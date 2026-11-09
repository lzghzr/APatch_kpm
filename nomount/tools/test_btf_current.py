#!/usr/bin/env python3
"""将冻结BTF Oracle接到当前完整生产查询，逐条保留原断言。"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixtures', 'blobs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text().split('\n#ifndef CONFIG_KPM_BASELINES\n#include "nm_btf.c"', 1)[0]
    offsets = offsets.replace('__attribute__((section(".data.re_offsets"), used))', '')
    rows = []
    for index in range(8):
        original = (args.fixtures / f'btf-{index}/btf.c').read_text()
        oracle = re.findall(r'\bassert\s*\([^;]+\);', original)
        prefix = original.split('/* SPDX-License-Identifier: GPL-2.0-or-later */\n#ifndef __NM_STRUCTS_H', 1)[0]
        main = original[original.index('int main(int argc,char**argv)'):]
        # 原夹具独立测试固定I/O共同前部；显式选择新增bias=0，保留原接受/拒绝语义。
        before = ' struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;'
        assert main.count(before) >= 1
        main = main.replace(before, ' struct_offset.fop_io_bias=0;\n' + before, 1)
        source = prefix + (ROOT / 'nomount/nm_structs.h').read_text() + offsets + (ROOT / 'nomount/nm_btf.c').read_text() + main
        assert re.findall(r'\bassert\s*\([^;]+\);', source) == oracle
        out = args.output / f'btf-{index}'
        out.mkdir()
        (out / 'btf.c').write_text(source)
        commands = [['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-fsanitize=address,undefined', str(out / 'btf.c'), '-o', str(out / 'btf')],
                    [str((out / 'btf').resolve()), str((args.blobs / f'btf-{index}/input.btf').resolve())]]
        for n, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, text=True)
            (out / f'{n}.log').write_text(result.stdout + result.stderr)
            result.check_returncode()
        rows.append({'index': index, 'preserved_assert_sites': len(oracle), 'result': 'PASS'})
    (args.output / 'receipt.json').write_text(json.dumps(rows, indent=2) + '\n')
    print('8 current-production BTF replays, all original assertion sites preserved PASS')


if __name__ == '__main__':
    main()
