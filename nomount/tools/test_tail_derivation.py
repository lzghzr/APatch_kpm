#!/usr/bin/env python3
"""用五份目标窗口检查末端锚点；追加断链、错标志与尾部声明反例。"""
import argparse
import json
from pathlib import Path

import derive_operation_tails as derive


def refused(call):
    try:
        call()
    except (AssertionError, ValueError):
        return
    raise AssertionError('反例被接受')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    # 已人工核对的目标立即数及尾部算式，避免只比对工具自己的输出。
    expected = {
        'kernel_mi8-4.9': ([176, 216, 96, 112], [256, 232, 128, 128]),
        'kernel_mi9-4.14': ([176, 224, 96, 120], [256, 240, 128, 136]),
        'kernel_mi10-4.19': ([176, 224, 96, 120], [192, 240, 128, 136]),
        'kernel_mi11-5.4': ([160, 224, 96, 152], [256, 272, 192, 168]),
        'kernel_android12-5.10': ([160, 192, 96, 168], [256, 240, 192, 184]),
    }
    negatives = 0
    for target, (slots, sizes) in expected.items():
        receipt = json.loads((args.evidence / target / 'derive-01/receipt.json').read_text())
        code = {name: item['assembly'] for name, item in receipt['windows'].items()}
        probes = [('set_posix_acl', lambda c: derive.chained_slot(c, 32)),
                  ('super_cache_count', lambda c: derive.chained_slot(c, 48, True)),
                  ('d_set_d_op', derive.real_slot), ('unregister_key_type', derive.link_slot)]
        for index, (name, probe) in enumerate(probes):
            assert probe(code[name])['slot'] == slots[index]
            field = list(receipt['derived'])[index]
            item = receipt['derived'][field]
            assert (slots[index] + item['span'] + item['alignment'] - 1) & -item['alignment'] == sizes[index]
            for line in range(len(code[name])):
                changed = code[name].copy()
                changed[line] = 'nop'
                if line in [item.get(key) for key in ('table_load_index', 'member_load_index', 'member_address_index')]:
                    refused(lambda: probe(changed))
                    negatives += 1
        real = code['d_set_d_op'].copy()
        at = receipt['derived']['dentry_ops_size']['member_load_index']
        real[at + 3] = real[at + 3].replace('#0x4000000', '#0x2000000')
        refused(lambda: derive.real_slot(real))
        negatives += 1
    original = '''struct sample { char front[13];
 int (*last)(void *);
 ANDROID_KABI_RESERVE(1);
 ANDROID_KABI_RESERVE(2);
 ANDROID_KABI_RESERVE(3);
 ANDROID_KABI_RESERVE(4);
 } ____cacheline_aligned;'''
    first = derive.tail(original, 'sample', 'last', True, 128)
    changed = derive.tail(original.replace('char front[13]', 'char front[499]'), 'sample', 'last', True, 128)
    assert first == changed and first['span'] == 40 and first['alignment'] == 128
    assert derive.tail(original, 'sample', 'last', False, 64)['span'] == 8
    refused(lambda: derive.tail(original.replace('} ____', 'unsigned long unknown;\n} ____'), 'sample', 'last', True, 128))
    refused(lambda: derive.tail(original.replace('ANDROID_KABI_RESERVE(1)', '#ifdef HIDDEN\n ANDROID_KABI_RESERVE(1)'), 'sample', 'last', True, 128))
    print(f'PASS: five target anchor sets, {negatives + 2} negative cases; prefix independence, KABI tail and 64/128 alignment')


if __name__ == '__main__':
    main()
