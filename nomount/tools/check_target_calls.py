#!/usr/bin/env python3
"""用指定镜像的有界函数片段核对静态配置；不代替声明核对或真机测试。"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from inspect_target import unpack_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'config', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    target = json.loads(args.config.read_text())
    data = unpack_target(args.image).data
    digest = lambda b: hashlib.sha256(b).hexdigest()
    assert digest(args.image.read_bytes()) == target['image_sha256']
    assert digest(data) == target['kernel_sha256']
    symbols = {name: at for at, kind, name in json.loads(args.symbols.read_text()) if kind in ('T', 't')}
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    windows = {'iterate_dir': 12, 'generic_file_mmap': 8, 'generic_fillattr': 36,
               'simple_open': 6, 'noop_llseek': 2, 'nonseekable_open': 4, 'file_ns_capable': 16,
               'init_special_inode': 24, '__insert_inode_hash': 28, 'inode_init_always': 52,
               '__mutex_init': 10, 'register_key_type': 32, 'vfs_getattr_nosec': 17, 'full_name_hash': 3}
    decoded = {}
    for name, count in windows.items():
        at = symbols[name]
        assert at % 4 == 0 and at + count * 4 <= len(data)
        decoded[name] = [(i.address - at, i.mnemonic, i.op_str) for i in cs.disasm(data[at:at + count * 4], at)]
        assert len(decoded[name]) == count
    values = target['offsets']
    checks = []

    def instruction(name, mnemonic, operands):
        found = [(index, text) for index, op, text in decoded[name] if op == mnemonic and re.fullmatch(operands, text)]
        assert found, (name, mnemonic, operands)
        return found[0][0]

    def field(field, name, mnemonic, text):
        offset = values[field]
        # Capstone 的零偏移打印为 [xN]，正值打印为十六进制。
        index = instruction(name, mnemonic, text.format(value=hex(offset)))
        checks.append({'field': field, 'value': offset, 'anchor': name, 'instruction_offset': index})

    field('file_inode_ops', 'iterate_dir', 'ldr', r'x22, \[x0, #{value}\]')
    field('file_mapping', 'generic_file_mmap', 'ldr', r'x2, \[x0, #{value}\]')
    field('inode_superblock', 'generic_fillattr', 'ldr', r'x2, \[x0, #{value}\]')
    field('inode_number', 'generic_fillattr', 'ldr', r'x2, \[x0, #{value}\]')
    field('inode_nlink', 'generic_fillattr', 'ldr', r'w2, \[x0, #{value}\]')
    field('inode_size', 'generic_fillattr', 'ldr', r'x2, \[x0, #{value}\]')
    field('inode_blocks', 'generic_fillattr', 'ldr', r'x0, \[x0, #{value}\]')
    field('inode_private', 'simple_open', 'ldr', r'x0, \[x0, #{value}\]')
    field('file_private', 'simple_open', 'str', r'x0, \[x1, #{value}\]')
    field('file_position', 'noop_llseek', 'ldr', r'x0, \[x0, #{value}\]')
    field('file_cred', 'file_ns_capable', 'ldr', r'x0, \[x0, #{value}\]')
    instruction('nonseekable_open', 'ldr', r'w0, \[x1, #' + hex(values['file_flags'] + 4) + r'\]')
    field('inode_file_ops', 'init_special_inode', 'str', r'x1, \[x0, #{value}\]')
    field('inode_hash', '__insert_inode_hash', 'str', r'x0, \[x19, #{value}\]')
    field('inode_data', 'inode_init_always', 'add', r'x22, x1, #{value}')
    field('iop_getattr', 'vfs_getattr_nosec', 'ldr', r'x3, \[x3, #{value}\]')
    # 同一内核的 getter 明确转交 mnt/dentry/stat 三个寄存器。
    for op, text in [('mov', 'x2, x1'), ('ldr', r'x0, \[x5\]'), ('mov', 'x1, x4'), ('blr', 'x3')]:
        instruction('vfs_getattr_nosec', op, text)
    assert values['getattr_callback_args'] == 3 and values['getattr_function_args'] == 2
    for op, text in [('str', r'x2, \[x1\]'), ('str', r'w2, \[x1, #8\]'), ('strh', r'w2, \[x1, #0xc\]')]:
        instruction('generic_fillattr', op, text)
    assert values['kstat_inode_first'] == 1
    instruction('full_name_hash', 'cmp', r'w1, #7')
    instruction('full_name_hash', 'ldr', r'x3, \[x0\]')
    assert values['name_hash_args'] == 2
    # mutex 初始化写到 osq@32；key_type 注册写入内部链表尾部@120。
    instruction('__mutex_init', 'str', r'wzr, \[x0, #0x20\]')
    instruction('register_key_type', 'str', r'x19, \[x22, #0x78\]')
    assert values['mutex_size'] == 40 and values['key_type_size'] == 128
    result = {'scope': 'Developer bounded target instruction corroboration; complete table sizes need source/config evidence',
              'image_sha256': target['image_sha256'], 'kernel_sha256': target['kernel_sha256'],
              'config_sha256': digest(args.config.read_bytes()), 'checks': checks, 'windows': decoded,
              'result': 'PASS'}
    (args.output / 'receipt.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('bounded field/call corroboration: PASS;', len(checks), 'field anchors')


if __name__ == '__main__':
    main()
