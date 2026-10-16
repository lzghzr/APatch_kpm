#!/usr/bin/env python3
"""对保存的 Linux fs.h 编译核对文件访问所需的共同片段，不外推完整结构布局。"""

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
    parser.add_argument('--headers', type=Path, required=True)
    parser.add_argument('--target-header', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', default='clang')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    files = [(tag, args.headers / tag / 'include/linux/fs.h')
             for tag in ('v4.4', 'v4.9', 'v4.14', 'v4.19', 'v5.15', 'v6.6')]
    files.append(('target', args.target_header))
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {'scope': 'ARM64 common declaration fragments; RANDSTRUCT disabled; not full structs or vendor coverage',
               'production_header_sha256': sha(root / 'nomount/nm_structs.h'),
               'tool_sha256': sha(Path(__file__)), 'profiles': []}
    for tag, path in files:
        text = path.read_text()
        ops = 'struct file_operations {' + text.split('struct file_operations {', 1)[1].split('(*write_iter)', 1)[0]
        # Include the complete write_iter declaration, stopping before any later field.
        tail = text.split('struct file_operations {', 1)[1].split('(*write_iter)', 1)[1]
        ops += '(*write_iter)' + tail.split(';', 1)[0] + ';\n};\n'
        iocb = 'struct kiocb {' + text.split('struct kiocb {', 1)[1].split('(*ki_complete)', 1)[0]
        tail = text.split('struct kiocb {', 1)[1].split('(*ki_complete)', 1)[1]
        iocb += '(*ki_complete)' + tail.split(';', 1)[0] + ';\n};\n'
        declarations = ops + iocb
        forwards = '\n'.join('struct ' + name + ';' for name in sorted(set(re.findall(r'struct\s+(\w+)', declarations))))
        source = '''typedef unsigned char u8; typedef unsigned short u16;
typedef unsigned int u32; typedef unsigned long long u64;
typedef long long loff_t, int64_t; typedef long ssize_t; typedef unsigned long size_t;
#define __user
#define randomized_struct_fields_start
#define randomized_struct_fields_end
#define offsetof(T,F) __builtin_offsetof(T,F)
''' + forwards + '\n' + declarations + (root / 'nomount/nm_structs.h').read_text()
        for native, common, fields in [('file_operations', 'nm_file_io_ops',
                                       ('owner', 'llseek', 'read', 'write', 'read_iter', 'write_iter')),
                                      ('kiocb', 'nm_kiocb_head', ('ki_filp', 'ki_pos', 'ki_complete'))]:
            for field in fields:
                source += f'_Static_assert(offsetof(struct {native},{field}) == offsetof(struct {common},{field}), "{field}");\n'
            source += f'_Static_assert(sizeof(struct {native}) == sizeof(struct {common}), "prefix size");\n'
        c_file = args.output / (tag + '.c')
        c_file.write_text(source)
        obj = args.output / (tag + '.o')
        compiled = subprocess.run([args.compiler, '--target=aarch64-none-elf', '-Wall', '-Werror', '-c',
                                   str(c_file), '-o', str(obj)], text=True, capture_output=True)
        (args.output / (tag + '.log')).write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        receipt['profiles'].append({'name': tag, 'fs_header_sha256': sha(path),
                                    'reference_source_sha256': sha(c_file), 'reference_object_sha256': sha(obj)})
        print(tag, 'common file operations and kiocb prefixes: PASS')
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('receipt SHA-256', sha(args.output / 'receipt.json'))


if __name__ == '__main__':
    main()
