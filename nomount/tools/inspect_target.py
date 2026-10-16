#!/usr/bin/env python3
"""为一个目标生成 NoMount 移植输入；不推断运行时兼容性。"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'kernel_img' / 'offset_harness'))
import bootimg
import kallsyms_extract


# 本阶段只盘点原版入口、虚拟文件和对象回收路径；不是全部依赖表。
FUNCTIONS = {
    'control': ('register_key_type', 'unregister_key_type', 'capable',
                'get_user_pages_fast', 'set_page_dirty_lock'),
    'vfs': ('kern_path', 'path_get', 'path_put', 'dentry_open', 'fput', 'new_inode',
            'iget5_locked', 'unlock_new_inode', 'd_lookup', 'd_add', 'dput',
            'd_set_d_op', 'generic_file_mmap', 'vfs_getattr', 'vfs_getxattr',
            'iterate_dir', 'clear_inode', 'truncate_inode_pages_final'),
    'rcu': ('call_rcu', 'synchronize_rcu', 'rcu_barrier'),
    'btf_queries': ('bpf_get_btf_vmlinux', 'btf_find_by_name_kind', 'btf_type_by_id',
                    'btf_name_by_offset', 'btf_resolve_size'),
}
ANCHORS = ('vfs_llseek', 'iterate_dir', 'generic_fillattr', 'set_nlink',
           'inc_nlink', 'path_get', 'd_set_d_op', 'generic_file_mmap')
CONFIG_KEYS = ('CONFIG_KEYS', 'CONFIG_DEBUG_INFO_BTF', 'CONFIG_KALLSYMS_ALL',
               'CONFIG_ARM64_PAGE_SHIFT', 'CONFIG_CFI', 'CONFIG_CFI_CLANG',
               'CONFIG_CFI_PERMISSIVE', 'CONFIG_SHADOW_CALL_STACK')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected_config(data):
    start = data.find(b'IKCFG_ST')
    end = data.find(b'IKCFG_ED', start + 8) if start >= 0 else -1
    if end < 0:
        return None
    text = gzip.decompress(data[start + 8:end]).decode()
    result = {}
    for line in text.splitlines():
        if line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, value = line[2:-11], 'n'
        elif line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        else:
            continue
        if key in CONFIG_KEYS:
            result[key] = value
    return result


def unpack_target(image):
    source = image.read_bytes()
    if not source.startswith(b'ANDROID!'):
        return bootimg.unpack_bytes(source, image.name)
    if len(source) < 48:
        raise ValueError('boot 头不完整')
    version = struct.unpack_from('<I', source, 40)[0]
    kernel_size = struct.unpack_from('<I', source, 8)[0]
    if version in (3, 4):
        start = 4096
    elif version in (0, 1, 2):
        start = struct.unpack_from('<I', source, 36)[0]
        if start < 2048 or start > 1048576 or start & (start - 1):
            raise ValueError('boot 头页大小无效')
    else:
        raise ValueError('未支持的 boot 头版本')
    if not kernel_size or start + kernel_size > len(source):
        raise ValueError('boot 头 kernel 段越过文件边界')
    # boot kernel_size 是文件段长度；arm64 image_size 还包含运行时内存需求。
    result = bootimg.unpack_bytes(source[start:start + kernel_size], image.name)
    result.source_sha256 = sha(source)
    result.format = f'android-boot v{version}'
    return result


def inspect(image):
    unpacked = unpack_target(image)
    data = unpacked.data
    symbols, mode = kallsyms_extract.extract(data)
    if symbols is None:
        raise ValueError(f'本提取器未覆盖目标符号表：{mode}')
    addresses = {}
    for offset, kind, name in symbols:
        if kind in ('t', 'T', 'w', 'W'):
            addresses.setdefault(name, offset)
    functions = {
        group: {name: addresses.get(name) for name in names}
        for group, names in FUNCTIONS.items()
    }
    anchors = {}
    for name in ANCHORS:
        offset = addresses.get(name)
        if offset is None:
            continue
        if offset < 0 or offset + 128 > len(data) or offset % 4:
            raise ValueError(f'{name} 入口不在已提取镜像范围内')
        anchors[name] = {
            'file_offset': offset,
            'words': list(struct.unpack_from('<32I', data, offset)),
        }
    return {
        'scope': 'Developer 单目标依赖与入口清单；不证明函数 ABI、布局或真机行为',
        'image': image.name,
        'image_sha256': unpacked.source_sha256,
        'kernel_sha256': sha(data),
        'kernel_release': unpacked.release,
        'format': unpacked.format,
        'extraction_warnings': unpacked.warnings,
        'symbol_mode': mode,
        'symbol_count': len(symbols),
        'config': selected_config(data),
        'functions': functions,
        'anchors': anchors,
    }, symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='新的输出目录，已存在时拒绝覆盖')
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError('输出目录已存在，请使用新的目录')
        report, symbols = inspect(args.image)
        args.output.mkdir(parents=True)
        (args.output / 'target.json').write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        (args.output / 'symbols.json').write_text(json.dumps(symbols) + '\n')
    except (OSError, ValueError, EOFError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    print(f'{report["image"]}: {report["kernel_release"]}; '
          f'{report["symbol_count"]} symbols; 单目标清单已生成')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
