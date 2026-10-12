#!/usr/bin/env python3
"""核对固定子模块，使用上游 freestanding 工具准备常驻工作区源码。"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


GENERATOR_OPTIONS = [
    '--spdx', '-DZSTD_NO_INTRINSICS', '-DZSTD_NO_UNUSED_FUNCTIONS',
    '-DZSTD_LEGACY_SUPPORT=0', '-DZSTD_STATIC_LINKING_ONLY', '-DFSE_STATIC_LINKING_ONLY',
    '-DXXH_STATIC_LINKING_ONLY', '-DXXH_NO_STDLIB', '-D__GNUC__', '-D__linux__=1',
    '-DSTATIC_BMI2=0', '-DZSTD_ADDRESS_SANITIZER=0', '-DZSTD_MEMORY_SANITIZER=0',
    '-DZSTD_DATAFLOW_SANITIZER=0', '-DZSTD_COMPRESS_HEAPMODE=1', '-U__cplusplus',
    '-UZSTD_DLL_EXPORT', '-UZSTD_DLL_IMPORT', '-U__ICCARM__', '-UZSTD_MULTITHREAD',
    '-U_MSC_VER', '-U_WIN32', '-RZSTDLIB_VISIBLE=', '-RZSTDERRORLIB_VISIBLE=',
    '-DZSTD_HAVE_WEAK_SYMBOLS=0', '-DZSTD_TRACE=0', '-DZSTD_NO_TRACE',
    '-DZSTD_DISABLE_ASM', '-DZSTD_LINUX_KERNEL',
]


def prepare(module, output):
    upstream = module / 'zstd'
    entry = subprocess.check_output(
        ['git', '-C', str(module.parent), 'ls-tree', 'HEAD', '--',
         str(upstream.relative_to(module.parent))], text=True).split()
    commit = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if not entry or entry[0] != '160000' or commit != entry[2]:
        raise ValueError('ZSTD 子模块提交不匹配；先 git submodule update --init --recursive')
    if subprocess.check_output(['git', '-C', str(upstream), 'status', '--porcelain']):
        raise ValueError('ZSTD 子模块工作树不干净')
    if output.exists():
        raise ValueError('codec 输出目录已存在；请使用新的空输出目录')
    subprocess.run([sys.executable, str(upstream / 'contrib/freestanding_lib/freestanding.py'),
                    '--source-lib', str(upstream / 'lib'), '--output-lib', str(output),
                    '--zstd-deps', str(upstream / 'contrib/linux-kernel/zstd_deps.h'),
                    '--mem', str(upstream / 'contrib/linux-kernel/mem.h'),
                    *GENERATOR_OPTIONS], check=True)
    # 内核生成器通常转接到内核 xxHash；本模块保留自带实现的原字节。
    for name in ('xxhash.c', 'xxhash.h'):
        shutil.copyfile(upstream / 'lib/common' / name, output / 'common' / name)
    generated = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'MANIFEST.json').write_text(json.dumps({
        'source_commit': commit, 'generator_options': GENERATOR_OPTIONS,
        'files': generated}, indent=2) + '\n')
    return upstream


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='新的源码输出目录')
    args = parser.parse_args()
    prepare(Path(__file__).resolve().parents[1], args.output)
