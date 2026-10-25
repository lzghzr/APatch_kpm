#!/usr/bin/env python3
"""Developer：执行生产 dentry 发布 helper，检查存储顺序、标志及 ARM64 release。

需 --output 新目录与 --ndk。宿主观察点验证两个存储边界，不证明内核并发；
另用未插桩的同一生产函数交叉编译，核对生成的两个 STLR 的顺序和宽度。
既有 Oracle 不变；输出包括原始 C、汇编、编译/运行日志和 receipt.json。
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

from test_directory_abis import function


ROOT = Path(__file__).resolve().parents[2]
BASELINE = '699c547ec1b5eafb8e758626efc211e662af8b7a'
PRELUDE = '''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
'''
FIXTURE = r'''
static _Alignas(16) unsigned char storage[512];
static struct nm_dentry_head* head = (void*)storage;
static const void *old_ops, *new_ops;
static unsigned old_flags, wanted_flags, stores;
static void observe_store(const void* address, uintptr_t value, int order) {
  assert(order == __ATOMIC_RELEASE);
  if (stores == 0) {
    assert(address == &nm_dentry_objects(storage)->d_op);
    assert(value == (uintptr_t)new_ops);
    assert(head->d_flags == old_flags);
    assert(nm_dentry_objects(storage)->d_op == old_ops);
  } else {
    assert(stores == 1 && address == &head->d_flags);
    assert(value == wanted_flags);
    assert(head->d_flags == old_flags);
    assert(nm_dentry_objects(storage)->d_op == new_ops);
  }
  stores++;
}
// 仅对提取到宿主夹具中的生产 helper 设置观察点；实际存储仍用编译器 builtin。
#define __atomic_store_n(p, v, mo) do { observe_store(p, (uintptr_t)(v), mo); __atomic_store_n(p, v, mo); } while (0)
'''
MAIN = r'''
#undef __atomic_store_n
int main(void) {
  const unsigned examples[] = {0, ~0U, 0x0400081fU, 0xa5a5a5a5U};
  unsigned cases = 0;
  for (unsigned f = 0; f < 36; f++) {
    for (unsigned owned = 0; owned < 2; owned++) {
      for (unsigned original = 0; original < 2; original++) {
        memset(storage, 0, sizeof(storage));
        struct_offset.dentry_ops = 256;
        old_flags = f < 4 ? examples[f] : (1U << (f - 4));
        wanted_flags = old_flags;
        if (owned) wanted_flags &= ~(0x1U | 0x2U | 0x8U | 0x10U | 0x04000000U);
        wanted_flags |= 0x4U | 0x800U;
        old_ops = original ? storage + 384 : NULL;
        new_ops = storage + 400;
        head->d_flags = old_flags;
        nm_dentry_objects(storage)->d_op = old_ops;
        stores = 0;
        nm_publish_dentry_ops(storage, new_ops, owned);
        assert(stores == 2 && head->d_flags == wanted_flags);
        assert(nm_dentry_objects(storage)->d_op == new_ops);
        cases++;
      }
    }
  }
  assert(cases == 144);
  puts("144 publication cases: PASS");
  return 0;
}
'''


def run(command, output, name):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--host-tag', default='darwin-x86_64')
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    helper = function(offsets, 'nm_publish_dentry_ops')
    prelude = PRELUDE + (ROOT / 'nomount/nm_structs.h').read_text()
    prelude += '\nstruct { int dentry_ops; } struct_offset;\n'
    prelude += function(offsets, 'nm_dentry_objects') + '\n'

    def host_case(name, body, good):
        source = output / (name + '.c')
        source.write_text(prelude + FIXTURE + body + MAIN)
        binary = output / name
        built = run([args.cc, '-std=gnu11', '-O2', '-Wall', '-Werror', '-fsanitize=address,undefined',
                     str(source), '-o', str(binary)], output, name + '-compile')
        built.check_returncode()
        tested = run([str(binary)], output, name + '-run')
        if good:
            tested.check_returncode()
        else:
            assert tested.returncode != 0, name + ': bad publication unexpectedly accepted'
        return {'name': name, 'returncode': tested.returncode, 'expected_success': good}

    results = [host_case('production', helper, True)]
    baseline = subprocess.check_output(['git', 'show', BASELINE + ':nomount/nm_offsets.c'], cwd=ROOT).decode()
    results.append(host_case('old-candidate', function(baseline, 'nm_publish_dentry_ops'), False))
    # 保持其它代码不变，分别破坏发布顺序、release 及指针发布。
    stores = re.findall(r'^  __atomic_store_n\([^\n]+;', helper, flags=re.M)
    assert len(stores) == 2
    bad_order = helper.replace(stores[0], '@POINTER_STORE@', 1).replace(stores[1], stores[0], 1)
    bad_order = bad_order.replace('@POINTER_STORE@', stores[1], 1)
    results.append(host_case('flags-before-pointer', bad_order, False))
    results.append(host_case('flags-relaxed', helper.replace(stores[1], stores[1].replace('__ATOMIC_RELEASE', '__ATOMIC_RELAXED')), False))
    results.append(host_case('missing-pointer', helper.replace(stores[0], '', 1), False))

    # 原样 helper，不使用宿主观察宏；实际目标编译参数约束保持 ARM64 通用寄存器。
    arm_source = output / 'arm64.c'
    arm_source.write_text(prelude + helper + '\nvoid publication_probe(void* d, const void* op, bool owned) '
                          '{ nm_publish_dentry_ops(d, op, owned); }\n')
    assembly = output / 'arm64.s'
    compiler = args.ndk.resolve() / 'toolchains/llvm/prebuilt' / args.host_tag / 'bin/aarch64-linux-android31-clang'
    built = run([str(compiler), '-O2', '-mgeneral-regs-only', '-ffixed-x18', '-mno-outline-atomics',
                 '-fno-strict-aliasing', '-S', str(arm_source), '-o', str(assembly)], output, 'arm64-compile')
    built.check_returncode()
    # 此翻译单元只有一个运行时发布入口；必须先 64 位指针，后 32 位 flags。
    release_registers = re.findall(r'\bstlr\s+([xw]\d+)', assembly.read_text())
    assert len(release_registers) == 2 and [reg[0] for reg in release_registers] == ['x', 'w'], release_registers
    receipt = {'scope': 'Developer Tier-3 helper/store-boundary and ARM64 codegen checks; not kernel concurrency proof',
               'baseline_commit': BASELINE, 'production_cases': 144, 'host_results': results,
               'arm64_release_registers': release_registers, 'existing_oracle_changes': [],
               'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
               'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
