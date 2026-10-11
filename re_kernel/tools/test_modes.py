#!/usr/bin/env python3
"""Developer 双模式自检：生产新增推导片段、ELF 模式和静态补丁边界。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('patcher', root / 'patch_offsets.py')
    patcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patcher)
    results = []
    for module in ('re_kernel', 're_kernel_x'):
        version = re.search(r'^MYKPM_VERSION := (.+)$', (root / module / 'Makefile').read_text(), re.M)[1]
        for mode in ('static', 'dynamic'):
            for debug in ('', '_debug'):
                suffix = '_baselines' if mode == 'static' else ''
                path = root / module / f'{module}_{version}{suffix}{debug}.kpm'
                data = path.read_bytes()
                assert b'offset_mode=' + mode.encode() + b'\0' in data
                assert (b'bpf_get_btf_vmlinux\0' in data) == (mode == 'dynamic')
                assert (b'binder_free_proc\0' in data) == (mode == 'dynamic')
                if mode == 'static':
                    assert b'task_struct_offset\0' not in data and b'cred_offset\0' not in data
                    offset, size, abi = patcher.sections(data)
                    fields = patcher.source_fields(root / module / "re_offsets.c")
                    assert size == len(fields) * 2 == 90 and abi is None
                    assert struct.unpack_from('<h', data, offset + size - 2)[0] == 6
                    for value in (3, 4, 5, 6):
                        original = data[offset:offset + size]
                        payload = original[:-2] + struct.pack('<h', value)
                        profile = args.output / f'{path.stem}-abi{value}.bin'
                        profile.write_bytes(payload)
                        output = args.output / f'{path.stem}-abi{value}.kpm'
                        layout = args.output / f'{path.name}.json'
                        if not layout.exists():
                            patcher.run(argparse.Namespace(command='baseline', kpm=path, output=layout, source=root / module / 're_offsets.c'))
                        patcher.run(argparse.Namespace(command='patch', kpm=path, output=output,
                                                       layout=layout, blob=profile, offsets=None))
                        patched = output.read_bytes()
                        assert patched[:offset] == data[:offset] and patched[offset + size:] == data[offset + size:]
                        assert patched[offset:offset + size] == payload
                elif module == 're_kernel_x':
                    offset, size, abi = patcher.sections(data)
                    values = struct.unpack_from('<45h', data, offset)
                    fields = patcher.source_fields(root / module / "re_offsets.c")
                    assert values[fields.index('binder_buffer_data')] == -1
                    assert all(v == 0 for f, v in zip(fields, values) if f != 'binder_buffer_data')
                results.append({'file': path.name, 'sha256': sha(path), 'mode': mode})

    offsets = (root / 're_kernel_x/re_offsets.c').read_text()
    fragment = offsets.split('  // KP 已经计算的任务与凭据偏移', 1)[1].split('  // Generic Netlink', 1)[0]
    fragment = '  // KP 已经计算的任务与凭据偏移' + fragment
    table = re.search(r'struct struct_offset\s*\{.*?\};', (root / 're_kernel_x/re_offsets.c').read_text(), re.S)[0]
    instructions = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t u32;
/* INSTRUCTIONS */
/* TABLE */
static struct struct_offset struct_offset;
static struct { int16_t cred_offset, comm_offset; } task_struct_offset;
static struct { int16_t uid_offset; } cred_offset;
static bool binder_transaction_buffer_release_ver4, binder_transaction_buffer_release_ver5,
            binder_transaction_buffer_release_ver6;
static uint32_t words[16];
static void* anchor = words;
static uint32_t cookie_words[8];
static void* cookie_anchor;
#define logkm(...) ((void)0)
#define lookup_name(name) name = anchor; if (!name) return -21
#define lookup_name_continue(name) name = cookie_anchor
static int calculate_extra(void) {
/* FRAGMENT */
  return 0;
}
static uint32_t ldr(int rt, int rn, unsigned int off) {
  return 0xf9400000 | (off / 8 << 10) | (rn << 5) | rt;
}
static void reset(void) {
  for (unsigned int i = 0; i < 16; i++) words[i] = 0xd503201f;
  struct_offset = (struct struct_offset){.sk_buff_head = 208, .binder_buffer_data = -1};
  task_struct_offset.cred_offset = 1944; task_struct_offset.comm_offset = 1960;
  cred_offset.uid_offset = 4; anchor = words; cookie_anchor = NULL;
  binder_transaction_buffer_release_ver4 = false;
  binder_transaction_buffer_release_ver5 = false;
  binder_transaction_buffer_release_ver6 = false;
}
int main(void) {
  for (int abi = 3; abi <= 6; abi++) {
    reset(); words[0] = ldr(7, 0, 48); words[1] = ldr(1, 7, 136);
    binder_transaction_buffer_release_ver4 = abi == 4;
    binder_transaction_buffer_release_ver5 = abi >= 5;
    binder_transaction_buffer_release_ver6 = abi == 6;
    assert(calculate_extra() == 0);
    assert(struct_offset.task_struct_cred == 1944 && struct_offset.cred_uid == 4);
    assert(struct_offset.task_struct_comm == 1960 && struct_offset.sk_buff_tail == 200);
    assert(struct_offset.sock_sk_net == 48 && struct_offset.binder_release_abi == abi);
    assert(struct_offset.binder_buffer_data == -1);
  }
  reset(); words[3] = ldr(8, 0, 48); words[5] = ldr(9, 0, 560);
  words[7] = ldr(20, 8, 72); words[8] = ldr(0, 9, 24); words[9] = 0xaa1403e1;
  assert(calculate_extra() == 0 && struct_offset.sock_sk_net == 48);
  reset(); words[3] = ldr(8, 0, 48); words[7] = ldr(20, 8, 72);
  words[8] = 0xaa0203f4; words[9] = 0xaa1403e1;
  assert(calculate_extra() == -EINVAL);
  reset(); words[14] = ldr(3, 0, 56); words[15] = ldr(1, 3, 136);
  assert(calculate_extra() == 0 && struct_offset.sock_sk_net == 56);
  reset(); words[15] = ldr(3, 0, 56); assert(calculate_extra() == -EINVAL);
  reset(); words[0] = ldr(7, 0, 48); words[1] = 0xaa0203e7; words[2] = ldr(1, 7, 136);
  assert(calculate_extra() == -EINVAL);
  reset(); words[0] = ldr(7, 0, 48); words[1] = 0xd65f03c0; words[2] = ldr(1, 7, 136);
  assert(calculate_extra() == -EINVAL);
  reset(); words[0] = ldr(7, 0, 48); words[1] = ldr(2, 7, 136);
  words[2] = ldr(8, 0, 64); words[3] = ldr(1, 8, 136);
  assert(calculate_extra() == -EINVAL);
  reset(); anchor = NULL; assert(calculate_extra() == -21);
  reset(); task_struct_offset.cred_offset = -1; assert(calculate_extra() == -EINVAL);
  reset(); anchor = NULL; cookie_anchor = cookie_words;
  for (unsigned int i = 0; i < 8; i++) cookie_words[i] = 0xd503201f;
  cookie_words[2] = ldr(8, 0, 48);
  assert(calculate_extra() == 0 && struct_offset.sock_sk_net == 48);
  cookie_words[2] = 0xd503201f; cookie_words[7] = ldr(8, 0, 56);
  assert(calculate_extra() == 0 && struct_offset.sock_sk_net == 56);
  cookie_words[7] = 0xd503201f;
  assert(calculate_extra() == -21);  // 短入口扫不到，旧入口也缺失。
  cookie_words[0] = 0xd65f03c0; cookie_words[2] = ldr(8, 0, 48);
  assert(calculate_extra() == -21);
  cookie_words[0] = 0x94000001;
  assert(calculate_extra() == -21);
  cookie_words[0] = 0xaa0103e0;
  assert(calculate_extra() == -21);  // x0 已被覆盖。
  cookie_words[0] = 0xd503201f; cookie_words[2] = 0xb9403008;
  assert(calculate_extra() == -21);  // 32 位读取不是 net 指针。
  puts("shared KP fields, skb tail, ABI3-6, short socket chain and fixed-window failures: PASS");
}
'''.replace('/* INSTRUCTIONS */', instructions).replace('/* TABLE */', table).replace('/* FRAGMENT */', fragment)
    source = args.output / 'extra.c'
    source.write_text(fixture)
    binary = args.output / 'extra'
    build = subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                            str(source), '-o', str(binary)], capture_output=True, text=True)
    (args.output / 'build.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stdout + build.stderr
    run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    inputs = [root / f for f in ('re_kernel/re_offsets.c', 're_kernel/re_kernel.c', 're_kernel_x/re_offsets.c',
                                're_kernel_x/re_kernel.c', 're_kernel/Makefile', 're_kernel_x/Makefile', 'kpm_utils.h', 'patch_offsets.py',
                                're_kernel_x/re_btf.c')]
    (args.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer host/ELF selfcheck; no device conclusion',
        'sources': {str(p.relative_to(root)): sha(p) for p in inputs}, 'artifacts': results,
        'extra_stdout': run.stdout, 'extra_exit_code': run.returncode}, indent=2) + '\n')
    print('Eight mode-tagged KPMs, static imports/table patches, dynamic zero table: PASS')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
