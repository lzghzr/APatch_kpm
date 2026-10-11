#!/usr/bin/env python3
"""Developer 旧内核自检：在镜像副本上运行生产推导，记录失败阶段。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from test_genl_offsets import instruction_source, offset_source


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evidence', type=Path, required=True)
    ap.add_argument('--image', action='append', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    source = (root / 're_kernel_x/re_offsets.c').read_text()
    calculation = source[source.index('static long calculate_offsets()'):].split('#endif /* !CONFIG_KPM_BASELINES */', 1)[0]
    extra = source.split('  // KP 已经计算的任务与凭据偏移', 1)[1].split('  // Generic Netlink', 1)[0]
    extra = '  // KP 已经计算的任务与凭据偏移' + extra
    table = re.search(r'struct struct_offset\s*\{.*?\};', (root / 're_kernel_x/re_offsets.c').read_text(), re.S)[0]
    common = offset_source(module).split('struct struct_offset', 1)[0]
    names = sorted(set(re.findall(r'lookup_name(?:_continue)?\((\w+)\)', calculation)) |
                   {'binder_transaction_buffer_release', 'binder_proc_transaction', 'binder_transaction',
                    'binder_stats', 'genl_validate_assign_mc_groups'})
    preamble = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CONFIG_REKERNEL_X 1
#define CONFIG_DEBUG 1
#define logkm(...) printf(__VA_ARGS__)
#pragma clang diagnostic ignored "-Wformat"
static unsigned char* image;
struct binding { const char* name; size_t offset; };
/* BINDINGS */
static unsigned long kallsyms_lookup_name(const char* name) {
  for (unsigned int i = 0; i < ARRAY_SIZE(bindings); i++)
    if (!strcmp(name, bindings[i].name)) return (unsigned long)(image + bindings[i].offset);
  return 0;
}
#define lookup_name_continue(n) n = (typeof(n))kallsyms_lookup_name(#n)
#define lookup_name(n) lookup_name_continue(n); if (!n) return -21
#define kvar(n) n
struct binder_proc; struct task_struct; struct binder_transaction; struct sk_buff;
static void *binder_transaction_buffer_release, *binder_proc_transaction, *binder_transaction, *binder_stats;
static bool binder_transaction_buffer_release_ver4, binder_transaction_buffer_release_ver5,
            binder_transaction_buffer_release_ver6;
// SDK 的运行时结果在此以夹具输入提供；本测试不证明 KP 自身偏移计算。
static struct { int16_t cred_offset, comm_offset; } task_struct_offset = {1944, 1960};
static struct { int16_t uid_offset; } cred_offset = {4};
static int calculate_btf_offsets(void) { return -ENODATA; }
'''
    results = []
    fields = re.findall(r'int16_t (\w+);', table)
    for label in args.image:
        base = args.evidence / label
        image = base / 'Image'
        inventory = json.loads((base / 'inventory.json').read_text())
        assert sha(image) == inventory['image_sha256']
        original = root / 'kernel_img' / inventory['image']
        assert original.is_file() and sha(original) == inventory['source_sha256']
        selected = {}
        for offset, _, name in json.loads((base / 'symbols.json').read_text()):
            plain = re.split(r'[.$]', name, maxsplit=1)[0]
            if plain in names and (plain not in selected or name == plain or selected[plain]['name'].endswith('.cfi_jt')):
                selected[plain] = {'offset': offset, 'name': name}
        directory = args.output / label
        directory.mkdir()
        bindings = 'static struct binding bindings[] = {' + ','.join(
            '{"' + name + '",' + str(item['offset']) + '}' for name, item in selected.items()) + '};'
        setup = '\n'.join(f'  {n} = (void*)kallsyms_lookup_name("{n}");' for n in
                          ('binder_transaction_buffer_release', 'binder_proc_transaction', 'binder_transaction', 'binder_stats'))
        dump = '\n'.join(f'  printf("RESULT {field}=%d\\n", struct_offset.{field});' for field in fields)
        fixture = preamble.replace('/* BINDINGS */', bindings) + instruction_source(root) + common + table
        fixture += '\nstatic struct struct_offset struct_offset = {.binder_buffer_data = -1};\n' + calculation
        fixture += '\nstatic int calculate_extra(void) {\n' + extra + '\nreturn 0;\n}\n'
        fixture += f'''int main(void) {{
  FILE* file = fopen({json.dumps(str(image.resolve()))}, "rb"); assert(file);
  assert(!fseek(file, 0, SEEK_END)); long length = ftell(file); assert(length > 0); rewind(file);
  assert(!posix_memalign((void**)&image, 4096, length));
  assert(fread(image, 1, length, file) == (size_t)length); assert(!fclose(file));
{setup}
  assert(binder_transaction_buffer_release && binder_proc_transaction && binder_transaction && binder_stats);
  int result = calculate_offsets(); printf("FULL_RC=%d\\n", result);
{dump}
  struct_offset.sk_buff_head = 208;
  int extra = calculate_extra(); printf("EXTRA_RC=%d\\n", extra);
  assert(extra == 0 && struct_offset.sock_sk_net == 48);
  free(image); return 0;
}}
'''
        code = directory / 'probe.c'
        code.write_text(fixture)
        binary = directory / 'probe'
        build = subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                                '-fsanitize=address,undefined', str(code), '-o', str(binary)], capture_output=True, text=True)
        (directory / 'build.log').write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stderr
        run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
        (directory / 'run.log').write_text(run.stdout + run.stderr)
        assert run.returncode == 0, run.stdout[-2500:] + run.stderr
        values = {name: int(value) for name, value in re.findall(r'^RESULT (\w+)=(-?\d+)$', run.stdout, re.M)}
        result = {'image': label, 'image_sha256': sha(image), 'symbols_sha256': sha(base / 'symbols.json'),
                  'selected': selected, 'full_rc': int(re.search(r'FULL_RC=(-?\d+)', run.stdout)[1]),
                  'extra_rc': int(re.search(r'EXTRA_RC=(-?\d+)', run.stdout)[1]), 'values': values}
        results.append(result)
        print(label, 'full_rc=' + str(result['full_rc']), 'socket chain: PASS')
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer image/host selfcheck; decodes ARM64 bytes; SDK offsets are fixture inputs; no device conclusion',
        'source_sha256': sha(root / 're_kernel_x/re_offsets.c'), 'results': results}, indent=2) + '\n')


if __name__ == '__main__':
    main()
