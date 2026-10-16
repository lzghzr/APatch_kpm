#!/usr/bin/env python3
"""执行规则层 BTF 前缀核对；合成数据不作为目标内核布局证据。"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    oracle = root / 're_kernel/tools/test_btf.py'
    spec = importlib.util.spec_from_file_location('btf_host', oracle)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    btf = host.Btf()
    integer = btf.add('u32', 1, 4, struct.pack('<I', 32))
    pointer = btf.add('', 2, 0)
    btf.aggregate('path', 16, [('mnt', pointer, 0), ('dentry', pointer, 8)])
    btf.aggregate('dentry', 256, [('d_inode', pointer, 48)])
    data = btf.data()
    records, strings = host.index_btf(data)
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define kfunc_lookup_name(n) kf_##n = (typeof(kf_##n))lookup(#n)
#define pr_info(...) ((void)0)
static int mode;
static void* lookup(const char*);
'''
    source = prelude + common
    source += 'static const u32 records[] = {' + ','.join(map(str, records)) + '};\n'
    source += f'static const u32 string_start = {strings}, string_length = {len(data) - strings};\n'
    source += host.HOST + r'''
static struct btf* host_error(void) { return ERR_PTR(-ENODATA); }
static struct btf* host_none(void) { return NULL; }
static void* lookup(const char* name) {
  if (!mode) return NULL;
  if (!strcmp(name, "bpf_get_btf_vmlinux")) return mode == 2 ? host_error : mode == 3 ? host_none : host_get;
  if (!strcmp(name, "btf_find_by_name_kind")) return host_find;
  if (!strcmp(name, "btf_type_by_id")) return host_type;
  if (!strcmp(name, "btf_name_by_offset")) return host_name;
  if (!strcmp(name, "btf_resolve_size")) return host_size;
  return NULL;
}
'''
    files = ('nomount/nm_structs.h', 'nomount/nm_offsets.c', 'nomount/nm_btf.c', 'kpm_utils.h')
    source += (root / files[0]).read_text()
    source += (root / files[1]).read_text().split('static struct inode* nm_file_inode', 1)[0]
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source += (root / files[2]).read_text()
    source += r'''
int main(int argc, char** argv) {
  assert(argc == 2);
  FILE* file = fopen(argv[1], "rb"); assert(file);
  assert(!fseek(file, 0, SEEK_END)); long length = ftell(file); assert(length > 0);
  rewind(file); blob = malloc(length); assert(blob);
  assert(fread(blob, 1, length, file) == (size_t)length); fclose(file);
  mode = 1; assert(!calculate_btf_rule_prefixes());
  struct kpm_btf btf = {&object, host_find, host_type, host_name, host_size};
  struct btf_type* path = (void*)kpm_btf_type(&btf, "path", 4);
  struct btf_type* dentry = (void*)kpm_btf_type(&btf, "dentry", 4);
  assert(path && dentry);
  struct btf_member* fields = (void*)(path + 1);
  fields[1].offset = 0; assert(calculate_btf_rule_prefixes() == -EINVAL); fields[1].offset = 64;
  path->size = 24; assert(calculate_btf_rule_prefixes() == -EINVAL); path->size = 16;
  struct btf_member* inode = (void*)(dentry + 1);
  inode->offset = 56 * 8; assert(calculate_btf_rule_prefixes() == -EINVAL); inode->offset = 48 * 8;
'''
    source += f'  inode->type = {integer}; assert(calculate_btf_rule_prefixes() == -EINVAL); inode->type = {pointer};\n'
    source += r'''
  u32 name = dentry->name_off; dentry->name_off = 0;
  assert(calculate_btf_rule_prefixes() == -ENOENT); dentry->name_off = name;
  resolve_error = 1; assert(calculate_btf_rule_prefixes() == -EINVAL); resolve_error = 0;
  mode = 0; assert(calculate_btf_rule_prefixes() == -ENODATA);
  mode = 2; assert(calculate_btf_rule_prefixes() == -ENODATA);
  mode = 3; assert(calculate_btf_rule_prefixes() == -ENODATA);
  mode = 1; assert(!calculate_btf_rule_prefixes());
  free(blob); puts("rule BTF prefixes and rejection boundaries: PASS"); return 0;
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    test = args.output / 'prefix.c'
    test.write_text(source)
    (args.output / 'synthetic.btf').write_bytes(data)
    binary = args.output / 'prefix'
    compiled = subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function',
                               '-fsanitize=address,undefined', '-g', str(test), '-o', str(binary)], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    executed = subprocess.run([str(binary), str(args.output / 'synthetic.btf')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(executed.stdout + executed.stderr)
    executed.check_returncode()
    receipt = {'scope': 'Developer synthetic BTF only; not native target layout',
               'sources': {name: sha(root / name) for name in files},
               'oracle_sha256': sha(oracle), 'tool_sha256': sha(Path(__file__)),
               'generated_source_sha256': sha(test), 'binary_sha256': sha(binary), 'result': executed.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(executed.stdout.strip())
    print(f'receipt SHA-256 {sha(args.output / "receipt.json")}')


if __name__ == '__main__':
    main()
