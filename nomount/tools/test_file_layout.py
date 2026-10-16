#!/usr/bin/env python3
"""执行真实短入口与合成 BTF 的文件布局自检；不证明 VFS/CFI/实机行为。"""

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
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--ops-reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'nomount/tools'))
    import inspect_target
    image = inspect_target.unpack_target(args.image).data
    symbols = {name: offset for offset, kind, name in json.loads(args.symbols.read_text()) if kind in ('t', 'T')}
    values = json.loads(args.reference.read_text())['values']
    ops_size = json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']['file_operations']['size']
    spec = importlib.util.spec_from_file_location('btf_host', root / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
    btf = host.Btf()
    integer = {width: btf.add('u' + str(width * 8), 1, width, struct.pack('<I', width * 8)) for width in (4, 8)}
    pointer = btf.add('', 2, 0)
    invalid_value = btf.aggregate('invalid_value', 8, [])
    callback_types = {}
    signatures = {'llseek': (8, [pointer, integer[8], integer[4]]),
                  'read_iter': (8, [pointer, pointer]), 'open': (4, [pointer, pointer]),
                  'release': (4, [pointer, pointer]), 'mmap': (4, [pointer, pointer]),
                  'splice_read': (8, [pointer, pointer, pointer, integer[8], integer[4]])}
    for name, (result, params) in signatures.items():
        proto = btf.add('', 13, integer[result], b''.join(struct.pack('<II', 0, arg) for arg in params), len(params))
        callback_types[name] = btf.add('', 2, proto)
    fields = [('owner', pointer, 0), ('llseek', callback_types['llseek'], 8), ('read', pointer, 16), ('write', pointer, 24), ('write_iter', pointer, 40)]
    fields += [(name, callback_types[name], values['file_operations.' + name]) for name in signatures if name != 'llseek']
    btf.aggregate('file_operations', ops_size, fields)
    btf.aggregate('file', values['file_size'], [('private_data', pointer, values['file.private_data']),
                  ('f_pos', integer[8], values['file.f_pos']), ('f_flags', integer[4], values['file.f_flags']),
                  ('f_mode', integer[4], values['file.f_flags'] + 4), ('f_cred', pointer, values['file.f_cred'])])
    # i_private 的值来自本目标 simple_open 的真实入口；该合成记录只用于 BTF 路由自检。
    simple = struct.unpack_from('<I', image, symbols['simple_open'])[0]
    private = ((simple >> 10) & 0xfff) * 8
    assert (simple & 0xffc003ff) == 0xf9400008
    btf.aggregate('inode', private + 8, [('i_private', pointer, private), ('i_flags', integer[4], 12)])
    btf.aggregate('kiocb', 24, [('ki_filp', pointer, 0), ('ki_pos', integer[8], 8), ('ki_complete', pointer, 16)])
    data = btf.data(); records, strings = host.index_btf(data)
    prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define kfunc_lookup_name(n) kf_##n = (typeof(kf_##n))lookup(#n)
#define pr_info(...) ((void)0)
static int mode, lookups;
static void* lookup(const char*);
static unsigned long kallsyms_lookup_name(const char* name) { return (uintptr_t)lookup(name); }
'''
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    source = prelude + common
    entries = {}
    for name, count in [('simple_open', 4), ('noop_llseek', 2), ('nonseekable_open', 5), ('file_ns_capable', 8)]:
        offset = symbols[name]; raw = image[offset:offset + count * 4]
        words = struct.unpack('<' + 'I' * count, raw)
        source += 'static u32 ' + name + '_entry[] = {' + ','.join(map(str, words)) + '};\n'
        entries[name] = {'offset': offset, 'words': count, 'sha256': hashlib.sha256(raw).hexdigest()}
    source += 'static const u32 records[] = {' + ','.join(map(str, records)) + '};\n'
    source += f'static const u32 string_start = {strings}, string_length = {len(data) - strings};\n'
    source += host.HOST + r'''
static struct btf* host_error(void) { return ERR_PTR(-ENODATA); }
static struct btf* host_none(void) { return NULL; }
static void* lookup(const char* name) {
  if (mode) {
    if (!strcmp(name,"bpf_get_btf_vmlinux")) return mode == 2 ? host_error : mode == 3 ? host_none : host_get;
    if (!strcmp(name,"btf_find_by_name_kind")) return host_find;
    if (!strcmp(name,"btf_type_by_id")) return host_type;
    if (!strcmp(name,"btf_name_by_offset")) return host_name;
    if (!strcmp(name,"btf_resolve_size")) return host_size;
  }
'''
    source += '\n'.join(f'if (!strcmp(name,"{name}")) {{ lookups++; return {name}_entry; }}' for name in entries)
    source += '\nreturn NULL;\n}\n'
    files = ('nomount/nm_structs.h', 'nomount/nm_offsets.c', 'nomount/nm_btf.c', 'kpm_utils.h')
    source += (root / files[0]).read_text()
    offset_source = (root / files[1]).read_text().replace('#include "nm_btf.c"', (root / files[2]).read_text())
    source += offset_source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source += 'static void target(void) { struct_offset.file_inode_ops = 32; struct_offset.file_mapping = 240;\n'
    slots = {'fop_open': 'open', 'fop_release': 'release', 'fop_mmap': 'mmap', 'fop_splice_read': 'splice_read'}
    source += f'struct_offset.file_ops_size = {ops_size};\n' + '\n'.join(
        f'struct_offset.{slot} = {values["file_operations." + field]};' for slot, field in slots.items()) + '\n}\n'
    source += r'''
int main(int argc, char** argv) {
  assert(argc == 2); FILE* file = fopen(argv[1],"rb"); assert(file);
  fseek(file,0,SEEK_END); long size = ftell(file); rewind(file); blob = malloc(size); assert(blob);
  assert(fread(blob,1,size,file) == (size_t)size); fclose(file);
  target(); mode = 0; assert(!nm_prepare_file_layout() && lookups == 4);
'''
    expected = {'inode_private': private, 'file_private': values['file.private_data'], 'file_position': values['file.f_pos'],
                'file_flags': values['file.f_flags'], 'file_cred': values['file.f_cred']}
    source += '\n'.join(f'assert(struct_offset.{key} == {value});' for key, value in expected.items())
    source += r'''
  struct struct_offset snapshot = struct_offset;
  u32 instructions[8] = {0x94000000,0xf9400008,0xb4000048,0xf9000028};
  assert(nm_find_private_fields(instructions,&snapshot) < 0);
  memcpy(instructions,simple_open_entry,sizeof(simple_open_entry)); instructions[1] ^= 1U<<5;
  assert(nm_find_private_fields(instructions,&snapshot) < 0); // CBZ 跳到其他位置。
  memcpy(instructions,nonseekable_open_entry,sizeof(nonseekable_open_entry)); instructions[1] = 0xaa0203e1;
  assert(nm_find_file_flags(instructions) < 0); // x1 被改写。
  memcpy(instructions,file_ns_capable_entry,sizeof(file_ns_capable_entry)); instructions[0] = 0x94000000;
  assert(nm_find_file_cred(instructions) < 0); // 调用切断参数来源。
  mode = 1; lookups = 0; assert(!nm_prepare_file_layout() && !lookups);
  struct kpm_btf btf = {&object,host_find,host_type,host_name,host_size};
  struct btf_type* io = (void*)kpm_btf_type(&btf,"kiocb",4);
  struct btf_member* fields = (void*)(io + 1); fields[2].offset = 8 * 8;
  assert(nm_prepare_file_layout() == -EINVAL && !lookups); fields[2].offset = 16 * 8;
  struct btf_type* ops = (void*)kpm_btf_type(&btf,"file_operations",4);
  fields = (void*)(ops + 1);
  struct btf_type* proto = NULL;
  for (u32 i = 0; i < (ops->info & 0xffff); i++)
    if (!strcmp(host_name(&object,fields[i].name_off),"read_iter")) {
      const struct btf_type* pointer = host_type(&object,fields[i].type); proto = (void*)host_type(&object,pointer->size);
    }
  assert(proto); u32 info = proto->info; proto->info = (13U<<24)|3;
  assert(nm_prepare_file_layout() == -EOPNOTSUPP && !lookups); proto->info = info;
  struct btf_param* params = (void*)(proto + 1); u32 argument = params[0].type;
'''
    source += f'params[0].type = {integer[8]}; assert(nm_prepare_file_layout() == -EOPNOTSUPP); params[0].type = argument;\n'
    source += f'params[0].type = {invalid_value}; assert(nm_prepare_file_layout() == -EOPNOTSUPP); params[0].type = argument;\n'
    source += r'''
  resolve_error = 1; assert(nm_prepare_file_layout() == -EINVAL && !lookups); resolve_error = 0;
  mode = 2; assert(nm_prepare_file_layout() == -ENODATA && !lookups);
  mode = 3; assert(!nm_prepare_file_layout() && lookups == 4);
  struct_offset.fop_open = -1; mode = 0; assert(nm_prepare_file_layout() == -EINVAL);
  target(); mode = 1; assert(!nm_prepare_file_layout());
  free(blob); printf("file entry anchors, storage and BTF/ABI boundaries: PASS\n"); return 0;
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    c_file = args.output / 'layout.c'; c_file.write_text(source)
    (args.output / 'synthetic.btf').write_bytes(data)
    binary = args.output / 'layout'
    compiled = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function',
                               '-fsanitize=address,undefined', '-g', str(c_file), '-o', str(binary)], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr); compiled.check_returncode()
    run = subprocess.run([str(binary), str(args.output / 'synthetic.btf')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr); run.check_returncode()
    receipt = {'scope': 'Developer real target entries plus synthetic BTF; no native execution',
               'image_sha256': sha(args.image), 'kernel_sha256': hashlib.sha256(image).hexdigest(),
               'sources': {name: sha(root / name) for name in files}, 'tool_sha256': sha(Path(__file__)),
               'reference_sha256': sha(args.reference), 'ops_reference_sha256': sha(args.ops_reference),
               'symbols_sha256': sha(args.symbols), 'entries': entries, 'derived_fields': expected, 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
