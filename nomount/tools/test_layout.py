#!/usr/bin/env python3
"""运行真实目标入口的布局代码，并检查合成 BTF 的分派边界。"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'nomount/tools'))
    import inspect_target
    reference = json.loads(args.reference.read_text())
    image = inspect_target.unpack_target(args.image).data
    assert reference['image_sha256'] == sha(args.image.read_bytes())
    assert reference['kernel_sha256'] == sha(image)
    symbols = {name: offset for offset, kind, name in json.loads(args.symbols.read_text())}
    windows = {'vfs_llseek': 16, 'generic_file_mmap': 8, 'iterate_dir': 12,
               'generic_fillattr': 32, 'set_nlink': 8, 'inc_nlink': 16, 'd_set_d_op': 16}
    declarations, lookups, entries = [], [], {}
    for name, count in windows.items():
        offset = symbols[name]
        raw = image[offset:offset + count * 4]
        assert offset >= 0 and offset % 4 == 0 and len(raw) == count * 4
        words = struct.unpack('<' + 'I' * count, raw)
        declarations.append(f'static uint32_t {name}_entry[] = {{' + ','.join(map(str, words)) + '};')
        lookups.append(f'if (!strcmp(name, "{name}")) {{ function_lookups++; return {name}_entry; }}')
        entries[name] = {'offset': offset, 'words': count, 'sha256': sha(raw)}
    spec = importlib.util.spec_from_file_location('btf_host', root / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    btf = host.Btf()
    ints = {size: btf.add('u' + str(size * 8), 1, size, struct.pack('<I', size * 8)) for size in (2, 4, 8)}
    pointer = btf.add('', 2, 0)
    fields = reference['offsets']
    btf.aggregate('file', 512, [('f_inode', pointer, fields['file_inode_ops']),
                  ('f_op', pointer, fields['file_inode_ops'] + 8), ('f_mapping', pointer, fields['file_mapping'])])
    btf.aggregate('inode', 512, [('i_mode', ints[2], 0), ('i_uid', ints[4], 4), ('i_gid', ints[4], 8),
                  ('i_sb', pointer, fields['inode_superblock']), ('i_ino', ints[8], fields['inode_number']),
                  ('i_nlink', ints[4], fields['inode_nlink']), ('i_size', ints[8], fields['inode_size'])])
    btf.aggregate('dentry', 256, [('d_op', pointer, fields['dentry_ops'])])
    btf.aggregate('file_operations', 256, [('owner', pointer, 0), ('llseek', pointer, 8)])
    for name, size in [('inode_operations', 256), ('super_operations', 280),
                       ('dentry_operations', 192), ('key_type', 136)]:
        btf.aggregate(name, size, [])
    data = btf.data()
    records, strings = host.index_btf(data)
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    source = (root / 'nomount/nm_structs.h').read_text() + (root / 'nomount/nm_offsets.c').read_text()
    source = source.replace('#include "nm_btf.c"', (root / 'nomount/nm_btf.c').read_text())
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
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
#define ERR_PTR(v) ((void*)(intptr_t)(v))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define pr_info printf
#define kfunc_def(name) (*kf_##name)
#define kfunc(name) kf_##name
#define kfunc_lookup_name(name) kf_##name = (typeof(kf_##name))lookup(#name)
static void* lookup(const char* name);
static unsigned long kallsyms_lookup_name(const char* name);
static int btf_mode, function_lookups;
static const struct btf* host_no_data_error(void) { return ERR_PTR(-ENODATA); }
static const struct btf* host_null_data(void) { return NULL; }
'''
    fixture = prelude + common + '\n'.join(declarations)
    fixture += 'static const u32 records[] = {' + ','.join(map(str, records)) + '};\n'
    fixture += f'static const u32 string_start = {strings}, string_length = {len(data) - strings};\n'
    fixture += host.HOST + r'''
static void* lookup(const char* name) {
  if (btf_mode) {
    if (!strcmp(name, "bpf_get_btf_vmlinux")) {
      if (btf_mode == 2) return host_bad_get;
      if (btf_mode == 3) return host_no_data_error;
      if (btf_mode == 4) return host_null_data;
      return host_get;
    }
    if (!strcmp(name, "btf_type_by_id")) return host_type;
    if (!strcmp(name, "btf_find_by_name_kind")) return host_find;
    if (!strcmp(name, "btf_name_by_offset")) return host_name;
    if (!strcmp(name, "btf_resolve_size")) return host_size;
  }
''' + '\n'.join(lookups) + r'''
  return NULL;
}
static unsigned long kallsyms_lookup_name(const char* name) { return (uintptr_t)lookup(name); }
''' + source
    fixture += '\nstatic void check_values(void) {\n'
    fixture += '\n'.join(f'assert(struct_offset.{name} == {value});' for name, value in fields.items())
    fixture += r'''
  unsigned char* file = calloc(1, 512); unsigned char* inode = calloc(1, 512);
  unsigned char* dentry = calloc(1, 256); assert(file && inode && dentry);
  void* marker = file;
  memcpy(file + struct_offset.file_inode_ops, &inode, sizeof(inode));
  memcpy(file + struct_offset.file_inode_ops + offsetof(struct nm_file_inode_ops, f_op), &marker, sizeof(marker));
  memcpy(file + struct_offset.file_mapping, &marker, sizeof(marker));
  memcpy(inode + struct_offset.inode_superblock, &marker, sizeof(marker));
  memcpy(dentry + struct_offset.dentry_ops, &marker, sizeof(marker));
  u64 number = 1234567; u32 links = 3; int64_t size = 987654;
  memcpy(inode + struct_offset.inode_number, &number, sizeof(number));
  memcpy(inode + struct_offset.inode_nlink, &links, sizeof(links));
  memcpy(inode + struct_offset.inode_size, &size, sizeof(size));
  assert((void*)nm_file_inode(file) == inode && nm_file_ops(file) == marker);
  assert(nm_file_mapping(file) == marker && (void*)nm_inode_superblock(inode) == marker);
  assert(nm_inode_number(inode) == number && nm_inode_nlink(inode) == links && nm_inode_size(inode) == size);
  assert(nm_dentry_ops(dentry) == marker);
  free(dentry); free(inode); free(file);
}
int main(int argc, char** argv) {
  assert(argc == 2);
  FILE* f = fopen(argv[1], "rb"); assert(f);
  assert(!fseek(f, 0, SEEK_END)); long len = ftell(f); assert(len > 0); rewind(f);
  blob = malloc(len); assert(blob);
  assert(fread(blob, 1, len, f) == (size_t)len && !fclose(f));
  assert(calculate_offsets() == 0); check_values();
  uint32_t saved[32];
  memcpy(saved, vfs_llseek_entry, sizeof(vfs_llseek_entry));
  for (unsigned int i = 0; i < ARRAY_SIZE(vfs_llseek_entry); i++) vfs_llseek_entry[i] = 0xd503201f;
  assert(calculate_offsets() != 0);
  memcpy(vfs_llseek_entry, saved, sizeof(vfs_llseek_entry));
  assert(calculate_offsets() == 0);
  // 一个锚点整体移位，另一个保持原位；必须拒绝片段关系冲突。
  memcpy(saved, iterate_dir_entry, sizeof(iterate_dir_entry));
  for (unsigned int i = 0; i < ARRAY_SIZE(iterate_dir_entry); i++) {
    if (inst_is_ldp(iterate_dir_entry[i]) && inst_get_ldp_rn(iterate_dir_entry[i]) == 0)
      iterate_dir_entry[i] += 1u << 15;
  }
  assert(calculate_offsets() != 0);
  memcpy(iterate_dir_entry, saved, sizeof(iterate_dir_entry));
  assert(calculate_offsets() == 0);
  assert(inst_get_ldp_imm(0xa9ff7bfd) == -16);
  assert(inst_get_ldr_imm_imm(0x79400008) == 0 && inst_get_str_imm_imm(0x79000828) == 4);
  // 参数或访存结果失去对象语义时，不接受外观相同的后续序列。
  uint32_t scalar[] = {0xf9402001, 0xf9001021}; // ldr x1,[x0,#64]; str x1,[x1,#32]
  assert(nm_scalar_copy(scalar, 2, 3, offsetof(struct nm_kstat_prefix, ino)) < 0);
  uint32_t discard[16] = {0xf940141f, 0xf94007e8}; // ldr xzr,[x0,#40]; ldr x8,[sp,#8]
  assert(nm_find_file_objects(discard) < 0);
  uint32_t bad_dentry[16] = {0xf9403001, 0xb5000041, 0xf9003001};
  assert(nm_find_dentry_ops(bad_dentry) < 0); // 首条覆盖 new_ops。
  bad_dentry[0] = 0xf9403000; bad_dentry[1] = 0xb5000040;
  assert(nm_find_dentry_ops(bad_dentry) < 0); // 首条覆盖 dentry。
  uint32_t boundary[17];
  for (unsigned int i = 0; i < ARRAY_SIZE(boundary); i++) boundary[i] = 0xd503201f;
  boundary[15] = 0xf9401408; boundary[16] = 0xf9400509;
  assert(nm_find_file_objects(boundary) < 0); // 第二条在入口窗口外。
  boundary[0] = 0x94000000; boundary[1] = 0xf9401408; boundary[2] = 0xf9400509;
  assert(nm_find_file_objects(boundary) < 0); // 调用后 x0 已不是入口 file。
  uint32_t branch[12] = {0xa9425013, 0xd61f0040, 0xf9400a88};
  assert(inst_is_br(branch[1]) && inst_get_br_rn(branch[1]) == 2);
  assert(nm_find_file_objects_from_iterate(branch) < 0); // BR 后不扫描顺序后继。
  btf_mode = 1; function_lookups = 0;
  assert(calculate_offsets() == 0 && function_lookups == 0); check_values();
  struct kpm_btf test = {&object, host_find, host_type, host_name, host_size};
  const struct btf_type* type = kpm_btf_type(&test, "file", 4); assert(type);
  struct btf_member* member = (void*)(type + 1); u32 old = member->offset;
  member->offset = 0; function_lookups = 0;
  assert(calculate_offsets() == -EINVAL && function_lookups == 0);
  member->offset = old;
  resolve_error = 1;
  assert(calculate_offsets() == -EINVAL && function_lookups == 0);
  resolve_error = 0; btf_mode = 2;
  assert(calculate_offsets() == -EINVAL && function_lookups == 0);
  btf_mode = 3;
  assert(calculate_offsets() == -ENODATA && function_lookups == 0);
  btf_mode = 4; function_lookups = 0;
  assert(calculate_offsets() == 0 && function_lookups == 7); check_values();
  btf_mode = 1;
  assert(calculate_btf_operation_sizes() == 0);
  assert(struct_offset.file_ops_size == 256 && struct_offset.inode_ops_size == 256);
  assert(struct_offset.super_ops_size == 280 && struct_offset.dentry_ops_size == 192 && struct_offset.key_type_size == 136);
  struct btf_type* key_type = (void*)kpm_btf_type(&test, "key_type", 4); assert(key_type);
  u32 old_name = key_type->name_off; key_type->name_off = 0;
  assert(calculate_btf_operation_sizes() == -ENOENT); key_type->name_off = old_name;
  u32 old_size = key_type->size; key_type->size = 4097;
  assert(calculate_btf_operation_sizes() == -EINVAL); key_type->size = 0;
  assert(calculate_btf_operation_sizes() == -EINVAL); key_type->size = old_size;
  btf_mode = 4; assert(calculate_btf_operation_sizes() == -ENODATA);
  btf_mode = 3; assert(calculate_btf_operation_sizes() == -ENODATA);
  free(blob);
  puts("PASS: target entry offsets, storage/accessors, conflicts and synthetic BTF dispatch");
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'synthetic.btf').write_bytes(data)
    path = args.output / 'target.c'
    path.write_text(fixture)
    binary = args.output / 'target'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-fno-strict-aliasing',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(path), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary), str(args.output / 'synthetic.btf')], text=True, capture_output=True, check=True)
    assert not result.stderr, result.stderr
    sources = [Path(__file__), root / 'nomount/nm_structs.h', root / 'nomount/nm_offsets.c',
               root / 'nomount/nm_btf.c', root / 'kpm_utils.h', root / 're_kernel/tools/test_btf.py']
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer 真实入口执行 + 合成 BTF；不证明 native VFS 回调、并发或实机行为',
        'image_sha256': reference['image_sha256'], 'kernel_sha256': sha(image),
        'reference_sha256': sha(args.reference.read_bytes()), 'symbols_sha256': sha(args.symbols.read_bytes()),
        'entries': entries, 'stdout': result.stdout,
        'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in sources},
    }, ensure_ascii=False, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
