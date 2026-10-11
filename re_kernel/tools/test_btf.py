#!/usr/bin/env python3
"""Developer BTF 自检：执行生产查询代码，核对合成或目标 BTF 的参考偏移。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


# 冻结基准的 38 项动态查询判据；静态表的其余字段不增加动态查询依赖。
REK_BTF_FIELDS = (
    'binder_alloc_buffer_size', 'binder_alloc_buffer', 'binder_alloc_free_async_space',
    'binder_alloc_pid', 'binder_node_async_todo', 'binder_node_cookie',
    'binder_node_has_async_transaction', 'binder_node_lock', 'binder_node_ptr',
    'binder_proc_alloc', 'binder_proc_context', 'binder_proc_inner_lock',
    'binder_proc_is_dead', 'binder_proc_is_frozen', 'binder_proc_outer_lock',
    'binder_proc_outstanding_txns', 'binder_stats_deleted_transaction', 'binder_transaction_buffer',
    'binder_transaction_code', 'binder_transaction_flags', 'binder_transaction_from',
    'binder_transaction_to_proc', 'genl_family_id', 'genl_family_config',
    'genl_family_mcgrps', 'genl_family_n_mcgrps', 'genl_family_n_mcgrps_size',
    'genl_family_mcgrp_offset', 'net_genl_sock', 'sk_buff_len',
    'sk_buff_transport_header', 'sk_buff_network_header', 'sk_buff_head',
    'sk_buff_data', 'task_struct_group_leader', 'task_struct_jobctl',
    'task_struct_pid', 'task_struct_tgid',
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index_btf(data):
    magic, version, flags, header, start, length, strings, string_length = struct.unpack_from('<HBBIIIII', data)
    assert (magic, version, flags, header) == (0xeb9f, 1, 0, 24)
    assert header + start + length <= len(data) and header + strings + string_length <= len(data)
    at, end = header + start, header + start + length
    records = [0]
    while at < end:
        records.append(at)
        _, info, _ = struct.unpack_from('<III', data, at)
        kind, count = (info >> 24) & 31, info & 65535
        extra = {1: 4, 2: 0, 3: 12, 4: count * 12, 5: count * 12, 6: count * 8, 7: 0,
                 8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: count * 8, 14: 4, 15: count * 12,
                 16: 0, 17: 4, 18: 0, 19: count * 12}[kind]
        at += 12 + extra
    assert at == end
    return records, header + strings


class Btf:
    def __init__(self):
        self.strings = bytearray(b'\0')
        self.records = []

    def name(self, text):
        pos = len(self.strings)
        self.strings.extend(text.encode() + b'\0')
        return pos

    def add(self, name, kind, size, extra=b'', count=0, flag=False):
        self.records.append(struct.pack('<III', self.name(name), kind << 24 | count | int(flag) << 31, size) + extra)
        return len(self.records)

    def aggregate(self, name, size, members, kind=4):
        return self.add(name, kind, size, b''.join(struct.pack('<III', self.name(n), t, off * 8)
                                                  for n, t, off in members), len(members))

    def data(self):
        records = b''.join(self.records)
        return struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(records), len(records), len(self.strings)) + records + self.strings


def synthetic():
    b = Btf()
    ints = {size: b.add('u' + str(size * 8), 1, size, struct.pack('<I', size * 8)) for size in (1, 2, 4, 8)}
    pointer = b.add('', 2, ints[8])
    u32 = b.add('named_u32', 8, ints[4])
    list_head = b.aggregate('list_head', 16, [('next', pointer, 0), ('prev', pointer, 8)])
    array16 = b.add('', 3, 0, struct.pack('<III', ints[1], ints[4], 16))
    array48 = b.add('', 3, 0, struct.pack('<III', ints[1], ints[4], 48))
    stats_array = b.add('', 3, 0, struct.pack('<III', u32, ints[4], 7))
    enum = b.add('binder_stat_types', 6, 4, b''.join(struct.pack('<Ii', b.name(n), v) for n, v in
                [('BINDER_STAT_PROC', 0), ('BINDER_STAT_TRANSACTION', 5)]), 2)
    work_enum = b.add('', 6, 4, struct.pack('<Ii', b.name('BINDER_WORK_TRANSACTION'), 1), 1)
    work = b.aggregate('binder_work', 24, [('type', work_enum, 16), ('entry', list_head, 0)])
    alloc = b.aggregate('binder_alloc', 160, [('pid', ints[4], 132), ('free_async_space', ints[8], 104),
                          ('buffer_size', ints[8], 120), ('buffer', pointer, 64)])
    lock = b.aggregate('spinlock_t', 4, [('raw', ints[4], 0)])
    b.aggregate('binder_node', 136, [('ptr', ints[8], 88), ('cookie', ints[8], 96), ('lock', lock, 4),
                ('has_async_transaction', ints[1], 107), ('async_todo', list_head, 112)])
    b.aggregate('binder_proc', 624, [('pid', ints[4], 64), ('tsk', pointer, 72), ('alloc', alloc, 424),
                ('context', pointer, 576), ('inner_lock', lock, 584), ('outer_lock', lock, 588),
                ('is_dead', ints[1], 112), ('is_frozen', ints[1], 113), ('outstanding_txns', ints[4], 108)])
    b.aggregate('binder_thread', 128, [('proc', pointer, 0)])
    b.aggregate('binder_transaction', 200, [('work', work, 8), ('from', pointer, 40), ('to_proc', pointer, 72),
                ('buffer', pointer, 112), ('code', u32, 120), ('flags', u32, 124)])
    fields = [('free', ints[4], 320 | 1 << 24), ('transaction', pointer, 48 * 8),
              ('target_node', pointer, 56 * 8), ('data_size', ints[8], 64 * 8),
              ('offsets_size', ints[8], 72 * 8), ('extra_buffers_size', ints[8], 80 * 8), ('pid', ints[4], 96 * 8)]
    b.add('binder_buffer', 4, 104, b''.join(struct.pack('<III', b.name(n), t, off) for n, t, off in fields), len(fields), True)
    b.aggregate('binder_stats', 256, [('obj_deleted', stats_array, 184)])
    b.aggregate('task_struct', 4096, [('group_leader', pointer, 1560), ('jobctl', ints[8], 1408), ('pid', ints[4], 1496),
                ('tgid', ints[4], 1500), ('cred', pointer, 1944), ('comm', array16, 1960)])
    b.aggregate('cred', 200, [('uid', u32, 4)])
    netns = b.aggregate('possible_net_t', 8, [('net', pointer, 0)])
    sk_common = b.aggregate('sock_common', 64, [('skc_net', netns, 48)])
    b.aggregate('sock', 800, [('__sk_common', sk_common, 0)])
    # sk 位于匿名 union 中；skb.cb 的名字在外层直接存在。
    union = b.aggregate('', 8, [('sk', pointer, 0), ('ip_defrag_offset', ints[4], 0)], 5)
    b.aggregate('sk_buff', 240, [('', union, 24), ('cb', array48, 40), ('len', u32, 112),
                ('transport_header', ints[2], 178), ('network_header', ints[2], 180),
                ('tail', u32, 200), ('head', pointer, 208), ('data', pointer, 216)])
    creds = b.aggregate('scm_creds', 12, [('uid', u32, 4)])
    b.aggregate('netlink_skb_parms', 40, [('creds', creds, 0)])
    b.aggregate('net', 1024, [('genl_sock', pointer, 280)])
    b.aggregate('genl_family', 112, [('hdrsize', u32, 0), ('name', array16, 4), ('version', u32, 20),
                ('maxattr', u32, 24), ('id', u32, 28), ('mcgrp_offset', u32, 32), ('n_mcgrps', ints[1], 39), ('mcgrps', pointer, 80)])
    b.aggregate('genl_multicast_group', 18, [('name', array16, 0)])
    proto = b.add('', 13, 0, b''.join(struct.pack('<II', b.name(n), t) for n, t in
                  [('proc', pointer), ('thread', pointer), ('buffer', pointer), ('failed_at', ints[8]), ('is_failure', ints[1])]), 5)
    b.add('binder_transaction_buffer_release', 12, proto)
    b.name('off_end_offset')
    ref = dict(binder_alloc_buffer_size=120, binder_alloc_buffer=64, binder_alloc_free_async_space=104, binder_alloc_pid=132,
               binder_node_async_todo=112, binder_node_cookie=96, binder_node_has_async_transaction=107, binder_node_lock=4,
               binder_node_ptr=88, binder_proc_alloc=424, binder_proc_context=576, binder_proc_inner_lock=584,
               binder_proc_is_dead=112, binder_proc_is_frozen=113, binder_proc_outer_lock=588, binder_proc_outstanding_txns=108,
               binder_stats_deleted_transaction=204, binder_transaction_buffer=112, binder_transaction_code=120,
               binder_transaction_flags=124, binder_transaction_from=40, binder_transaction_to_proc=72,
               task_struct_group_leader=1560, task_struct_jobctl=1408, task_struct_pid=1496, task_struct_tgid=1500,
               task_struct_cred=1944, task_struct_comm=1960, cred_uid=4, sock_sk_net=48,
               sk_buff_len=112, sk_buff_transport_header=178, sk_buff_network_header=180, sk_buff_tail=200,
               sk_buff_head=208, sk_buff_data=216, net_genl_sock=280, genl_family_id=28, genl_family_config=0,
               genl_family_mcgrps=80, genl_family_n_mcgrps=39, genl_family_n_mcgrps_size=1, genl_family_mcgrp_offset=32,
               binder_buffer_data=-1, binder_release_abi=6)
    return b.data(), ref


HOST = r'''
static unsigned char* blob;
struct btf { int unused; };
static struct btf object;
static int resolve_error;
static struct btf* host_get(void) { return &object; }
static const struct btf_type* host_type(const struct btf* btf, u32 id) {
  assert(btf == &object && id < ARRAY_SIZE(records));
  return id ? (const struct btf_type*)(blob + records[id]) : NULL;
}
static const char* host_name(const struct btf* btf, u32 off) {
  assert(btf == &object && off < string_length);
  return (char*)blob + string_start + off;
}
static int host_find(const struct btf* btf, const char* name, u8 kind) {
  for (u32 id = 1; id < ARRAY_SIZE(records); id++) {
    const struct btf_type* type = host_type(btf, id);
    if (((type->info >> 24) & 31) == kind && !strcmp(host_name(btf, type->name_off), name)) return id;
  }
  return -ENOENT;
}
static const struct btf_type* host_size(const struct btf* btf, const struct btf_type* type, u32* size) {
  if (resolve_error) return ERR_PTR(-EINVAL);
  const struct btf_type* array = NULL;
  u64 count = 1;
  for (u32 depth = 0; depth < 32 && type; depth++) {
    switch ((type->info >> 24) & 31) {
      case 1: case 4: case 5: case 6: case 16: case 19: *size = type->size; goto done;
      case 2: *size = 8; goto done;
      case 8: case 9: case 10: case 11: type = host_type(btf, type->size); break;
      case 3: {
        const u32* a = (const u32*)(type + 1);
        if (!array) array = type;
        count *= a[2]; if (count > UINT32_MAX) return ERR_PTR(-EINVAL);
        type = host_type(btf, a[0]); break;
      }
      default: return ERR_PTR(-EINVAL);
    }
  }
  return ERR_PTR(-EINVAL);
done:
  if (count * *size > UINT32_MAX) return ERR_PTR(-EINVAL);
  *size *= count;
  return array ? array : type;
}
static struct btf* host_bad_get(void) { return ERR_PTR(-EINVAL); }
static struct btf* host_empty_get(void) { return NULL; }
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--btf', type=Path)
    ap.add_argument('--reference', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    if args.btf:
        assert args.reference, '目标 BTF 需要单独提供参考字段'
        data, reference = args.btf.read_bytes(), json.loads(args.reference.read_text())
        if 'offsets' in reference:
            reference = reference['offsets']
    else:
        data, reference = synthetic()
    (args.output / 'input.btf').write_bytes(data)
    records, strings = index_btf(data)
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define dev_t kernel_dev_t
#define mode_t kernel_mode_t
#define off_t kernel_off_t
#include "re_kernel_host.h"
#undef dev_t
#undef mode_t
#undef off_t
#define kfunc_def(name) (*kf_##name)
#define kfunc(name) kf_##name
#define kfunc_lookup_name(name) ((void)0)
#define ERR_PTR(error) ((void*)(intptr_t)(error))
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define PTR_ERR(ptr) ((intptr_t)(ptr))
#define logkm(...) ((void)0)
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
'''
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].split('// instruction\n', 1)[0]
    inputs = [Path(__file__), root / 'kpm_utils.h']
    results = []
    for module, mode in [('re_kernel', False), ('re_kernel_x', True)]:
        production = (root / module / 're_btf.c').read_text()
        decl, functions = production.split('static int rekernel_btf_release_abi', 1)
        inputs += [root / module / 're_btf.c']
        header = root / module / 're_structs.h'
        # 结构体来自生产头文件；只注入原生 API 的宿主实现。
        (args.output / 're_kernel_host.h').write_text('#include <ktypes.h>\n' + header.read_text())
        table_path = root / module / 're_offsets.c'
        table_source = table_path.read_text()
        table = re.search(r'struct struct_offset\s*\{.*?\};', table_source, re.S)[0]
        fields = re.findall(r'int16_t (\w+);', table)
        if not mode:
            assert set(REK_BTF_FIELDS).issubset(fields)
            fields = REK_BTF_FIELDS
        checks = '\n'.join(f'  assert(struct_offset.{name} == {reference[name]});' for name in fields)
        if mode:
            define = '#define CONFIG_REKERNEL_X 1\n'
            checks += '\n  assert(struct_offset.binder_release_abi == ' + str(reference['binder_release_abi']) + ');'
        else:
            define = 'static bool binder_transaction_buffer_release_ver4, binder_transaction_buffer_release_ver5, binder_transaction_buffer_release_ver6;\n'
            abi = reference['binder_release_abi']
            checks += f'\n  assert(binder_transaction_buffer_release_ver4 == {int(abi == 4)});\n  assert(binder_transaction_buffer_release_ver5 == {int(abi >= 5)});\n  assert(binder_transaction_buffer_release_ver6 == {int(abi == 6)});'
        fixture = ('#define REKERNEL_TARGET_BTF 1\n' if args.btf else '') + code + define + table + '\nstatic struct struct_offset struct_offset;\n' + common + '\n' + decl
        fixture += 'static const u32 records[] = {' + ','.join(map(str, records)) + '};\n'
        fixture += f'static const u32 string_start = {strings}, string_length = {len(data) - strings};\n'
        fixture += HOST + 'static int rekernel_btf_release_abi' + functions
        fixture += '#define rekernel_btf_type(name, kind) kpm_btf_type(&rekernel_btf, name, kind)\n'
        fixture += r'''
int main(int argc, char** argv) {
  assert(argc == 2);
  FILE* f = fopen(argv[1], "rb"); assert(f);
  assert(!fseek(f, 0, SEEK_END)); long len = ftell(f); assert(len > 0); rewind(f);
  blob = malloc(len); assert(blob);
  assert(fread(blob, 1, len, f) == (size_t)len); assert(!fclose(f));
  kfunc(bpf_get_btf_vmlinux) = host_get;
  kfunc(btf_type_by_id) = host_type;
  kfunc(btf_find_by_name_kind) = host_find;
  kfunc(btf_name_by_offset) = host_name;
  kfunc(btf_resolve_size) = host_size;
  assert(calculate_btf_offsets() == 0);
''' + checks + r'''
  kfunc(bpf_get_btf_vmlinux) = NULL;
  assert(calculate_btf_offsets() == -ENODATA);
  kfunc(bpf_get_btf_vmlinux) = host_empty_get;
  assert(calculate_btf_offsets() == -ENODATA);
  kfunc(bpf_get_btf_vmlinux) = host_bad_get;
  assert(calculate_btf_offsets() == -EINVAL);
  kfunc(bpf_get_btf_vmlinux) = host_get;
  resolve_error = 1; assert(calculate_btf_offsets() == -EINVAL); resolve_error = 0;
  struct btf_type* alloc = (struct btf_type*)rekernel_btf_type("binder_alloc", 4);
  struct btf_member* members = (struct btf_member*)(alloc + 1);
  u32 required = 0;
  while (required < (alloc->info & 65535) && strcmp(host_name(&object, members[required].name_off), "buffer_size")) required++;
  assert(required < (alloc->info & 65535));
  members += required;
  struct btf_member saved = members[0];
  members[0].offset += 1; assert(calculate_btf_offsets() < 0); members[0] = saved;
  u32 info = alloc->info; alloc->info = info | 1U << 31;
  members[0].offset |= 1U << 24; assert(calculate_btf_offsets() < 0); members[0] = saved; alloc->info = info;
  u32 size = alloc->size; alloc->size = 1; assert(calculate_btf_offsets() < 0); alloc->size = size;
  struct btf_type* cb = (struct btf_type*)rekernel_btf_type("sk_buff", 4);
  struct btf_member* m = (struct btf_member*)(cb + 1);
  for (u32 i = 0; i < (cb->info & 65535); i++) {
    if (strcmp(host_name(&object, m[i].name_off), "cb")) continue;
    m[i].offset += 64; assert(calculate_btf_offsets() == -EINVAL); m[i].offset -= 64;
  }
  assert(calculate_btf_offsets() == 0);
  struct btf_type* func = (struct btf_type*)rekernel_btf_type("binder_transaction_buffer_release", 12);
  struct btf_type* proto = (struct btf_type*)host_type(&object, func->size);
  struct btf_param* params = (struct btf_param*)(proto + 1);
  assert((proto->info & 65535) == 5);
  u32 original_name = params[3].name_off;
  params[3].name_off = 0; assert(rekernel_btf_release_abi() == -EINVAL);
  params[3].name_off = original_name;
#ifndef REKERNEL_TARGET_BTF
  // 四种 ABI 的变异使用完整合成类型和字符串，目标 BTF 保持自身参数记录。
  u32 names[2] = {UINT32_MAX, UINT32_MAX};
  for (u32 off = 0; off < string_length; off++) {
    const char* text = host_name(&object, off);
    if (!strcmp(text, "off_end_offset")) names[0] = off;
    if (!strcmp(text, "failed_at")) names[1] = off;

  }
  assert(names[0] != UINT32_MAX && names[1] != UINT32_MAX);
  struct btf_param third = params[2], fourth = params[3];
  u32 proto_info = proto->info;
  params[3].name_off = names[0]; assert(rekernel_btf_release_abi() == 5);
  params[3].name_off = names[1]; assert(rekernel_btf_release_abi() == 6);
  params[3].name_off = 0; assert(rekernel_btf_release_abi() == -EINVAL);
  params[3].type = params[0].type; assert(rekernel_btf_release_abi() == -EINVAL);
  proto->info = (proto_info & ~65535U) | 3;
  params[2].type = params[0].type; assert(rekernel_btf_release_abi() == 3);
  params[2].type = fourth.type; assert(rekernel_btf_release_abi() == -EINVAL);
  proto->info = (proto_info & ~65535U) | 4;
  assert(rekernel_btf_release_abi() == 4);
  params[2].type = params[0].type; assert(rekernel_btf_release_abi() == -EINVAL);
  proto->info = (proto_info & ~65535U) | 6; assert(rekernel_btf_release_abi() == -EINVAL);
  proto->info = proto_info; params[2] = third; params[3] = fourth;
#endif
  assert(calculate_btf_offsets() == 0);
  free(blob);
  puts("BTF fields, nested/anonymous members, shared layouts, native error contracts: PASS");
}
'''
        source, binary = args.output / (module + '.c'), args.output / module
        source.write_text(fixture)
        command = ['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter',
                   '-Wno-macro-redefined', '-idirafter', str(root / 'KernelPatch/kernel/include'), '-I', str(args.output), '-I', str(root / module),
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g', str(source), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True)
        (args.output / (module + '-build.log')).write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stdout + build.stderr
        run = subprocess.run([str(binary.resolve()), str((args.output / 'input.btf').resolve())], capture_output=True, text=True)
        results.append({'module': module, 'binary_sha256': sha(binary), 'exit_code': run.returncode,
                        'stdout': run.stdout, 'stderr': run.stderr, 'reference': {name: reference[name] for name in fields}})
        print(module + ': ' + (run.stdout.strip() or run.stderr))
        inputs += [header, table_path]
        if run.returncode:
            break
    (args.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer host/offline BTF API emulation; no device conclusion',
        'input_sha256': sha(args.output / 'input.btf'), 'source_hashes': {str(p.relative_to(root)): sha(p) for p in inputs},
        'results': results}, indent=2) + '\n')
    assert len(results) == 2 and all(r['exit_code'] == 0 for r in results)


if __name__ == '__main__':
    main()
