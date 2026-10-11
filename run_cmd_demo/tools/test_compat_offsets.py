#!/usr/bin/env python3
"""Developer 离线自检：在目标镜像副本上执行生产偏移计算；BTF API 由宿主夹具模拟。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def btf_index(data):
    magic, version, flags, header, start, length, strings, string_length = struct.unpack_from('<HBBIIIII', data)
    if magic != 0xeb9f or version != 1 or flags or header != 24:
        raise ValueError('不支持的 BTF header')
    if header + strings + string_length > len(data):
        raise ValueError('BTF 字符串段越界')
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
    if at != end or end > len(data):
        raise ValueError('BTF 类型段越界')
    return records, header + strings


HOST_BTF = r'''
static unsigned char* btf_data;
static const struct btf_type* offline_type(const struct btf* btf, u32 id) {
  assert(btf == &test_btf && id < sizeof(type_offsets) / sizeof(type_offsets[0]));
  return id ? (const struct btf_type*)(btf_data + type_offsets[id]) : NULL;
}
static const char* offline_name(const struct btf* btf, u32 offset) {
  assert(btf == &test_btf);
  return (const char*)btf_data + string_start + offset;
}
static int offline_find(const struct btf* btf, const char* name, unsigned char kind) {
  for (u32 id = 1; id < sizeof(type_offsets) / sizeof(type_offsets[0]); id++) {
    const struct btf_type* type = offline_type(btf, id);
    if (((type->info >> 24) & 31) == kind && !strcmp(offline_name(btf, type->name_off), name)) return id;
  }
  return -ENOENT;
}
// 模拟原生 btf_resolve_size 的按链查询；夹具不建立 resolved_ids/resolved_sizes。
static const struct btf_type* offline_size(const struct btf* btf, const struct btf_type* type, u32* size) {
  for (unsigned int depth = 0; depth < 32 && type; depth++) {
    switch ((type->info >> 24) & 31) {
      case 1: case 4: case 5: case 6: case 16: case 19: *size = type->size; return type;
      case 2: *size = 8; return type;
      case 8: case 9: case 10: case 11: case 18: type = offline_type(btf, type->size); break;
      default: return ERR_PTR(-EINVAL);
    }
  }
  return ERR_PTR(-EINVAL);
}
static void* read_bytes(const char* path, size_t alignment) {
  FILE* f = fopen(path, "rb"); assert(f);
  assert(!fseek(f, 0, SEEK_END)); long size = ftell(f); assert(size > 0); rewind(f);
  void* data; assert(posix_memalign(&data, alignment, size) == 0);
  assert(fread(data, 1, size, f) == (size_t)size); assert(!fclose(f)); return data;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True, help='已解包的 Image')
    parser.add_argument('--symbols', type=Path, required=True, help='[[镜像偏移,类型,名称],...] 的符号 JSON')
    parser.add_argument('--btf', type=Path, help='可选，目标原始 BTF blob')
    parser.add_argument('--reference', type=Path, required=True, help='另行核对的字段参考 JSON')
    parser.add_argument('--output', type=Path, required=True, help='新的空输出目录')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    image = args.image.read_bytes()
    symbols = json.loads(args.symbols.read_text())
    reference = json.loads(args.reference.read_text())
    assert sha(args.image) == reference['image_sha256']
    selected = {}
    for offset, _, name in symbols:
        # 对照 KP 的名称匹配，函数体优先；命中的实际名称保存在 receipt。
        base = re.split(r'[.$]', name, maxsplit=1)[0]
        if base not in selected or name == base or selected[base]['name'].endswith('.cfi_jt'):
            selected[base] = {'offset': offset, 'name': name}
    names = ['call_usermodehelper_exec', 'selinux_cred_getsecid', 'selinux_task_getsecid',
             '__init_kthread_worker', 'kthread_create_worker', 'selinux_blob_sizes']
    required = ['call_usermodehelper_setup', 'call_usermodehelper_exec', 'prepare_kernel_cred', 'abort_creds',
                'security_transfer_creds', 'security_secctx_to_secid', 'override_creds', 'revert_creds',
                'init_task', 'filp_open', 'replace_fd', 'filp_close']
    assert all(name in selected for name in required)
    if 'kthread_create_worker' in selected:
        assert 'kthread_queue_work' in selected
    else:
        assert all(name in selected for name in ['__init_kthread_worker', 'queue_kthread_work', 'kthread_worker_fn',
                                                 'kthread_create_on_node', 'wake_up_process', '__kmalloc', 'kfree'])
        assert '__lockdep_no_validate__' in selected or 'lockdep_init_map' not in selected
    assert 'selinux_cred_getsecid' in selected or 'selinux_task_getsecid' in selected
    for name in names:
        if name in selected and name != 'selinux_blob_sizes':
            at = selected[name]['offset']
            assert 0 <= at < len(image) - 128
    code = (module / 'run_cmd.c').read_text().replace('#include "rc_offsets.c"', (module / 'rc_offsets.c').read_text())
    code = '#define KPM_INFO(...)\n' + re.sub(r'^#include .*\n', '', code, flags=re.M)
    # 宿主使用 Mach-O，不携带 KPM 的 ELF 数据段属性。
    code = code.replace('__attribute__((section(".data.re_offsets"), used))', '')
    utilities = 'typedef uint8_t u8;\ntypedef uint64_t u64;\n' + (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    fixture = (module / 'tools/test_run_cmd.c').read_text()
    code = re.sub(r'^#include .*\n', '', (module / 'run_cmd.h').read_text(), flags=re.M) + '\n' + utilities + '\n' + code
    fixture = fixture.replace('/* PRODUCTION_FUNCTIONS */', code)
    fixture = fixture[:fixture.index('int main(void) {')]
    records, strings = btf_index(args.btf.read_bytes()) if args.btf else ([0], 0)
    fixture += 'static const u32 type_offsets[] = {' + ','.join(map(str, records)) + '};\n'
    fixture += f'static const u32 string_start = {strings};\n' + HOST_BTF
    bindings = ''
    for name in names:
        if name == 'selinux_blob_sizes':
            if name in selected:
                bindings += f'  kvar({name}) = (int*)((char*)map + {selected[name]["offset"]});\n'
                bindings += f'  *kvar({name}) = {reference["runtime_blob"]};\n'
            else:
                bindings += f'  kvar({name}) = NULL;\n'
        else:
            value = f'(char*)map + {selected[name]["offset"]}' if name in selected else 'NULL'
            bindings += f'  kfunc({name}) = (typeof(kfunc({name})))({value});\n'
    native_btf = ''
    if args.btf:
        assert all(name in selected for name in ['bpf_get_btf_vmlinux', 'btf_find_by_name_kind', 'btf_type_by_id',
                                                 'btf_name_by_offset', 'btf_resolve_size'])
        native_btf = f'''  btf_data = read_bytes({json.dumps(str(args.btf.resolve()))}, 8);
  cmd_btf = &test_btf;
  kfunc(btf_find_by_name_kind) = offline_find;
  kfunc(btf_type_by_id) = offline_type;
  kfunc(btf_name_by_offset) = offline_name;
  kfunc(btf_resolve_size) = offline_size;
  assert(calculate_offsets() == 0);
  assert(subprocess_info_path_offset == {reference['path']});
  assert(cred_security_offset == {reference['security']} && cred_sid_offset == {reference['sid']});
  puts("BTF fields matched reference");
  cmd_btf = NULL;
  subprocess_info_path_offset = cred_security_offset = cred_sid_offset = legacy_worker_size = -1;
  free(btf_data);
'''
    fixture += f'''int main(void) {{
  void* map = read_bytes({json.dumps(str(args.image.resolve()))}, 0x1000);
  cred_offset.security_offset = -1;
  task_struct_offset.real_cred_offset = {reference.get('real_cred', -1)};
  task_struct_offset.cred_offset = {reference.get('cred', -1)};
{bindings}{native_btf}
  assert(calculate_offsets() == 0);
  assert(subprocess_info_path_offset == {reference['path']});
  assert(cred_security_offset == {reference['security']} && cred_sid_offset == {reference['sid']});
  assert(legacy_worker_size == {reference.get('worker_size', -1)});
  printf("instruction fields: path=0x%x security=0x%x sid=0x%x worker_size=%d\\n",
         subprocess_info_path_offset, cred_security_offset, cred_sid_offset, legacy_worker_size);
  free(map);
  return 0;
}}
'''
    source = args.output / 'probe.c'
    source.write_text(fixture)
    binary = args.output / 'probe'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(source), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer offline/host selfcheck; native BTF API emulation; not kernel execution proof',
        'image_sha256': sha(args.image), 'symbols_sha256': sha(args.symbols),
        'btf_sha256': sha(args.btf) if args.btf else None,
        'reference': reference, 'selected': {name: selected.get(name) for name in names},
        'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
        'source_hashes': {str(p.relative_to(root)): sha(p) for p in
                          [module / 'run_cmd.c', module / 'rc_offsets.c', module / 'run_cmd.h', root / 'kpm_utils.h',
                           module / 'tools/test_run_cmd.c', Path(__file__)]}}, indent=2) + '\n')
    print(result.stdout, end='')
    if result.returncode:
        raise RuntimeError(result.stderr or f'offset probe failed: {result.returncode}')


if __name__ == '__main__':
    main()
