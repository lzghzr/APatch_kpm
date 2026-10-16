#!/usr/bin/env python3
"""Developer：真实目标文件字段／完整表尺寸入口及失败边界；不执行原生函数。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def digest(data):
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
    image = inspect_target.unpack_target(args.image).data
    reference = json.loads(args.reference.read_text())
    assert reference['image_sha256'] == digest(args.image.read_bytes())
    assert reference['kernel_sha256'] == digest(image)
    offsets = reference['offsets']
    symbols = {n: o for o, kind, n in json.loads(args.symbols.read_text())}
    tty_names = [n for n in symbols if n == 'tty_fops' or n.startswith('tty_fops.')]
    assert len(tty_names) == 1
    start = symbols['tty_default_fops']
    windows = {'tty_default_fops': 7, 'simple_open': 4, 'noop_llseek': 2,
               'nonseekable_open': 5, 'file_ns_capable': 12}
    entries = {}
    for name, count in windows.items():
        at = symbols[name]
        raw = image[at:at + count * 4]
        assert at % 4 == 0 and len(raw) == count * 4
        entries[name] = {'offset': at, 'count': count, 'words': list(struct.unpack('<' + 'I' * count, raw)),
                         'sha256': digest(raw)}
    utils = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    source = (root / 'nomount/nm_offsets.c').read_text()
    prefix = source.split('// int保留', 1)[0].replace('__attribute__((section(".data.re_offsets"), used))', '')
    functions = source.split('#include "nm_btf.c"\n', 1)[1].split('static int nm_scalar_copy', 1)[0]
    validation = source.split('static int nm_validate_file_offsets', 1)[1].split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
    validation = 'static int nm_validate_file_offsets' + validation
    route = source.split('static int nm_prepare_file_layout(void)', 1)[1].split('static int nm_prepare_inode_layout', 1)[0]
    route = 'static int nm_prepare_file_layout(void)' + route
    c = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
static unsigned int queries;
static int mode, missing;
static uintptr_t lookup(const char* name);
static unsigned long kallsyms_lookup_name(const char* name) { return lookup(name); }
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) { return lookup(name); }
static int calculate_btf_file_offsets(bool* unavailable) {
  *unavailable = mode == 0;
  return mode == 1 ? -EINVAL : -ENODATA;
}
static unsigned char code[8192] __attribute__((aligned(4096)));
'''
    for name, entry in entries.items():
        c += f'static const u32 {name}_original[] = {{' + ','.join(map(str, entry['words'])) + '};\n'
        if name != 'tty_default_fops':
            c += f'static u32 {name}_entry[{entry["count"]}];\n'
    c += f'static u32* defaults = (void*)(code + {start % 4096});\n'
    c += f'static uintptr_t image_base(void) {{ return (uintptr_t)defaults - {start}U; }}\n'
    for name in ['memcpy', 'memset', tty_names[0]]:
        c += f'static uintptr_t symbol_{"table" if name == tty_names[0] else name}(void) {{ return image_base() + {symbols[name]}U; }}\n'
    c += '''static void reset(void) {
  queries = 0; missing = 0;
  memcpy(defaults,tty_default_fops_original,sizeof(tty_default_fops_original));
'''
    c += ''.join(f'  memcpy({name}_entry,{name}_original,sizeof({name}_entry));\n' for name in entries if name != 'tty_default_fops')
    c += '}\nstatic uintptr_t lookup(const char* name) { queries++;\n'
    c += 'if (!strcmp(name,"tty_default_fops")) return missing ? 0 : (uintptr_t)defaults;\n'
    c += ''.join(f'if (!strcmp(name,"{name}")) return (uintptr_t){name}_entry;\n' for name in entries if name != 'tty_default_fops')
    c += 'if (!strcmp(name,"memcpy")) return symbol_memcpy();\nif (!strcmp(name,"memset")) return symbol_memset();\nif (!strcmp(name,"tty_fops")) return symbol_table();\nreturn 0;}\n'
    c += utils + (root / 'nomount/nm_structs.h').read_text() + prefix + functions + validation + route
    c += 'static void seed(void) {\n' + ''.join(f'struct_offset.{field}={value};\n' for field, value in offsets.items()) + '}\n'
    c += '''static int size(void) { return nm_find_file_operations_size(defaults,symbol_memcpy(),symbol_memset(),symbol_table()); }
int main(void) {
  reset(); seed();
'''
    c += f'  assert(size()=={offsets["file_ops_size"]});\n'
    c += '''  struct_offset.file_ops_size=-1;
  assert(!calculate_file_entry_offsets());
'''
    fields = ['inode_private', 'file_private', 'file_position', 'file_flags', 'file_cred', 'file_ops_size']
    c += ''.join(f'  assert(struct_offset.{field}=={offsets[field]});\n' for field in fields)
    c += '''  assert(!nm_validate_file_offsets((const void*)&struct_offset));
  reset(); mode=0; seed(); struct_offset.file_ops_size=-1;
  assert(!nm_prepare_file_layout() && queries>0);
  reset(); mode=0; seed(); struct_offset.fop_open=-1;
  assert(nm_prepare_file_layout()==-EINVAL); // 回调槽尚未取得仍拒绝该阶段。
  reset(); mode=1; seed();
  assert(nm_prepare_file_layout()==-EINVAL && !queries);
  mode=2; assert(nm_prepare_file_layout()==-ENODATA && !queries); // API 错误不当成缺 BTF。
  reset(); seed(); missing=1;
  assert(calculate_file_entry_offsets()==-ENOENT);
  reset(); defaults[6]^=1;
  assert(size()==-EOPNOTSUPP); // BL 指向其他目标。
  reset(); defaults[0]=0xAA0203E0;
  assert(size()==-EOPNOTSUPP); // x0 在调用前被改写。
  reset(); defaults[0]=0x34000002;
  assert(size()==-EOPNOTSUPP); // 条件分支不能线性穿越。
  reset(); defaults[6]=0xD63F0200;
  assert(size()==-EOPNOTSUPP); // 不接受未解析的间接调用。
'''
    # 修改 MOVZ 的立即数；不修改生产算法或旧 Oracle。
    length_index = 5 if entries['tty_default_fops']['words'][5] & 31 == 2 else 2
    c += f'  const unsigned int length_index={length_index};\n'
    c += '''  const unsigned int bad_sizes[]={0,8,49,4097};
  for(unsigned int i=0;i<sizeof(bad_sizes)/sizeof(bad_sizes[0]);i++) {
    reset(); defaults[length_index]=0x52800002U|(bad_sizes[i]<<5);
    assert(size()==-EINVAL);
  }
  reset(); defaults[length_index]=0x52800003U|(216U<<5);
  assert(size()==-EOPNOTSUPP); // 长度写到其他寄存器。
  reset(); defaults[length_index]^=1U<<21;
  assert(size()==-EOPNOTSUPP); // MOVZ 非零 hw 不接受为未移位长度。
  reset(); defaults[6]=0x910003FD;
  assert(size()==-ENOENT); // 7 条之外的证据不纳入。
'''
    if length_index == 5:
        c += '''  reset(); assert(nm_find_file_operations_size(defaults,symbol_memcpy(),symbol_memset(),0)==-EOPNOTSUPP);
  defaults[4]^=1U<<10; assert(size()==-EOPNOTSUPP); // memcpy 源表不匹配。
'''
    else:
        c += '''  reset(); defaults[1]|=1U<<5; assert(size()==-EOPNOTSUPP); // memset 填充值非零。
  reset(); defaults[3]=0xAA0303E2; assert(size()==-EOPNOTSUPP); // 设置长度后覆写 x2。
  reset(); defaults[3]=0xC8027C83; assert(size()==-EOPNOTSUPP); // STXR 的状态寄存器在 bits20:16。
  reset(); defaults[3]=0xC8A27C83; assert(size()==-EOPNOTSUPP); // CAS 隐式覆盖 x2。
'''
    c += '''  reset(); simple_open_entry[1]^=1U<<5;
  struct struct_offset next=struct_offset;
  assert(nm_find_private_fields(simple_open_entry,&next)<0);
  reset(); nonseekable_open_entry[1]=0xAA0203E1;
  assert(nm_find_file_flags(nonseekable_open_entry)<0);
  reset(); nonseekable_open_entry[1]=0x54000080;
  assert(nm_find_file_flags(nonseekable_open_entry)<0); // 不跨条件分支找掩码写回。
  reset(); file_ns_capable_entry[0]=0x94000000;
  assert(nm_find_file_cred(file_ns_capable_entry)<0);
  assert(inst_is_subs_imm(0x71001C3F) && inst_get_subs_imm_sf(0x71001C3F)==0);
  assert(inst_get_subs_imm_rn(0x71001C3F)==1 && inst_get_subs_imm_rd(0x71001C3F)==31);
  assert(inst_get_subs_imm_imm(0x71001C3F)==7);
  assert(!inst_is_subs_imm(0x11001C3F) && inst_get_subs_imm_rn(0x11001C3F)==-1);
  assert(inst_get_b_cond_cond(0x54000109)==9 && inst_get_b_cond_imm19(0x54000109)==8);
  assert(!inst_is_b_cond(0x54000119) && inst_get_b_cond_cond(0x54000119)==-1);
'''
    if length_index == 2:
        c += '''  reset(); file_ns_capable_entry[3]^=1; assert(nm_find_file_cred(file_ns_capable_entry)<0);
  reset(); file_ns_capable_entry[3]=0x54000129; assert(nm_find_file_cred(file_ns_capable_entry)<0);
  reset(); file_ns_capable_entry[2]=0x91000000; assert(nm_find_file_cred(file_ns_capable_entry)<0);
  reset(); file_ns_capable_entry[11]^=1U<<5; assert(nm_find_file_cred(file_ns_capable_entry)<0);
'''
    c += '  puts("PASS: real file fields and sizeof anchor; register, call, window and fallback boundaries");\n}\n'
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output / 'file-layout.c'
    path.write_text(c)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
               '-g', str(path), '-o', str(args.output / 'file-layout')]
    built = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    result = subprocess.run([str(args.output / 'file-layout')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    files = ['nomount/nm_offsets.c', 'nomount/nm_structs.h', 'kpm_utils.h', 'nomount/tools/test_function_file_layout.py']
    receipt = {'scope': 'Developer production function extraction on real target words; query routing uses API fixture; no native calls or complete initialization proof',
               'image_sha256': reference['image_sha256'], 'kernel_sha256': reference['kernel_sha256'],
               'reference_sha256': digest(args.reference.read_bytes()), 'symbols_sha256': digest(args.symbols.read_bytes()),
               'sources': {name: digest((root / name).read_bytes()) for name in files},
               'entries': entries, 'derived_fields': {name: offsets[name] for name in fields},
               'generated_fixture_sha256': digest(c.encode()), 'result': result.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(result.stdout.strip())


if __name__ == '__main__':
    main()
