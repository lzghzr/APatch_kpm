#!/usr/bin/env python3
"""用真实镜像窗口执行控制布局的严格推导、逐指令反例和保护页；仅Developer宿主自检。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
COUNTS = {
    'B2N-416G_boot.img': (18, 16, 26, 10, 11),
    'boot_los23.2.img': (18, 17, 22, 7, 11),
    'kernel_mi6-4.4': (19, 16, 26, 10, 11),
    'kernel_mi8-4.9': (23, 17, 24, 10, 10),
    'kernel_mi9-4.14': (20, 16, 25, 7, 11),
    'kernel_mi10-4.19': (23, 16, 25, 7, 11),
    'kernel_mi11-5.4': (21, 17, 30, 7, 12),
    'kernel_android12-5.10': (21, 20, 24, 10, 13),
}
NAMES = ('register_key_type', 'unregister_key_type', 'key_instantiate_and_link', '__mutex_init', 'user_preparse')


def fixture(row, probe):
    spec = importlib.util.spec_from_file_location('matrix', ROOT / 'Developer/tools/verify_nomount_key_type_matrix.py')
    matrix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(matrix)
    lookup = probe[probe.rindex('static unsigned long kallsyms_lookup_name_by_suffix(const char* name){'):]
    lookup, main = lookup.split('int main(void){', 1)
    lookup = lookup.replace('{\n', '{\nif(override_name&&!strcmp(name,override_name))return override_value;\n', 1)
    allocation = re.search(r'arena=calloc\(1,(\d+)U\);assert\(arena\);', main)
    assert allocation
    setup = main[allocation.end():main.index('struct_offset.key_type_size=')]
    c = matrix.common_source() + '''#include <sys/mman.h>
#include <unistd.h>
static const char* override_name;
static uintptr_t override_value;
''' + lookup
    c += 'static void reset(void){override_name=NULL;override_value=0;memset((void*)&struct_offset,255,sizeof(struct_offset));\n' + setup + '}\n'
    c += '''static int strict_layout(void){
int rc=calculate_function_control_offsets();if(rc)return rc;
rc=calculate_function_key_callbacks();if(rc)return rc;
return calculate_function_key_type_size();}
'''
    c += 'int main(void){arena=calloc(1,' + allocation[1] + 'U);assert(arena);\n'
    expected = row['probe']['key_type_size']
    c += f'reset();assert(!strict_layout()&&struct_offset.key_type_size=={expected});\n'
    windows = row['probe']['windows']
    total = 0
    for name, count in zip(NAMES, COUNTS[row['image']]):
        at = windows[name]['offset']
        for mutant in (0xd503201f, 0xc8137c83):
            c += f'''for(unsigned i=0;i<{count};i++){{reset();((u32*)(arena+{at}U))[i]={mutant}U;
int rc=strict_layout();if(rc>=0||struct_offset.key_type_size!=-1){{fprintf(stderr,"accepted {name} %u {mutant} rc=%d\\n",i,rc);return 2;}}}}\n'''
            total += count
    # 错误外部身份、缺失锚点均不得宣称精确尺寸。
    for name in ('strcmp', 'down_write', 'memset', 'register_key_type', 'unregister_key_type', 'key_instantiate_and_link'):
        # memset并非每个目标的依赖；只对实际可见调用的目标强制拒绝。
        if name == 'memset' and row['image'] not in ('kernel_mi9-4.14', 'kernel_mi10-4.19', 'kernel_mi11-5.4'):
            continue
        c += f'reset();override_value=kallsyms_lookup_name("{name}")+4;override_name="{name}";'
        if name in ('register_key_type', 'unregister_key_type', 'key_instantiate_and_link'):
            c += 'override_value=0;'
        c += 'assert(strict_layout()<0&&struct_offset.key_type_size==-1);\n'
    # 已识别class清零的起点与注销link冲突，必须经正式准备入口报错。
    if row['image'] in ('kernel_mi9-4.14', 'kernel_mi10-4.19', 'kernel_mi11-5.4'):
        c += f'''reset();int lock,clear,offset;
u32* reg=(void*)kallsyms_lookup_name("register_key_type");
assert(nm_find_key_registration(reg,kallsyms_lookup_name("strcmp"),&lock,&clear,&offset)=={expected}-16);
reg[clear-3]^=1U<<10;nm_owned_operation_fallback=true;
assert(nm_prepare_control_layout()==-EINVAL&&struct_offset.key_type_size==-1);
reset();assert(!calculate_function_control_offsets()&&!calculate_function_key_callbacks());
reg[clear]^=1U;
assert(calculate_function_key_type_size()==-EINVAL&&struct_offset.key_type_size==-1);
'''
    # 新形态中的key->type必须是正偏移；后置索引亦核对位宽和更新模式。
    type_loads = {'kernel_mi8-4.9': (8, False), 'kernel_mi9-4.14': (21, True),
                  'kernel_mi10-4.19': (21, True), 'kernel_mi11-5.4': (25, False),
                  'kernel_android12-5.10': (19, False)}
    if row['image'] in type_loads:
        index, unscaled = type_loads[row['image']]
        mask = '0x1ff000U' if unscaled else '0x3ffc00U'
        c += f'reset();((u32*)kallsyms_lookup_name("key_instantiate_and_link"))[{index}]&=~{mask};assert(strict_layout()<0);\n'
    c += '''long page=sysconf(_SC_PAGESIZE);assert(page>512);
unsigned char* pages=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(pages!=MAP_FAILED&&!mprotect(pages+page,page,PROT_NONE));
'''
    # 将原生窗口紧贴不可读页；相对调用的预期目标随代码位置平移，原字节保持不变。
    for name, count in zip(NAMES, COUNTS[row['image']]):
        at = windows[name]['offset']
        c += f'''{{reset();const unsigned count={count};u32* edge=(void*)(pages+page-count*4);
memcpy(edge,arena+{at}U,count*4);uintptr_t delta=(uintptr_t)edge-(uintptr_t)(arena+{at}U);(void)delta;
'''
        if name == 'register_key_type':
            c += f'int lock,clear,offset;assert(nm_find_key_registration(edge,kallsyms_lookup_name("strcmp")+delta,&lock,&clear,&offset)=={expected}-16);\n'
        elif name == 'unregister_key_type':
            c += f'assert(nm_find_key_type_link(edge,kallsyms_lookup_name("down_write")+delta,kallsyms_lookup_name("__list_del_entry_valid")+delta)=={expected}-16);\n'
        elif name == 'key_instantiate_and_link':
            c += f'override_value=kallsyms_lookup_name("memset")+delta;override_name="memset";assert(nm_find_key_callback_slot(edge)=={row["probe"]["callback_offset"]});\n'
        elif name == '__mutex_init':
            c += f'assert(nm_find_mutex_size(edge)=={row["probe"]["mutex_size_or_error"]});\n'
        else:
            c += 'assert(nm_find_key_preparse_data(edge)==40);\n'
        c += '}\n'
    c += '''reset();memcpy(pages+page-NM_KEY_TYPE_PROBE_SIZE,(void*)kallsyms_lookup_name("key_type_user"),NM_KEY_TYPE_PROBE_SIZE);
override_name="key_type_user";override_value=(uintptr_t)(pages+page-NM_KEY_TYPE_PROBE_SIZE);
assert(!calculate_function_key_callbacks());
// BTI C + 单B恰好8字节；仅剩4字节时BTI不得扩读，也不递归解析第二个B。
u32* jt=(void*)(pages+page-8);jt[0]=0xd503245f;jt[1]=0x14000004;
uintptr_t start=(uintptr_t)pages,end=(uintptr_t)(pages+page),target=(uintptr_t)&jt[1]+16;
assert(nm_code_matches((uintptr_t)jt,target,start,end));
assert(!nm_code_matches((uintptr_t)&jt[1],target+4,start,end));
jt[1]=0xd503245f;assert(!nm_code_matches((uintptr_t)&jt[1],target,start,end));
jt[0]=0xd503201f;assert(!nm_code_matches((uintptr_t)jt,target,start,end));
jt[0]=0x14000001;jt[1]=0x14000004;assert(!nm_code_matches((uintptr_t)jt,target,start,end));
assert(!munmap(pages,page*2));free(arena);
'''
    c += f'puts("PASS: {row["image"]}: {total} instruction mutants, five guarded windows, 56-byte prefix and BTI bounds");return 0;}}\n'
    return c, total


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--matrix', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    receipts = []
    for row in json.loads((a.matrix / 'matrix.json').read_text())['targets']:
        if row['route'] != 'function':
            continue
        out = a.output / row['image']
        out.mkdir()
        c, total = fixture(row, (a.matrix / row['image'] / 'probe.c').read_text())
        (out / 'test.c').write_text(c)
        build = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-g',
                                str(out / 'test.c'), '-o', str(out / 'test')], capture_output=True, text=True)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        build.check_returncode()
        result = subprocess.run([str(out / 'test')], capture_output=True, text=True)
        (out / 'run.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            print(result.stdout + result.stderr, flush=True)
        result.check_returncode()
        print(result.stdout.strip(), flush=True)
        receipts.append({'image': row['image'], 'kernel_sha256': row['kernel_sha256'], 'instruction_mutants': total,
                         'guarded_window_counts': dict(zip(NAMES, COUNTS[row['image']])), 'result': result.stdout.strip()})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer host fixtures; no native calls', 'targets': receipts}, indent=2) + '\n')


if __name__ == '__main__':
    main()
