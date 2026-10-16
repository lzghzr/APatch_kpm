#!/usr/bin/env python3
"""Developer：为 B2N 追加绝对链接符号与重定位符号边界用例，完整保留父夹具。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    symbols = {name: (at, kind) for at, kind, name in json.loads(args.symbols.read_text())}
    assert symbols['_etext'][1] == 'A' and symbols['__start_rodata'][1] != 'A'
    assert symbols['_etext'][0] == symbols['__start_rodata'][0]
    c = args.fixture.read_text()
    assert c.count('int main(void){') == 1
    c = c.replace('int main(void){', 'static int parent_main(void){', 1)
    c = c.replace('static unsigned int queries;', 'static int bounds_case;\nstatic unsigned int queries;', 1)
    needle = 'static unsigned long kallsyms_lookup_name(const char* name) { queries++;'
    assert c.count(needle) == 1
    cases = '''if(real_symbols&&bounds_case){
if(!strcmp(name,"_etext"))return bounds_case==1?0xffffff8009000000ULL:(uintptr_t)(arena-4096);
if(!strcmp(name,"__start_rodata"))return bounds_case==3?0:bounds_case==4?(uintptr_t)(arena-4096):bounds_case==5?(uintptr_t)(arena+0x10000000U):RODATA;
}\n'''.replace('RODATA', f'(uintptr_t)(arena+{symbols["__start_rodata"][0]}U)')
    # 数值只用于模拟链接符号不重定位；生产代码不使用这个常量。
    cases = cases.replace('(uintptr_t)(arena-4096)', '(uintptr_t)arena-4096U')
    c = c.replace(needle, needle + cases, 1)
    allocation = re.search(r'arena=aligned_alloc\(4096,\d+U\);assert\(arena\);memset\(arena,0,\d+U\);reset\(\);', c)
    assert allocation
    c += 'int main(void){assert(!parent_main());' + allocation[0] + '\n'
    c += '''for(bounds_case=1;bounds_case<=2;bounds_case++){
storage_base();hide_local_table=true;assert(!calculate_function_inode_offsets());
assert(struct_offset.inode_file_ops==328&&struct_offset.inode_data==344&&struct_offset.inode_data_size==152);
}
for(bounds_case=3;bounds_case<=5;bounds_case++){
storage_base();hide_local_table=true;assert(calculate_function_inode_offsets()==-ENOENT);
}
free(arena);puts("PASS: absolute link address and below-start end use relocated rodata bound; missing/reversed/outside bounds rejected");return 0;}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output / 'bounds.c'
    path.write_text(c)
    cmd = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
           '-g', str(path), '-o', str(args.output / 'bounds')]
    r = subprocess.run(cmd, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    r = subprocess.run([str(args.output / 'bounds')], capture_output=True, text=True)
    (args.output / 'run.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    receipt = {'scope': 'Developer host symbol relocation model; no native calls or device result',
               'parent_fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
               'symbols_sha256': hashlib.sha256(args.symbols.read_bytes()).hexdigest(),
               'etext': symbols['_etext'], 'rodata': symbols['__start_rodata'], 'output': r.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(r.stdout.strip())


if __name__ == '__main__':
    main()
