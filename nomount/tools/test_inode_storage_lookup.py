#!/usr/bin/env python3
"""Developer：以实际局部符号名验证inode存储推导；原准备用例先单独执行。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('image', 'symbols', 'reference', 'fixture', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'nomount/tools'))
    import inspect_target
    image = inspect_target.unpack_target(args.image).data
    symbols = {name: at for at, kind, name in json.loads(args.symbols.read_text())}
    reference = json.loads(args.reference.read_text())
    assert hashlib.sha256(image).hexdigest() == reference['kernel_sha256']
    offsets = reference['offsets']
    names = [n for n in symbols if n == 'inode_init_always.no_open_fops' or n.startswith('no_open_fops.')]
    assert len(names) == 1
    local_name = names[0]
    table_at = symbols[local_name]
    llseek = [n for n in symbols if n.startswith('block_llseek.') and n.endswith('.cfi_jt')]
    base = struct.unpack_from('<Q', image, symbols['def_blk_fops'] + 8)[0] - symbols[llseek[0] if llseek else 'block_llseek']
    table = struct.unpack_from('<' + 'Q' * (offsets['file_ops_size'] // 8), image, table_at)
    current = (root / 'nomount/nm_offsets.c').read_text()
    c = args.fixture.read_text().split('int main(void) {', 1)[0]
    # 要求父夹具已由当前源码生成，防止旧实现意外进入本轮自检。
    start = current.index('struct nm_initial_fops_probe {')
    end = current.index('static bool nm_move(', start)
    assert current[start:end] in c
    c = c.replace('static unsigned int queries;', 'static bool real_symbols, hide_local_table, end_hidden;\nstatic unsigned int queries;', 1)
    needle = 'static unsigned long kallsyms_lookup_name(const char* name) { queries++;'
    lookup = 'if(real_symbols){if(missing&&!strcmp(missing,name))return 0;\n'
    for name in ['inode_init_always.no_open_fops', 'no_open_fops']:
        result = f'(uintptr_t)(arena+{symbols[name]}U)' if name in symbols else '0'
        lookup += f'if(!strcmp(name,"{name}"))return hide_local_table?0:{result};\n'
    for name in ['no_open', '_end', '__end_rodata']:
        result = f'(uintptr_t)(arena+{symbols[name]}U)' if name in symbols else '0'
        lookup += f'if(!strcmp(name,"{name}"))return {result};\n'
    lookup = lookup.replace('if(!strcmp(name,"__end_rodata"))return ', 'if(!strcmp(name,"__end_rodata"))return end_hidden?0:')
    lookup += '}\n'
    assert c.count(needle) == 1
    c = c.replace(needle, needle + lookup, 1)
    setup = 'static void storage_base(void){real_symbols=false;hide_local_table=false;tail_base();\n'
    for i, value in enumerate(table):
        at = value - base
        expression = f'{value}ULL'
        if symbols['_stext'] <= at <= symbols['_etext'] - 4:
            expression = f'(uintptr_t)(arena+{at}U)'
            word = struct.unpack_from('<I', image, at)[0]
            setup += f'*(u32*)(arena+{at}U)={word}U;\n'
        setup += f'((uintptr_t*)(arena+{table_at}U))[{i}]={expression};\n'
    setup += 'real_symbols=true;}\n'
    c += setup
    new_cases = 'int main(void){\n'
    # 父夹具的arena大小由已选目标数据符号算出；直接复用其常量。
    original_main = args.fixture.read_text().split('int main(void) {', 1)[1]
    arena_line = original_main.splitlines()[1]
    assert arena_line.startswith('arena=aligned_alloc(')
    new_cases += arena_line + '\n'
    new_cases += 'storage_base();assert(!calculate_function_inode_offsets());\n'
    for name in ['inode_file_ops', 'inode_data', 'inode_data_size', 'inode_blocks']:
        new_cases += f'assert(struct_offset.{name}=={offsets[name]});\n'
    new_cases += '''hide_local_table=true;assert(!calculate_function_inode_offsets());
assert(!nm_prepare_operation_sizes());assert(!nm_prepare_inode_layout());assert(!nm_prepare_directory_layout());
assert(!nm_prepare_control_layout());assert(!nm_prepare_permission_abi());
assert(!nm_prepare_virtual_directory_abi()&&!nm_prepare_topology_abi()&&!nm_prepare_backing_directory_abi());
'''
    for name in ['no_open', '_stext', '_etext', 'address_space_init_once', 'inode_init_always', 'generic_fillattr']:
        new_cases += f'storage_base();hide_local_table=true;missing="{name}";assert(calculate_function_inode_offsets()==-ENOENT);\n'
    # 两个合法镜像边界均缺失才属于缺少边界证据。
    new_cases += 'storage_base();hide_local_table=true;missing="_end";end_hidden=true;assert(calculate_function_inode_offsets()==-ENOENT);end_hidden=false;\n'
    new_cases += f'''storage_base();hide_local_table=true;
uintptr_t* fops=(void*)(arena+{table_at}U);fops[{offsets['fop_open']//8}]=0;
assert(calculate_function_inode_offsets()==-ENOENT);
storage_base();hide_local_table=true;fops[{offsets['fop_open']//8}]+=1;
assert(calculate_function_inode_offsets()==-ENOENT);
'''
    # 初始化器窗口中任何未知调用均切断地址来源，已有窗口的原断言另由父用例执行。
    new_cases += f'''for(unsigned i=0;i<21;i++){{storage_base();hide_local_table=true;
((u32*)(arena+{symbols['inode_init_always']}U))[i]=0x94000000;
assert(calculate_function_inode_offsets()<0);}}
'''
    new_cases += '''storage_base();long page=sysconf(_SC_PAGESIZE);assert(page>struct_offset.file_ops_size);
void* pages=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(pages!=MAP_FAILED&&!mprotect((char*)pages+page,page,PROT_NONE));
uintptr_t end=(uintptr_t)pages+page,table_start=end-struct_offset.file_ops_size;
struct nm_initial_fops_probe probe={(uintptr_t)pages, (uintptr_t)pages, end, end};
*(uintptr_t*)(table_start+struct_offset.fop_open)=probe.open;
assert(nm_initial_fops_matches(table_start,&probe));
assert(!nm_initial_fops_matches(table_start+8,&probe));
assert(!nm_initial_fops_matches(end,&probe));assert(!nm_initial_fops_matches(end+8,&probe));
assert(!nm_initial_fops_matches(table_start+1,&probe));
int saved=struct_offset.fop_open;struct_offset.fop_open=struct_offset.file_ops_size;
assert(!nm_initial_fops_matches(table_start,&probe));struct_offset.fop_open=saved;
assert(!munmap(pages,page*2));free(arena);
puts("PASS: actual symbol names, initializer table identity, complete layout preparation and guarded callback read");return 0;}
'''
    # 新夹具单独执行；不替换父用例中的任何断言。
    args.output.mkdir(parents=True, exist_ok=False)
    file = args.output / 'storage.c'
    file.write_text(c + new_cases)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
               '-g', str(file), '-o', str(args.output / 'storage')]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str(args.output / 'storage')], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    receipt = {'scope': 'Developer exact-name symbol fixture and complete layout preparation, no native calls or registration',
               'kernel_sha256': reference['kernel_sha256'], 'actual_table_symbol': local_name,
               'synthesized_lookup_aliases': [], 'table_offset': table_at,
               'table_sha256': hashlib.sha256(image[table_at:table_at+offsets['file_ops_size']]).hexdigest(),
               'derived': {name: offsets[name] for name in ['inode_file_ops', 'inode_data', 'inode_data_size', 'inode_blocks']},
               'fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(), 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
