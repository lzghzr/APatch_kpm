#!/usr/bin/env python3
"""以真实目标 BTF 执行生产查询代码；原生查询 API 由宿主夹具提供。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--btf', type=Path, required=True)
    parser.add_argument('--query-fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-stop', default=None, help='尚未支持目标的确切拒绝阶段')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('btf_host', root / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    blob = args.btf.read_bytes()
    records, strings = host.index_btf(blob)
    prefix = args.query_fixture.read_text().split('/* SPDX-License-Identifier: GPL-2.0-or-later */\n#ifndef __NM_STRUCTS_H', 1)[0]
    assert 'static void* lookup(const char* name)' in prefix
    prefix = re.sub(r'static const u32 records\[\] = \{[^}]*\};', 'static const u32 records[] = {' + ','.join(map(str, records)) + '};', prefix)
    prefix = re.sub(r'static const u32 string_start=\d+,string_length=\d+;', f'static const u32 string_start={strings},string_length={len(blob)-strings};', prefix)
    source = prefix + (root / 'nomount/nm_structs.h').read_text()
    source += (root / 'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES', 1)[0].replace('section(".data.re_offsets"), ', '')
    source += (root / 'nomount/nm_btf.c').read_text()
    phases = [('objects', 'calculate_btf_offsets(&unavailable)'), ('tables', 'calculate_btf_operation_sizes()'),
              ('rule', 'calculate_btf_rule_prefixes()'), ('file', 'calculate_btf_file_offsets(&unavailable)'),
              ('inode', 'calculate_btf_inode_offsets()'), ('directory', 'calculate_btf_directory_offsets()'),
              ('virtual', 'calculate_btf_virtual_directory_abi()'), ('topology', 'calculate_btf_topology_abi()'),
              ('backing_path', 'calculate_btf_backing_directory_abi()'), ('permission', 'calculate_btf_backing_inode_abi()'),
              ('control', 'calculate_btf_control_layout()'), ('validate_inode', 'nm_validate_inode_offsets((const void*)&struct_offset)'),
              ('validate_file', 'nm_validate_file_offsets((const void*)&struct_offset)'),
              ('validate_directory', 'nm_validate_directory_offsets((const void*)&struct_offset)')]
    source += '''
int main(int argc,char** argv){
 assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);
 bool unavailable=false;int rc;\n'''
    for name, call in phases:
        source += f'rc={call};if(rc){{printf("STOP {name} %d\\n",rc);free(blob);return 3;}}\n'
    fields = re.findall(r'int16_t\s+(\w+)\s*;', (root / 'nomount/nm_offsets.c').read_text().split('};', 1)[0])
    source += r'''
 if(struct_offset.getattr_context_kind==1){
 const struct btf_type* fn=host_type(&object,host_find(&object,"inode_permission",12));
 struct btf_type* proto=(void*)host_type(&object,fn->size);struct btf_param* params=(void*)(proto+1);
 const struct btf_type* lookup_fn=host_type(&object,host_find(&object,"vfs_path_lookup",12));
 const struct btf_type* lookup_proto=host_type(&object,lookup_fn->size);const struct btf_param* lookup_args=(const void*)(lookup_proto+1);
 u32 saved=params[0].type;params[0].type=lookup_args[1].type;
 assert(calculate_btf_backing_inode_abi()==-EOPNOTSUPP);params[0].type=saved;
 struct btf_type* mount=(void*)host_type(&object,host_find(&object,"vfsmount",4));struct btf_member* members=(void*)(mount+1);bool checked=false;
 for(u32 i=0;i<(mount->info&65535);i++)if(!strcmp(host_name(&object,members[i].name_off),"mnt_userns")){
 u32 type=members[i].type,offset=members[i].offset;members[i].type=lookup_args[1].type;
 assert(calculate_btf_backing_inode_abi()==-EOPNOTSUPP);members[i].type=type;
 members[i].offset=offset+64;assert(calculate_btf_backing_inode_abi()==-EINVAL);members[i].offset=offset;checked=true;break;}
 assert(checked&&!calculate_btf_backing_inode_abi());puts("namespace pointee and mount slot rejection: PASS");
 }
'''
    source += 'puts("OFFSETS");' 
    source += ''.join(f'printf("{field} %d\\n",struct_offset.{field});' for field in fields)
    source += 'free(blob);return 0;}\n'
    c = args.output / 'btf.c'
    c.write_text(source)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'btf')]
    built = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    run = subprocess.run([str(args.output / 'btf'), str(args.btf)], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    if args.expect_stop:
        assert run.returncode == 3 and f'STOP {args.expect_stop} ' in run.stdout, run.stdout + run.stderr
        offsets = None
    else:
        run.check_returncode()
        offsets = {line.split()[0]: int(line.split()[1]) for line in run.stdout.split('OFFSETS\n')[1].splitlines()}
        assert set(offsets) == set(fields)
        (args.output / 'offsets.json').write_text(json.dumps({'offsets': offsets}, indent=2) + '\n')
    sources = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [root / 'nomount/nm_structs.h', root / 'nomount/nm_offsets.c', root / 'nomount/nm_btf.c', Path(__file__)]}
    receipt = {'scope': 'Developer production BTF queries with emulated native API; not ARM64 invocation or device proof', 'btf_sha256': hashlib.sha256(blob).hexdigest(), 'query_fixture_sha256': hashlib.sha256(args.query_fixture.read_bytes()).hexdigest(), 'sources': sources, 'expected_stop': args.expect_stop, 'returncode': run.returncode, 'offsets': offsets, 'output': run.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Target production BTF layout:', args.expect_stop or 'PASS')


if __name__ == '__main__':
    main()
