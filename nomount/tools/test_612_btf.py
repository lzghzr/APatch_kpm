#!/usr/bin/env python3
"""以选定内核的真实 BTF 贯通生产布局查询，输出静态配置与布局对照。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

from inspect_target import unpack_target

ROOT = Path(__file__).resolve().parents[2]


def btf_from_image(image, index):
    at = -1
    while True:
        at = image.find(b'\x9f\xeb\x01\x00', at + 1)
        if at < 0:
            raise ValueError('no complete BTF in selected image')
        if at + 24 > len(image):
            continue
        _, _, _, header, types, type_length, strings, string_length = struct.unpack_from('<HBBIIIII', image, at)
        end = at + header + max(types + type_length, strings + string_length)
        if header < 24 or end > len(image):
            continue
        blob = image[at:end]
        try:
            records, start = index(blob)
        except (ValueError, IndexError, struct.error):
            continue
        return blob, records, start


NEGATIVE = r'''
static struct btf_member* selected_member(const char* type,const char* name){
 const struct btf_type* t=host_type(&object,host_find(&object,type,4));assert(t);
 struct btf_member* m=(void*)(t+1);
 for(unsigned i=0;i<(t->info&0xffff);i++)if(!strcmp(host_name(&object,m[i].name_off),name))return &m[i];
 assert(0);return NULL;
}
static void reject_changed_btf(void){
 struct struct_offset saved=struct_offset;bool unavailable=false;struct btf_member*m;u32 old;
 m=selected_member("file","f_op");old=m->offset;m->offset=0x7fff*8;
 assert(calculate_btf_offsets(&unavailable)==-EINVAL&&!unavailable);m->offset=old;struct_offset=saved;
 m=selected_member("file","f_op");old=m->offset;m->offset=selected_member("file","f_inode")->offset;
 assert(!calculate_btf_offsets(&unavailable)&&nm_validate_file_offsets((const void*)&struct_offset)==-EINVAL);
 m->offset=old;struct_offset=saved;
 m=selected_member("file_operations","llseek");old=m->offset;m->offset=0;
 assert(calculate_btf_offsets(&unavailable)==-EINVAL&&!unavailable);m->offset=old;struct_offset=saved;
 m=selected_member("file_operations","read_iter");old=m->offset;m->offset+=64;
 assert(calculate_btf_file_offsets(&unavailable)==-EINVAL&&!unavailable);m->offset=old;struct_offset=saved;
 m=selected_member("inode","i_atime_nsec");old=m->offset;m->offset+=32;
 assert(calculate_btf_inode_offsets(&unavailable)==-EINVAL&&!unavailable);m->offset=old;struct_offset=saved;
 m=selected_member("inode","i_atime_sec");old=m->type;m->type=selected_member("inode","i_atime_nsec")->type;
 assert(calculate_btf_inode_offsets(&unavailable)==-EINVAL&&!unavailable);m->type=old;struct_offset=saved;
 api_mode=1;assert(calculate_btf_offsets(&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_offsets(&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(!calculate_btf_offsets(&unavailable)&&!unavailable);
 assert(!memcmp(&saved,(const void*)&struct_offset,sizeof(saved)));
 puts("6.12 BTF mutation and unavailable/error routing PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, nargs='+', required=True)
    parser.add_argument('--query-fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('btf_host', ROOT / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    base = args.query_fixture.read_text().split('/* SPDX-License-Identifier: GPL-2.0-or-later */\n#ifndef __NM_STRUCTS_H', 1)[0]
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    fields = re.findall(r'int16_t\s+(\w+);', offsets.split('};', 1)[0])
    prefix = offsets.split('\n#ifndef CONFIG_KPM_BASELINES\n#include "nm_btf.c"', 1)[0]
    prefix = prefix.replace('__attribute__((section(".data.re_offsets"), used))', '')
    phases = ['offsets', 'operation_sizes', 'rule_prefixes', 'file_offsets', 'inode_offsets', 'directory_offsets',
              'virtual_directory_abi', 'topology_abi', 'backing_directory_abi', 'backing_inode_abi', 'control_layout',
              'file_control', 'file_write']
    results = []
    for number, path in enumerate(args.images):
        result = unpack_target(path)
        blob, records, strings = btf_from_image(result.data, host.index_btf)
        out = args.output / str(number)
        out.mkdir()
        (out / 'input.btf').write_bytes(blob)
        source = re.sub(r'static const u32 records\[\]\s*=\s*\{[^}]*\};',
                        'static const u32 records[] = {' + ','.join(map(str, records)) + '};', base)
        source = re.sub(r'static const u32 string_start=\d+,string_length=\d+;',
                        f'static const u32 string_start={strings},string_length={len(blob)-strings};', source)
        source += (ROOT / 'nomount/nm_structs.h').read_text() + prefix + (ROOT / 'nomount/nm_btf.c').read_text()
        source += NEGATIVE
        source += '''
int main(int argc,char**argv){
 assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);
 blob=malloc(n);assert(blob&&fread(blob,1,n,f)==(size_t)n);fclose(f);bool unavailable=false;int rc;
'''
        for phase in phases:
            source += f'rc=calculate_btf_{phase}(&unavailable);printf("{phase} %d %d\\n",rc,unavailable);if(rc)return 3;\n'
        for name in ('inode', 'file', 'directory'):
            source += f'assert(!nm_validate_{name}_offsets((const void*)&struct_offset));\n'
        source += '''
 assert(!validate_offsets()&&!nm_validate_control_layout());
 struct nm_setattr_layout setter;int slot,second;
 assert(!calculate_btf_setattr(&setter,&unavailable));
 assert(!calculate_btf_owned_permission(&unavailable,&slot,&second));
 int context=struct_offset.getattr_context_kind;
 assert(calculate_btf_xattr_read(context,&unavailable)==(context?5:4));
 assert(calculate_btf_xattr_write(context,&unavailable)>=0);
 assert(!calculate_btf_xattr_remove(context,&unavailable));
 assert(!calculate_btf_xattr_internal_list(&unavailable));
 reject_changed_btf();puts("OFFSETS");
'''
        source += ''.join(f'printf("{field} %d\\n",struct_offset.{field});\n' for field in fields)
        source += 'free(blob);return 0;}\n'
        c = out / 'btf.c'
        c.write_text(source)
        build = subprocess.run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                                '-fsanitize=address,undefined', '-g', str(c), '-o', str(out / 'btf')], text=True, capture_output=True)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        build.check_returncode()
        run = subprocess.run([str((out / 'btf').resolve()), str((out / 'input.btf').resolve())], text=True, capture_output=True)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        print(path, run.stdout, run.stderr)
        run.check_returncode()
        values = {line.split()[0]: int(line.split()[1]) for line in run.stdout.split('OFFSETS\n')[1].splitlines()}
        assert set(values) == set(fields)
        config = {'image': str(path), 'scope': 'Developer target BTF, host native-query API', 'offsets': values}
        (out / 'offsets.json').write_text(json.dumps(config, indent=2) + '\n')
        results.append({'image': str(path), 'offsets': values, 'result': 'PASS'})
    (args.output / 'receipt.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
