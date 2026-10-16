#!/usr/bin/env python3
"""核对 f_path 共同片段、目标原生目录函数声明及生产 BTF ABI 拒绝边界。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('headers', 'target-header', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    profiles = []
    files = [(tag, args.headers/tag/'include/linux/fs.h') for tag in ('v4.4','v4.9','v4.14','v4.19','v5.15','v6.6')]
    files.append(('target', args.target_header))
    for tag, path in files:
        text = path.read_text()
        fragment = re.search(r'struct path\s+f_path;.*?\*f_op;', text, re.S)
        assert fragment, tag
        source = '''typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef long long int64_t;
#define offsetof(T,F) __builtin_offsetof(T,F)
struct path {void* mnt;void* dentry;};struct file_operations;
'''+(root/'nomount/nm_structs.h').read_text()+'\nstruct native_file_fragment {'+fragment[0]+'};\n'
        for field in ('f_path','f_inode','f_op'):
            source += f'_Static_assert(offsetof(struct native_file_fragment,{field})==offsetof(struct nm_file_path_inode_ops,{field}),"{field}");\n'
        source += '_Static_assert(sizeof(struct native_file_fragment)==sizeof(struct nm_file_path_inode_ops),"span");\n'
        if tag == 'target':
            declarations = [re.search(r'extern\s+[^;{}]*?\b'+name+r'\s*\([^;{}]*?;', text, re.S)[0]
                            for name in ('iget5_locked','unlock_new_inode','generic_fillattr','set_nlink','generic_file_llseek')]
            source += 'typedef long long loff_t;struct kstat;\n'+'\n'.join(declarations)+'\n'
            signatures = {
                'iget5_locked': 'struct inode* (*)(struct super_block*,unsigned long,int (*)(struct inode*,void*),int (*)(struct inode*,void*),void*)',
                'unlock_new_inode': 'void (*)(struct inode*)', 'generic_fillattr': 'void (*)(struct inode*,struct kstat*)',
                'set_nlink': 'void (*)(struct inode*,unsigned int)', 'generic_file_llseek': 'loff_t (*)(struct file*,loff_t,int)'}
            for name, signature in signatures.items():
                source += f'_Static_assert(__builtin_types_compatible_p(typeof(&{name}),{signature}),"{name} ABI");\n'
        c = args.output/(tag+'.c');c.write_text(source)
        result = subprocess.run(['/usr/bin/clang','--target=aarch64-none-elf','-Wall','-Werror','-c',str(c),'-o',str(args.output/(tag+'.o'))], text=True,capture_output=True)
        (args.output/(tag+'.log')).write_text(result.stdout+result.stderr);result.check_returncode()
        profiles.append({'name': tag, 'header_sha256': sha(path), 'source_sha256': sha(c)})
    spec = importlib.util.spec_from_file_location('btf_host', root/'re_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    b = host.Btf()
    integer = {size:b.add('u'+str(size*8),1,size,struct.pack('<I',size*8)) for size in (1,4,8)}
    pointer = b.add('',2,0)
    path = b.aggregate('path',16,[('mnt',pointer,0),('dentry',pointer,8)])
    b.aggregate('file',512,[('f_path',path,16),('f_inode',pointer,32),('f_op',pointer,40)])
    def prototype(arguments, result):
        return b.add('',13,result,b''.join(struct.pack('<II',b.name('arg'+str(i)),t) for i,t in enumerate(arguments)),len(arguments))
    pair = [pointer,pointer]
    test_proto = prototype(pair,integer[4]);test_pointer = b.add('',2,test_proto)
    functions = {}
    for name,arguments,result in [('generic_fillattr',pair,0),('unlock_new_inode',[pointer],0),('set_nlink',[pointer,integer[4]],0),
                                  ('generic_file_llseek',[pointer,integer[8],integer[4]],integer[8]),
                                  ('iget5_locked',[pointer,integer[8],test_pointer,test_pointer,pointer],pointer)]:
        functions[name] = (b.add(name,12,prototype(arguments,result)),arguments)
    blob = b.data();records,strings = host.index_btf(blob)
    source = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(v) ((void*)(intptr_t)(v))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define pr_info printf
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define kfunc_lookup_name(n) kf_##n=(typeof(kf_##n))lookup(#n)
static void* lookup(const char*);
'''
    source += (root/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
    source += '\nstatic const u32 records[] = {'+','.join(map(str,records))+'};\n'
    source += f'static const u32 string_start={strings},string_length={len(blob)-strings};\n'+host.HOST+r'''
static void* lookup(const char* name) {
 if(!strcmp(name,"bpf_get_btf_vmlinux"))return host_get;
 if(!strcmp(name,"btf_find_by_name_kind"))return host_find;
 if(!strcmp(name,"btf_type_by_id"))return host_type;
 if(!strcmp(name,"btf_name_by_offset"))return host_name;
 if(!strcmp(name,"btf_resolve_size"))return host_size;
 return NULL;
}
'''
    source += (root/'nomount/nm_structs.h').read_text()+(root/'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES',1)[0]+(root/'nomount/nm_btf.c').read_text()
    source = source.replace('__attribute__((section(".data.re_offsets"), used))','')
    source += r'''
int main(int argc,char** argv) {
 assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);
 struct_offset.file_inode_ops=32;assert(!calculate_btf_virtual_directory_abi());
 struct kpm_btf btf={&object,host_find,host_type,host_name,host_size};
 struct btf_type* file=(void*)kpm_btf_type(&btf,"file",4);struct btf_member* members=(void*)(file+1);
 members[0].offset+=64;assert(calculate_btf_virtual_directory_abi()==-EINVAL);members[0].offset-=64;
 struct btf_type* function=(void*)kpm_btf_type(&btf,"generic_fillattr",12);struct btf_type* proto=(void*)host_type(&object,function->size);
 u32 info=proto->info;proto->info=(13U<<24)|3;assert(calculate_btf_virtual_directory_abi()==-EOPNOTSUPP);proto->info=info;
 u32 name=function->name_off;function->name_off=0;assert(calculate_btf_virtual_directory_abi()==-ENOENT);function->name_off=name;
'''
    source += f'proto=(void*)host_type(&object,{test_proto});u32 result=proto->size;proto->size={integer[1]};assert(calculate_btf_virtual_directory_abi()==-EOPNOTSUPP);proto->size=result;\n'
    source += r'''
 info=proto->info;proto->info=(13U<<24)|1;assert(calculate_btf_virtual_directory_abi()==-EOPNOTSUPP);proto->info=info;
 assert(!calculate_btf_virtual_directory_abi());resolve_error=1;assert(calculate_btf_virtual_directory_abi()==-EINVAL);resolve_error=0;
 free(blob);puts("seven file-path fragments, target native declarations and virtual-directory BTF ABI boundaries: PASS");return 0;
}
'''
    c = args.output/'btf.c';c.write_text(source);(args.output/'synthetic.btf').write_bytes(blob)
    result = subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'btf')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode()
    run = subprocess.run([str(args.output/'btf'),str(args.output/'synthetic.btf')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    files = ('nomount/nm_structs.h','nomount/nm_offsets.c','nomount/nm_btf.c','kpm_utils.h')
    receipt = {'scope':'Developer ARM64 common fragments and host ABI contracts; not target runtime proof',
               'sources':{name:sha(root/name) for name in files},'tool_sha256':sha(Path(__file__)),
               'profiles':profiles,'synthetic_btf_sha256':sha(args.output/'synthetic.btf'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__ == '__main__':
    main()
