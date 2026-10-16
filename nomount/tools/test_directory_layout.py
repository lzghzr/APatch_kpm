#!/usr/bin/env python3
"""比较目录共同片段并执行 BTF 目录布局、缺失字段和调用 ABI 边界。"""
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
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('headers','target-header','reference','ops-reference','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True,exist_ok=False)
    reference=json.loads(args.reference.read_text())['values'];ops=json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']
    profiles=[]
    for tag,path in [(tag,args.headers/tag/'include/linux/dcache.h') for tag in ('v4.4','v4.9','v4.14','v4.19','v5.15','v6.6')]+[('target',args.target_header)]:
        text=path.read_text()
        match=re.search(r'const struct dentry_operations\s*\*d_op;.*?void\s*\*d_fsdata;',text,re.S);assert match,tag
        data='struct native_data {'+match[0]+'};\n'
        body=text.split('struct dentry_operations {',1)[1];end=body.index('(*d_release)');end=body.index(';',end)+1
        table='struct native_ops {'+body[:end]+'};\n'
        source='''typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef long long int64_t;
#define offsetof(T,F) __builtin_offsetof(T,F)
struct dentry;struct dentry_operations;struct super_block;struct qstr;struct inode;
'''+data+table+(root/'nomount/nm_structs.h').read_text()
        for native,common,fields in [('native_data','nm_dentry_ops_data',('d_op','d_sb','d_time','d_fsdata')),
                                      ('native_ops','nm_dentry_control_ops',('d_revalidate','d_weak_revalidate','d_hash','d_compare','d_delete'))]:
            for field in fields:source+=f'_Static_assert(offsetof(struct {native},{field})==offsetof(struct {common},{field}),"{field}");\n'
            source+=f'_Static_assert(sizeof(struct {native})==sizeof(struct {common}),"span size");\n' if native=='native_data' else f'_Static_assert(offsetof(struct {native},d_delete)+8==sizeof(struct {common}),"common head size");\n'
        c=args.output/(tag+'.c');c.write_text(source)
        result=subprocess.run(['/usr/bin/clang','--target=aarch64-none-elf','-Wall','-Werror','-c',str(c),'-o',str(args.output/(tag+'.o'))],text=True,capture_output=True)
        (args.output/(tag+'.log')).write_text(result.stdout+result.stderr);result.check_returncode()
        profiles.append({'name':tag,'header_sha256':sha(path),'source_sha256':sha(c)})
    spec=importlib.util.spec_from_file_location('btf_host',root/'re_kernel/tools/test_btf.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    b=host.Btf();integer={size:b.add('u'+str(size*8),1,size,struct.pack('<I',size*8)) for size in (1,4,8)};pointer=b.add('',2,0);proto={}
    def callback(name,args,result):
        p=b.add('',13,result,b''.join(struct.pack('<II',b.name('arg'+str(i)),t) for i,t in enumerate(args)),len(args));proto[name]=p;return b.add('',2,p)
    lookup=callback('lookup',[pointer,pointer,integer[4]],pointer)
    iterate=callback('iterate',[pointer,pointer],integer[4]);shared=callback('iterate_shared',[pointer,pointer],integer[4])
    revalidate=callback('d_revalidate',[pointer,integer[4]],integer[4]);weak=callback('d_weak_revalidate',[pointer,integer[4]],integer[4]);release=callback('d_release',[pointer],0)
    actor=callback('actor',[pointer,pointer,integer[4],integer[8],integer[8],integer[4]],integer[4])
    b.aggregate('inode_operations',ops['inode_operations']['size'],[('lookup',lookup,0)])
    b.aggregate('file_operations',ops['file_operations']['size'],[('iterate',iterate,ops['file_operations']['iterate']),('iterate_shared',shared,ops['file_operations']['iterate_shared'])])
    names=('d_revalidate','d_weak_revalidate','d_hash','d_compare','d_delete','d_init','d_release')
    b.aggregate('dentry_operations',reference['dentry_operations.size'],[(name,revalidate if i==0 else weak if i==1 else release if i==6 else pointer,i*8) for i,name in enumerate(names)])
    b.aggregate('dir_context',16,[('actor',actor,0),('pos',integer[8],8)])
    spin=b.aggregate('spinlock_t',4,[('raw_lock',integer[4],0)]);lockref=b.aggregate('lockref',8,[('lock',spin,0),('count',integer[4],4)])
    b.aggregate('dentry',256,[('d_lockref',lockref,reference['dentry.d_lockref']),('d_op',pointer,reference['dentry.d_op']),('d_sb',pointer,reference['dentry.d_sb']),('d_time',integer[8],reference['dentry.d_time']),('d_fsdata',pointer,reference['dentry.d_fsdata'])])
    blob=b.data();records,strings=host.index_btf(blob)
    source=r'''
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
static int mode;
'''
    source+=(root/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
    source+='\nstatic const u32 records[] = {'+','.join(map(str,records))+'};\n'
    source+=f'static const u32 string_start={strings},string_length={len(blob)-strings};\n'+host.HOST+r'''
static struct btf* host_error(void) {return ERR_PTR(-ENODATA);}
static struct btf* host_none(void) {return NULL;}
static void* lookup(const char* name) {
 if(mode==1)return NULL;
 if(!strcmp(name,"bpf_get_btf_vmlinux"))return mode==2?host_error:mode==3?host_none:host_get;
 if(!strcmp(name,"btf_find_by_name_kind"))return host_find;
 if(!strcmp(name,"btf_type_by_id"))return host_type;
 if(!strcmp(name,"btf_name_by_offset"))return host_name;
 if(!strcmp(name,"btf_resolve_size"))return host_size;
 return NULL;
}
'''
    files=('nomount/nm_structs.h','nomount/nm_offsets.c','nomount/nm_btf.c','kpm_utils.h')
    source+=(root/files[0]).read_text()+(root/files[1]).read_text().split('#ifndef CONFIG_KPM_BASELINES',1)[0]+(root/files[2]).read_text()
    source=source.replace('__attribute__((section(".data.re_offsets"), used))','')
    source+='''int main(int argc,char** argv) {assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);\n'''
    source+=f'struct_offset.dentry_ops={reference["dentry.d_op"]};struct_offset.dentry_ops_size={reference["dentry_operations.size"]};struct_offset.inode_ops_size={ops["inode_operations"]["size"]};struct_offset.file_ops_size={ops["file_operations"]["size"]};\n'
    source+='assert(!calculate_btf_directory_offsets());struct struct_offset valid=struct_offset;assert(!nm_validate_directory_offsets(&valid));\n'
    source+=f'assert(valid.dop_init==40&&valid.dop_release==48);assert(valid.dentry_lock=={reference["dentry.d_lockref"]}&&valid.fop_iterate=={ops["file_operations"]["iterate"]}&&valid.fop_iterate_shared=={ops["file_operations"]["iterate_shared"]});\n'
    source+=r'''
struct kpm_btf btf={&object,host_find,host_type,host_name,host_size};
struct btf_type* dentry=(void*)kpm_btf_type(&btf,"dentry",4);struct btf_member* members=(void*)(dentry+1);
members[4].offset+=64;assert(calculate_btf_directory_offsets()==-EINVAL);members[4].offset-=64;
'''
    source+=f'struct btf_type* p=(void*)host_type(&object,{proto["actor"]});p->size={integer[1]};assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);p->size={integer[4]};\n'
    source+=f'p=(void*)host_type(&object,{proto["d_revalidate"]});u32 count=p->info;p->info=(13U<<24)|4;assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);p->info=count;\n'
    source+=r'''
struct btf_type* fops=(void*)kpm_btf_type(&btf,"file_operations",4);u32 info=fops->info;fops->info=(4U<<24)|1;
assert(!calculate_btf_directory_offsets()&&struct_offset.fop_iterate_shared==-1);fops->info=info;assert(!calculate_btf_directory_offsets());
struct btf_type* dops=(void*)kpm_btf_type(&btf,"dentry_operations",4);members=(void*)(dops+1);
struct btf_member saved_init=members[5],saved_release=members[6];u32 dop_info=dops->info;
members[5]=saved_release;members[5].offset=40*8;dops->info=(4U<<24)|6;
assert(!calculate_btf_directory_offsets()&&struct_offset.dop_init==-1&&struct_offset.dop_release==40);
valid=struct_offset;assert(!nm_validate_directory_offsets(&valid));
members[5]=saved_init;members[6]=saved_release;dops->info=dop_info;assert(!calculate_btf_directory_offsets());
valid=struct_offset;valid.fop_iterate=valid.fop_iterate_shared;assert(nm_validate_directory_offsets(&valid)==-EINVAL);
valid=struct_offset;valid.fop_iterate=valid.fop_iterate_shared=-1;assert(nm_validate_directory_offsets(&valid)==-ENOENT);
valid=struct_offset;valid.dentry_lock=valid.dentry_ops;assert(nm_validate_directory_offsets(&valid)==-EINVAL);
resolve_error=1;assert(calculate_btf_directory_offsets()==-EINVAL);resolve_error=0;
mode=1;assert(calculate_btf_directory_offsets()==-ENODATA);mode=2;assert(calculate_btf_directory_offsets()==-ENODATA);mode=3;assert(calculate_btf_directory_offsets()==-ENODATA);
free(blob);puts("seven dentry declaration profiles, directory slots and callback ABI boundaries: PASS");return 0;
}
'''
    c=args.output/'btf.c';c.write_text(source);(args.output/'synthetic.btf').write_bytes(blob)
    result=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'btf')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode()
    run=subprocess.run([str(args.output/'btf'),str(args.output/'synthetic.btf')],text=True,capture_output=True);(args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'common declarations and synthetic BTF; not all vendors or runtime proof','profiles':profiles,'sources':{name:sha(root/name) for name in files},
             'tool_sha256':sha(Path(__file__)),'reference_sha256':sha(args.reference),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':
    main()
