#!/usr/bin/env python3
"""核对 inode 共同片段，并执行生产 BTF 的物化布局与 ABI 边界。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('headers', 'target-header', 'reference', 'ops-reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[2]
    native=json.loads(args.reference.read_text())['values']
    ops=json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']
    args.output.mkdir(parents=True,exist_ok=False)
    profiles=[]
    for tag,path in [(tag,args.headers/tag/'include/linux/fs.h') for tag in ('v4.4','v4.9','v4.14','v4.19','v5.15','v6.6')]+[('target',args.target_header)]:
        text=path.read_text();body=text.split('struct inode {',1)[1]
        objects='struct native_objects {const struct inode_operations'+body.split('const struct inode_operations',1)[1].split('i_mapping;',1)[0]+'i_mapping;};\n'
        times='struct native_times {loff_t'+body.split('loff_t',1)[1].split('spinlock_t',1)[0]+'};\n'
        super='struct native_super {'+text.split('struct super_block {',1)[1].split('const struct dquot_operations',1)[0]+'};\n'
        source='''typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;
typedef long long int64_t,loff_t;typedef unsigned int dev_t;
#define offsetof(T,F) __builtin_offsetof(T,F)
struct inode_operations;struct address_space;struct file_system_type;struct super_operations;struct super_block;
struct list_head {void *next,*prev;};struct timespec {long tv_sec,tv_nsec;};struct timespec64 {long long tv_sec;long tv_nsec;};
'''+objects+times+super+(root/'nomount/nm_structs.h').read_text()
        for native_name,common,fields in [('native_objects','nm_inode_ops_mapping',('i_op','i_sb','i_mapping')),
                                           ('native_times','nm_inode_size_times',('i_size','i_atime','i_mtime','i_ctime')),
                                           ('native_super','nm_super_head',('s_dev','s_blocksize_bits','s_blocksize','s_maxbytes','s_type','s_op'))]:
            for field in fields:
                actual='__i_ctime' if field=='i_ctime' and '__i_ctime' in times else field
                source+=f'_Static_assert(offsetof(struct {native_name},{actual})==offsetof(struct {common},{field}),"{field}");\n'
            source+=f'_Static_assert(sizeof(struct {native_name})==sizeof(struct {common}),"span size");\n'
        c=args.output/(tag+'.c');c.write_text(source)
        built=subprocess.run(['/usr/bin/clang','--target=aarch64-none-elf','-Wall','-Werror','-c',str(c),'-o',str(args.output/(tag+'.o'))],text=True,capture_output=True)
        (args.output/(tag+'.log')).write_text(built.stdout+built.stderr);built.check_returncode()
        profiles.append({'name':tag,'header_sha256':sha(path),'reference_source_sha256':sha(c)})
    spec=importlib.util.spec_from_file_location('btf_host',root/'re_kernel/tools/test_btf.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    b=host.Btf();ints={n:b.add('u'+str(n*8),1,n,struct.pack('<I',n*8)) for n in (1,2,4,8)}
    pointer=b.add('',2,0);times=b.aggregate('timespec64',16,[('tv_sec',ints[8],0),('tv_nsec',ints[8],8)])
    data_type=b.aggregate('address_space',native['address_space_size'],[]);hash_type=b.aggregate('hlist_node',16,[('next',pointer,0),('pprev',pointer,8)])
    inode_fields=[('i_mode',ints[2],0),('i_opflags',ints[2],2),('i_uid',ints[4],4),('i_gid',ints[4],8),('i_flags',ints[4],12)]
    for field in ('i_op','i_sb','i_mapping','i_ino','i_nlink','i_size','i_hash','i_fop','i_data','i_private','i_blocks'):
        kind=data_type if field=='i_data' else hash_type if field=='i_hash' else ints[8] if field in ('i_size','i_ino','i_blocks') else ints[4] if field=='i_nlink' else pointer
        inode_fields.append((field,kind,native['inode.'+field]))
    inode_fields.extend((field,times,native['inode.i_size']+8+i*16) for i,field in enumerate(('i_atime','i_mtime','i_ctime')))
    b.aggregate('inode',native['inode_size'],inode_fields)
    b.aggregate('super_block',256,[('s_dev',ints[4],16),('s_blocksize_bits',ints[1],20),('s_blocksize',ints[8],24),('s_maxbytes',ints[8],32),('s_type',pointer,40),('s_op',pointer,48)])
    b.aggregate('kstat',256,[('mode',ints[2],4),('ino',ints[8],32),('dev',ints[4],40),('uid',ints[4],48),('gid',ints[4],52),('size',ints[8],56)])
    proto_ids={}
    def callback(name,param,result):
        proto=b.add('',13,result,b''.join(struct.pack('<II',b.name('arg'+str(i)),t) for i,t in enumerate(param)),len(param));proto_ids[name]=proto;return b.add('',2,proto)
    attr=callback('getattr',[pointer,pointer,ints[4],ints[4]],ints[4])
    drop=callback('drop_inode',[pointer],ints[4]);evict=callback('evict_inode',[pointer],0)
    b.aggregate('inode_operations',ops['inode_operations']['size'],[('getattr',attr,ops['inode_operations']['getattr'])])
    b.aggregate('super_operations',ops['super_operations']['size'],[('drop_inode',drop,ops['super_operations']['drop_inode']),('evict_inode',evict,ops['super_operations']['evict_inode'])])
    blob=b.data();records,strings=host.index_btf(blob)
    common=(root/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
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
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define pr_info printf
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define kfunc_lookup_name(n) kf_##n=(typeof(kf_##n))lookup(#n)
static void* lookup(const char*);
static int mode;
'''+common+'\nstatic const u32 records[] = {'+','.join(map(str,records))+'};\n'
    source+=f'static const u32 string_start={strings},string_length={len(blob)-strings};\n'+host.HOST+r'''
static struct btf* host_error(void) {return ERR_PTR(-ENODATA);}
static struct btf* host_none(void) {return NULL;}
static void* lookup(const char* name) {
  if (mode==1)return NULL;
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
    expected={'inode_file_ops':native['inode.i_fop'],'inode_data':native['inode.i_data'],'inode_data_size':native['address_space_size'],
              'inode_hash':native['inode.i_hash'],'inode_blocks':native['inode.i_blocks'],'iop_getattr':ops['inode_operations']['getattr'],
              'sop_drop_inode':ops['super_operations']['drop_inode'],'sop_evict_inode':ops['super_operations']['evict_inode']}
    source+='''int main(int argc,char** argv) {assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);\n'''
    for dest,field in [('inode_superblock','i_sb'),('inode_number','i_ino'),('inode_nlink','i_nlink'),('inode_size','i_size'),('inode_private','i_private')]:
        source+=f'struct_offset.{dest}={native["inode."+field]};\n'
    source+='assert(!calculate_btf_inode_offsets());struct struct_offset valid=struct_offset;assert(!nm_validate_inode_offsets(&valid));\n'
    source+='\n'.join(f'assert(struct_offset.{dest}=={value});' for dest,value in expected.items())
    source+=r'''
  struct kpm_btf btf={&object,host_find,host_type,host_name,host_size};
  struct btf_type* inode=(void*)kpm_btf_type(&btf,"inode",4);struct btf_member* members=(void*)(inode+1);struct btf_member* mapping=NULL;
  for(unsigned int i=0;i<(inode->info&0xffff);i++)if(!strcmp(host_name(&object,members[i].name_off),"i_mapping"))mapping=members+i;
  assert(mapping);mapping->offset+=8;assert(calculate_btf_inode_offsets()==-EINVAL);mapping->offset-=8;
'''
    source+=f'struct btf_type* proto=(void*)host_type(&object,{proto_ids["evict_inode"]});proto->size={ints[4]};assert(calculate_btf_inode_offsets()==-EOPNOTSUPP);proto->size=0;\n'
    source+=f'proto=(void*)host_type(&object,{proto_ids["getattr"]});u32 count=proto->info;proto->info=(13U<<24)|5;assert(calculate_btf_inode_offsets()==-EOPNOTSUPP);proto->info=count;\n'
    source+=r'''
  struct btf_type* sb=(void*)kpm_btf_type(&btf,"super_block",4);members=(void*)(sb+1);members[5].offset+=64;assert(calculate_btf_inode_offsets()==-EINVAL);members[5].offset-=64;
  assert(!calculate_btf_inode_offsets());
  mode=1;assert(calculate_btf_inode_offsets()==-ENODATA);mode=2;assert(calculate_btf_inode_offsets()==-ENODATA);mode=3;assert(calculate_btf_inode_offsets()==-ENODATA);
  mode=0;resolve_error=1;assert(calculate_btf_inode_offsets()==-EINVAL);resolve_error=0;
  free(blob);puts("seven header profiles, common inode/super spans and BTF callback boundaries: PASS");return 0;
}
'''
    c=args.output/'btf.c';c.write_text(source);(args.output/'synthetic.btf').write_bytes(blob)
    built=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'btf')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(built.stdout+built.stderr);built.check_returncode()
    run=subprocess.run([str(args.output/'btf'),str(args.output/'synthetic.btf')],text=True,capture_output=True);(args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'common ARM64 declaration spans and synthetic BTF; not all vendors or runtime proof','profiles':profiles,'sources':{name:sha(root/name) for name in files},
             'tool_sha256':sha(Path(__file__)),'reference_sha256':sha(args.reference),'ops_reference_sha256':sha(args.ops_reference),'fields':expected,'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':
    main()
