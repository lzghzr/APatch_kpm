#!/usr/bin/env python3
"""编译核对连续声明片段，并用真实目标 BTF 执行控制回调核验；含布局/原型反例。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from test_directory_abis import function
from test_file_control import PRELUDE, run
from inspect_target import unpack_target

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--headers', nargs='+', type=Path, required=True)
    p.add_argument('--images', nargs='+', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    results = {'scope': 'Developer declaration/BTF source checks; not native VFS/CFI or performance proof', 'headers': [], 'targets': []}
    header = (ROOT/'nomount/nm_structs.h').read_text()
    for n, path in enumerate(a.headers):
        text = path.read_text().split('struct file_operations {', 1)[1].split('};', 1)[0]
        control = text[text.index('long (*unlocked_ioctl)'):]
        control = control[:control.index(';', control.index('(*mmap)'))+1]
        sync = text[text.index('int (*release)'):]
        sync = sync[:sync.index(';', sync.index('(*fsync)'))+1]
        source = '''typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;
typedef unsigned long long u64;typedef long int64_t;typedef long long loff_t;typedef _Bool bool;
#define offsetof(T,F) __builtin_offsetof(T,F)
''' + header
        source += 'struct reference_control {'+control+'};\nstruct reference_sync {'+sync+'};\n'
        for ref, current, members in [('reference_control','nm_file_control_ops',('unlocked_ioctl','compat_ioctl','mmap')),
                                      ('reference_sync','nm_file_sync_ops',('release','fsync'))]:
            source += f'_Static_assert(sizeof(struct {ref})==sizeof(struct {current}),"span");\n'
            for member in members:
                source += f'_Static_assert(offsetof(struct {ref},{member})==offsetof(struct {current},{member}),"slot");\n'
                source += f'_Static_assert(__builtin_types_compatible_p(typeof(((struct {ref}*)0)->{member}),typeof(((struct {current}*)0)->{member})),"prototype");\n'
        file = a.output/f'header-{n}.c';file.write_text(source)
        run(['/usr/bin/clang','--target=aarch64-none-elf','-fsyntax-only','-Wno-unused-function','-I',str(ROOT/'nomount'),str(file)],a.output/f'header-{n}.log')
        results['headers'].append({'path':str(path),'result':'PASS'})
    spec=importlib.util.spec_from_file_location('btf_host',ROOT/'re_kernel/tools/test_btf.py')
    host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    common=(ROOT/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
    offset=(ROOT/'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES',1)[0].replace('__attribute__((section(".data.re_offsets"), used))','')
    declarations=(ROOT/'nomount/nm_btf.c').read_text()
    # 此处只替换宿主提供的查询 API；待测函数保持生产源码。
    lookup=r'''
static int api_mode;
static struct btf* no_btf(void){return NULL;}
static struct btf* error_btf(void){return ERR_PTR(-ENODATA);}
static void* lookup(const char* name){
 if(!strcmp(name,"bpf_get_btf_vmlinux"))return api_mode==1?no_btf:api_mode==2?error_btf:host_get;
 if(!strcmp(name,"btf_find_by_name_kind"))return host_find;
 if(!strcmp(name,"btf_type_by_id"))return host_type;
 if(!strcmp(name,"btf_name_by_offset"))return host_name;
 if(!strcmp(name,"btf_resolve_size"))return host_size;return NULL;
}
'''
    tests=r'''
int main(int argc,char**argv){
 assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long length=ftell(f);rewind(f);
 blob=malloc(length);assert(blob&&fread(blob,1,length,f)==(size_t)length);fclose(f);
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};
 struct btf_type* ops=(void*)kpm_btf_type(&b,"file_operations",4);assert(ops);
 struct_offset.fop_mmap=kpm_btf_offset(&b,ops,"mmap",8);struct_offset.fop_release=kpm_btf_offset(&b,ops,"release",8);
 assert(struct_offset.fop_mmap>0&&struct_offset.fop_release>0);
 bool unavailable=false;assert(!calculate_btf_file_control(&unavailable)&&!unavailable);
 unsigned checked=0;struct btf_member*members=(void*)(ops+1);
 for(u32 i=0;i<(ops->info&65535);i++){
  const char*name=host_name(&object,members[i].name_off);
  if(strcmp(name,"unlocked_ioctl")&&strcmp(name,"compat_ioctl")&&strcmp(name,"fsync"))continue;
  u32 saved=members[i].offset;members[i].offset+=64;
  assert(calculate_btf_file_control(&unavailable)==-EINVAL);members[i].offset=saved;
  saved=members[i].name_off;members[i].name_off=ops->name_off;
  assert(calculate_btf_file_control(&unavailable)==-ENOENT);members[i].name_off=saved;
  const struct btf_type*proto=nm_btf_callback_prototype(&b,ops,name);assert(proto);
  struct btf_type*edit=(void*)proto;saved=edit->info;edit->info=(edit->info&~65535U)|1;
  assert(calculate_btf_file_control(&unavailable)==-EOPNOTSUPP);edit->info=saved;
  checked++;
 }
 assert(checked==3&&!calculate_btf_file_control(&unavailable));
 api_mode=1;assert(calculate_btf_file_control(&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_file_control(&unavailable)==-ENODATA&&!unavailable);
 api_mode=0;assert(!calculate_btf_file_control(&unavailable));
 printf("control offsets %d/%d/%d; 9 member/prototype mutations and 2 API boundaries PASS\n",
 struct_offset.fop_mmap-16,struct_offset.fop_mmap-8,struct_offset.fop_release+8);
 free(blob);return 0;
}
'''
    for n, path in enumerate(a.images):
        image=unpack_target(path).data
        pos=-1
        while True:
            pos=image.find(b'\x9f\xeb\x01\x00',pos+1)
            if pos<0:raise ValueError('BTF not found: '+str(path))
            try:
                h=struct.unpack_from('<HBBIIIII',image,pos)
                size=h[3]+max(h[4]+h[5],h[6]+h[7]);data=image[pos:pos+size]
                records,strings=host.index_btf(data)
                break
            except (AssertionError,KeyError,struct.error):pass
        out=a.output/f'btf-{n}';out.mkdir();(out/'input.btf').write_bytes(data)
        pre=PRELUDE.replace('#define CONFIG_KPM_BASELINES 1','')
        pre+='\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n#define nm_log_info(...) ((void)0)\n'
        pre+='static void* lookup(const char*);\n'
        pre+='#define kfunc_lookup_name(n) kfunc(n)=(typeof(kfunc(n)))lookup(#n)\n'
        source=pre+common+'\nstatic const u32 records[]={'+','.join(map(str,records))+'};\n'
        source+=f'static const u32 string_start={strings},string_length={len(data)-strings};\n'
        source+=host.HOST+lookup+header+offset+declarations+tests
        (out/'btf.c').write_text(source)
        run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-g',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log')
        run([str((out/'btf').resolve()),str((out/'input.btf').resolve())],out/'run.log')
        result=(out/'run.log').read_text().strip();print(path.name,result)
        results['targets'].append({'image':str(path),'result':result})
    results['result']='PASS'
    (a.output/'receipt.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
