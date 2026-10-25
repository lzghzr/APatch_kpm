#!/usr/bin/env python3
"""用厂商声明及真实目标 BTF 核对现代链接接口，追加成员/原型冲突负例。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
from test_file_control import PRELUDE, run
from inspect_target import unpack_target

ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
int main(int argc,char**argv){
 assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long length=ftell(f);rewind(f);
 blob=malloc(length);assert(blob&&fread(blob,1,length,f)==(size_t)length);fclose(f);
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 assert(!calculate_btf_symlink(&unavailable)&&!unavailable);
 struct btf_type*ops=(void*)kpm_btf_type(&b,"inode_operations",4);assert(ops);
 struct btf_member*members=(void*)(ops+1);unsigned checked=0;
 for(u32 i=0;i<(ops->info&65535);i++){
  const char*name=host_name(&object,members[i].name_off);
  if(strcmp(name,"get_link")&&strcmp(name,"lookup"))continue;
  u32 saved=members[i].offset;members[i].offset+=64;
  assert(calculate_btf_symlink(&unavailable)==-EINVAL);members[i].offset=saved;checked++;
 }
 assert(checked==2);
 struct btf_type*proto=(void*)nm_btf_callback_prototype(&b,ops,"get_link");assert(proto);
 u32 saved=proto->info;proto->info=(proto->info&~65535U)|2;assert(calculate_btf_symlink(&unavailable)==-EOPNOTSUPP);proto->info=saved;
 struct btf_param*params=(void*)(proto+1);
 for(unsigned i=0;i<3;i++){
  saved=params[i].type;params[i].type=params[(i+1)%3].type;
  assert(calculate_btf_symlink(&unavailable)==-EOPNOTSUPP);params[i].type=saved;
 }
 saved=proto->size;proto->size=params[0].type; /* pointer width alone is intentionally accepted for return */
 assert(!calculate_btf_symlink(&unavailable));proto->size=saved;
 for(unsigned i=0;i<2;i++){
  const struct btf_type*fn=kpm_btf_type(&b,i?"vfs_readlink":"vfs_get_link",12);assert(fn);
  struct btf_type*p=(void*)host_type(&object,fn->size);saved=p->info;p->info=(p->info&~65535U)|1;
  assert(calculate_btf_symlink(&unavailable)==-EOPNOTSUPP);p->info=saved;
 }
 api_mode=1;assert(calculate_btf_symlink(&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_symlink(&unavailable)==-ENODATA&&!unavailable);
 api_mode=0;assert(!calculate_btf_symlink(&unavailable));free(blob);
 puts("get_link@8, named parameters and native helpers; 8 mutations + 2 API boundaries PASS");return 0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--headers',nargs='+',type=Path,required=True)
    p.add_argument('--images',nargs='+',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    header=(ROOT/'nomount/nm_structs.h').read_text();rows=[]
    for n,path in enumerate(a.headers):
        body=path.read_text().split('struct inode_operations {',1)[1].split('};',1)[0]
        if '(*get_link)' not in body:
            rows.append({'header':str(path),'result':'UNSUPPORTED: legacy follow_link, no modern get_link'});continue
        prefix=body[:body.index(';',body.index('(*get_link)'))+1]
        source='typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef long int64_t;typedef _Bool bool;\n#define offsetof(T,F) __builtin_offsetof(T,F)\n'+header
        source+='struct reference_link{'+prefix+'};\n'
        for member in ('lookup','get_link'):
            source+=f'_Static_assert(offsetof(struct reference_link,{member})==offsetof(struct nm_inode_link_ops,{member}),"slot");\n'
            source+=f'_Static_assert(__builtin_types_compatible_p(typeof(((struct reference_link*)0)->{member}),typeof(((struct nm_inode_link_ops*)0)->{member})),"prototype");\n'
        c=a.output/f'header-{n}.c';c.write_text(source)
        run(['/usr/bin/clang','--target=aarch64-none-elf','-fsyntax-only','-I',str(ROOT/'nomount'),str(c)],a.output/f'header-{n}.log')
        rows.append({'header':str(path),'result':'PASS','asserts':4,'vfs_readlink_declared':'extern int vfs_readlink(' in path.read_text()})
    spec=importlib.util.spec_from_file_location('host',ROOT/'re_kernel/tools/test_btf.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    common=(ROOT/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
    offsets=(ROOT/'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES',1)[0].replace('__attribute__((section(".data.re_offsets"), used))','')
    declarations=(ROOT/'nomount/nm_btf.c').read_text()
    lookup=r'''
static int api_mode;static struct btf* no_btf(void){return NULL;}static struct btf* error_btf(void){return ERR_PTR(-ENODATA);}
static void* lookup(const char* name){
 if(!strcmp(name,"bpf_get_btf_vmlinux"))return api_mode==1?no_btf:api_mode==2?error_btf:host_get;
 if(!strcmp(name,"btf_find_by_name_kind"))return host_find;if(!strcmp(name,"btf_type_by_id"))return host_type;
 if(!strcmp(name,"btf_name_by_offset"))return host_name;if(!strcmp(name,"btf_resolve_size"))return host_size;return NULL;}
'''
    targets=[]
    for n,path in enumerate(a.images):
        data=unpack_target(path).data;pos=-1
        while True:
            pos=data.find(b'\x9f\xeb\x01\x00',pos+1)
            if pos<0:raise ValueError('BTF not found: '+str(path))
            try:
                h=struct.unpack_from('<HBBIIIII',data,pos);size=h[3]+max(h[4]+h[5],h[6]+h[7]);blob=data[pos:pos+size]
                records,strings=host.index_btf(blob);break
            except (AssertionError,KeyError,struct.error):pass
        out=a.output/f'btf-{n}';out.mkdir();(out/'input.btf').write_bytes(blob)
        pre=PRELUDE.replace('#define CONFIG_KPM_BASELINES 1','')
        pre+='\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n#define nm_log_info(...) ((void)0)\nstatic void* lookup(const char*);\n#define kfunc_lookup_name(n) kfunc(n)=(typeof(kfunc(n)))lookup(#n)\n'
        source=pre+common+'\nstatic const u32 records[]={'+','.join(map(str,records))+'};\n'
        source+=f'static const u32 string_start={strings},string_length={len(blob)-strings};\n'
        source+=host.HOST+lookup+header+offsets+declarations+TEST
        (out/'btf.c').write_text(source)
        run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-g',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log')
        run([str((out/'btf').resolve()),str((out/'input.btf').resolve())],out/'run.log')
        row={'image':str(path),'result':(out/'run.log').read_text().strip()};targets.append(row);print(row)
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer source/BTF checks, not native execution','headers':rows,'targets':targets},indent=2)+'\n')


if __name__=='__main__':main()
