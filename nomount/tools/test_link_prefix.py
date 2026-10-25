#!/usr/bin/env python3
"""核对旧链接完整前部声明几何，并执行两种兼容BTF查询及冲突负例。"""
import argparse,importlib.util,json,re,struct
from pathlib import Path
from test_file_control import PRELUDE,run
ROOT=Path(__file__).resolve().parents[2]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--headers',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 header=(ROOT/'nomount/nm_structs.h').read_text();rows=[]
 for n,path in enumerate(a.headers):
  body=path.read_text().split('struct inode_operations {',1)[1].split('};',1)[0];end=body.index(';',body.index('(*getattr)'))+1;body=body[:end]
  legacy='(*follow_link)' in body
  if '(*permission2)' not in body:rows.append({'header':str(path),'result':'modern native vfs_readlink; Android compat prefix not applicable'});continue
  members=re.findall(r'\(\s*\*\s*(\w+)\s*\)',body)
  assert not '#' in body
  reference='struct reference{'+''.join('void* '+m+';' for m in members)+'};\n'
  own='nm_inode_follow_prefix' if legacy else 'nm_inode_android_link_prefix'
  source='typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef long int64_t;typedef _Bool bool;\n#define offsetof(T,F) __builtin_offsetof(T,F)\n'+header+reference
  for m in members:
   mine='hardlink' if m=='link' else 'link.'+m if not legacy and m in ('lookup','get_link') else m
   source+=f'_Static_assert(offsetof(struct reference,{m})==offsetof(struct {own},{mine}),"{m}");\n'
  out=a.output/f'header-{n}.c';out.write_text(source);run(['/usr/bin/clang','--target=aarch64-none-elf','-fsyntax-only',str(out)],a.output/f'header-{n}.log')
  rows.append({'header':str(path),'legacy':legacy,'asserts':len(members),'result':'PASS'})
 spec=importlib.util.spec_from_file_location('btfhost',ROOT/'re_kernel/tools/test_btf.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
 for legacy in (False,True):
  b=host.Btf();integer=b.add('int',1,4,struct.pack('<I',32));char=b.add('char',1,1,struct.pack('<I',8));cp=b.add('',2,char);vp=b.add('',2,0)
  types={n:b.aggregate(n,8,[('dummy',vp,0)]) for n in ('inode','dentry','delayed_call')};ptr={n:b.add('',2,t) for n,t in types.items()}
  def proto(ret,args):return b.add('',13,ret,b''.join(struct.pack('<II',0,t) for t in args),len(args))
  def callback(ret,args):return b.add('',2,proto(ret,args))
  follow=callback(cp,[ptr['dentry'],vp] if legacy else [ptr['dentry'],ptr['inode'],ptr['delayed_call']]);read=callback(integer,[ptr['dentry'],cp,integer]);put=callback(0,[ptr['inode'],vp])
  fields=[('lookup',vp,0),('follow_link' if legacy else 'get_link',follow,8),('permission2',vp,24),('readlink',read,40),('getattr',vp,144 if legacy else 128)]
  if legacy:fields.append(('put_link',put,48))
  b.aggregate('inode_operations',192,fields);b.add('generic_readlink',12,proto(integer,[ptr['dentry'],cp,integer]));b.add('vfs_get_link',12,proto(cp,[ptr['dentry'],ptr['delayed_call']]))
  blob=b.data();records,strings=host.index_btf(blob);out=a.output/('follow' if legacy else 'get');out.mkdir();(out/'input.btf').write_bytes(blob)
  common=(ROOT/'kpm_utils.h').read_text().split('// BTF\n',1)[1].rsplit('#endif',1)[0]
  offsets=(ROOT/'nomount/nm_offsets.c').read_text().split('#ifndef CONFIG_KPM_BASELINES',1)[0].replace('__attribute__((section(".data.re_offsets"), used))','')
  pre=PRELUDE.replace('#define CONFIG_KPM_BASELINES 1','')+'\n#define nm_log_info(...) ((void)0)\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\nstatic void*lookup(const char*);\n#define kfunc_lookup_name(n) kfunc(n)=(typeof(kfunc(n)))lookup(#n)\n'
  lookup='''
static void*lookup(const char*n){if(!strcmp(n,"bpf_get_btf_vmlinux"))return host_get;if(!strcmp(n,"btf_find_by_name_kind"))return host_find;if(!strcmp(n,"btf_type_by_id"))return host_type;if(!strcmp(n,"btf_name_by_offset"))return host_name;if(!strcmp(n,"btf_resolve_size"))return host_size;return NULL;}
'''
  test=r'''
int main(int argc,char**argv){assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);fseek(f,0,2);long size=ftell(f);rewind(f);blob=malloc(size);assert(fread(blob,1,size,f)==size);fclose(f);
struct_offset.permission_abi=0;struct_offset.iop_getattr=GETATTR;bool unavailable=false;assert(!calculate_btf_link_compat(LEGACY,&unavailable)&&!unavailable);
struct kpm_btf b={&object,host_find,host_type,host_name,host_size};struct btf_type*ops=(void*)kpm_btf_type(&b,"inode_operations",4);struct btf_member*m=(void*)(ops+1);unsigned count=0;
for(unsigned i=0;i<(ops->info&65535);i++){const char*n=host_name(&object,m[i].name_off);if(!strcmp(n,"lookup"))continue;u32 saved=m[i].offset;m[i].offset+=64;assert(calculate_btf_link_compat(LEGACY,&unavailable)<0);m[i].offset=saved;count++;}
struct btf_type*pr=(void*)nm_btf_callback_prototype(&b,ops,LEGACY?"follow_link":"get_link");u32 saved=pr->info;pr->info=(pr->info&~65535U)|1;assert(calculate_btf_link_compat(LEGACY,&unavailable)==-EOPNOTSUPP);pr->info=saved;
const struct btf_type*fn=kpm_btf_type(&b,"generic_readlink",12);pr=(void*)host_type(&object,fn->size);saved=pr->info;pr->info=(pr->info&~65535U)|2;assert(calculate_btf_link_compat(LEGACY,&unavailable)==-EOPNOTSUPP);pr->info=saved;
struct_offset.permission_abi=1;assert(calculate_btf_link_compat(LEGACY,&unavailable)==-EINVAL);struct_offset.permission_abi=0;assert(!calculate_btf_link_compat(LEGACY,&unavailable));free(blob);printf("compat prefix %u field mutations + 3 ABI/shape negatives PASS\n",count);return 0;}
'''.replace('GETATTR','144' if legacy else '128').replace('LEGACY','true' if legacy else 'false')
  source=pre+common+'\nstatic const u32 records[]={'+','.join(map(str,records))+'};\n'+f'static const u32 string_start={strings},string_length={len(blob)-strings};\n'+host.HOST+lookup+header+offsets+(ROOT/'nomount/nm_btf.c').read_text()+test
  (out/'btf.c').write_text(source);run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log');run([str((out/'btf').resolve()),str((out/'input.btf').resolve())],out/'run.log')
  rows.append({'btf':'follow' if legacy else 'get','result':(out/'run.log').read_text().strip()})
 print(json.dumps(rows,indent=2));(a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
