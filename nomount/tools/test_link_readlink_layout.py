#!/usr/bin/env python3
"""在已通过的真实/合成BTF夹具后追加源readlink检查，并编译plain前部。"""
import argparse,json,re
from pathlib import Path
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
EXTRA=r'''
{
 struct kpm_btf sr_b={&object,host_find,host_type,host_name,host_size};bool sr_unavailable=false;
 struct btf_type*sr_ops=(void*)kpm_btf_type(&sr_b,"inode_operations",4);assert(sr_ops);
 int sr_slot=kpm_btf_offset(&sr_b,sr_ops,"readlink",8);assert(sr_slot>=0&&!calculate_btf_source_readlink(sr_slot,&sr_unavailable));
 assert(calculate_btf_source_readlink(sr_slot+8,&sr_unavailable)==-EINVAL);
 struct btf_member*sr_members=(void*)(sr_ops+1);unsigned sr_checked=0;
 for(unsigned sr_i=0;sr_i<(sr_ops->info&65535);sr_i++){
  if(strcmp(host_name(&object,sr_members[sr_i].name_off),"readlink"))continue;
  u32 sr_saved=sr_members[sr_i].offset;sr_members[sr_i].offset+=64;assert(calculate_btf_source_readlink(sr_slot,&sr_unavailable)==-EINVAL);sr_members[sr_i].offset=sr_saved;
  sr_saved=sr_members[sr_i].name_off;sr_members[sr_i].name_off=sr_ops->name_off;assert(calculate_btf_source_readlink(sr_slot,&sr_unavailable)==-ENOENT);sr_members[sr_i].name_off=sr_saved;
  struct btf_type*sr_proto=(void*)nm_btf_callback_prototype(&sr_b,sr_ops,"readlink");sr_saved=sr_proto->info;sr_proto->info=(sr_proto->info&~65535U)|2;assert(calculate_btf_source_readlink(sr_slot,&sr_unavailable)==-EOPNOTSUPP);sr_proto->info=sr_saved;
  sr_checked++;
 }
 assert(sr_checked==1&&!calculate_btf_source_readlink(sr_slot,&sr_unavailable));
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,nargs='+',required=True);p.add_argument('--headers',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for n,path in enumerate(a.fixtures):
  source=(path/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source);assert source.count('free(blob);')==1
  source=source.replace('free(blob);',EXTRA+'\nfree(blob);');after=re.findall(r'\bassert\s*\([^;]+\);',source);assert after[:len(before)]==before
  out=a.output/f'btf-{n}';out.mkdir();(out/'btf.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log');run([str((out/'btf').resolve()),str((path/'input.btf').resolve())],out/'run.log')
  rows.append({'fixture':str(path),'existing_assert_sites_preserved':len(before),'new_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',EXTRA)),'source_readlink_negatives':4,'result':'PASS'})
 for n,path in enumerate(a.headers):
  body=path.read_text().split('struct inode_operations {',1)[1].split('};',1)[0];body=body[:body.index(';',body.index('(*getattr)'))+1];assert '(*permission2)' not in body
  members=re.findall(r'\(\s*\*\s*(\w+)\s*\)',body);head=(ROOT/'nomount/nm_structs.h').read_text()
  source='typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef long int64_t;typedef _Bool bool;\n#define offsetof(T,F) __builtin_offsetof(T,F)\n'+head+'struct reference{'+''.join('void*'+m+';' for m in members)+'};\n'
  for m in members:
   mine='hardlink' if m=='link' else 'link.'+m if m in ('lookup','get_link') else m
   source+=f'_Static_assert(offsetof(struct reference,{m})==offsetof(struct nm_inode_plain_link_prefix,{mine}),"{m}");\n'
  out=a.output/f'plain-{n}.c';out.write_text(source);run(['/usr/bin/clang','--target=aarch64-none-elf','-fsyntax-only',str(out)],a.output/f'plain-{n}.log');rows.append({'header':str(path),'asserts':len(members),'result':'PASS'})
 print(json.dumps(rows,indent=2));(a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
