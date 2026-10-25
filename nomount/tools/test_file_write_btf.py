#!/usr/bin/env python3
"""8份BTF保留旧断言，追加write_iter槽位/签名与查询失败反例。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 struct btf_type*ops=(void*)kpm_btf_type(&b,"file_operations",4);assert(ops);
 int slot=kpm_btf_offset(&b,ops,"write_iter",8);int expected=slot==(int)offsetof(struct nm_file_io_ops,write_iter)?0:-EINVAL;
 assert(calculate_btf_file_write(&unavailable)==expected&&!unavailable);
 struct btf_type*p=(void*)nm_btf_callback_prototype(&b,ops,"write_iter");assert(p);
 struct btf_param*a=(void*)(p+1);u32 saved=p->info;p->info=(saved&~65535U)|1;
 assert(calculate_btf_file_write(&unavailable)==-EOPNOTSUPP);p->info=saved;
 saved=p->size;p->size=a[0].type;assert(calculate_btf_file_write(&unavailable)==-EOPNOTSUPP);p->size=saved;
 saved=a[0].type;a[0].type=a[1].type;assert(calculate_btf_file_write(&unavailable)==(expected?-EINVAL:-EOPNOTSUPP));a[0].type=saved;
 saved=a[1].type;a[1].type=a[0].type;assert(calculate_btf_file_write(&unavailable)==(expected?-EINVAL:-EOPNOTSUPP));a[1].type=saved;
 struct btf_member*m=(void*)(ops+1);unsigned hit=0;
 for(unsigned i=0;i<(ops->info&65535);i++)if(!strcmp(host_name(&object,m[i].name_off),"write_iter")){
  saved=m[i].offset;m[i].offset+=64;assert(calculate_btf_file_write(&unavailable)==-EINVAL);m[i].offset=saved;
  saved=m[i].name_off;m[i].name_off=m[4].name_off;assert(calculate_btf_file_write(&unavailable)==-ENOENT);m[i].name_off=saved;hit++;
 }assert(hit==1);
 api_mode=1;assert(calculate_btf_file_write(&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_file_write(&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(calculate_btf_file_write(&unavailable)==expected);printf("write_iter @%d, common-layout result=%d: 6 layout/signature negatives + 2 API boundaries PASS\n",slot,expected);
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,nargs='+',required=True);p.add_argument('--blobs',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 assert len(a.fixtures)==len(a.blobs)==8;a.output.mkdir(parents=True,exist_ok=False);rows=[]
 query=function((ROOT/'nomount/nm_btf.c').read_text(),'calculate_btf_file_write')
 for i,(f,b)in enumerate(zip(a.fixtures,a.blobs)):
  original=(f/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',original);assert len(before)==78
  source=original.replace('int main(int argc,char**argv)',query+'\nint main(int argc,char**argv)',1).replace('free(blob);',TEST+'\nfree(blob);',1)
  after=re.findall(r'\bassert\s*\([^;]+\);',source);assert after[:len(before)]==before
  out=a.output/f'btf-{i}';out.mkdir();(out/'btf.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log')
  run([str((out/'btf').resolve()),str(b.resolve())],out/'run.log')
  rows.append({'index':i,'prior_assert_sites':len(before),'added_assert_sites':len(after)-len(before),'result':(out/'run.log').read_text().strip()})
 (a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');print(rows)
if __name__=='__main__':main()
