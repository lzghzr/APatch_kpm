#!/usr/bin/env python3
"""保留8份BTF读取族断言，追加独立ACL入口存在性与精确签名检查。"""
import argparse,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 struct btf_type*f=(void*)kpm_btf_type(&b,"do_get_acl",12);int expected=f?1:0;
 assert(calculate_btf_xattr_acl(2,&unavailable)==expected&&!unavailable);
 if(f){
  struct btf_type*p=(void*)host_type(&object,f->size);struct btf_param*args=(void*)(p+1);u32 saved;
  assert(calculate_btf_xattr_acl(0,&unavailable)==-EOPNOTSUPP);
  saved=p->info;p->info=(saved&~65535U)|4;assert(calculate_btf_xattr_acl(2,&unavailable)==-EOPNOTSUPP);p->info=saved;
  saved=args[0].type;args[0].type=args[1].type;assert(calculate_btf_xattr_acl(2,&unavailable)==-EOPNOTSUPP);args[0].type=saved;
  saved=args[1].type;args[1].type=p->size;assert(calculate_btf_xattr_acl(2,&unavailable)==-EOPNOTSUPP);args[1].type=saved;
  saved=p->size;p->size=args[0].type;assert(calculate_btf_xattr_acl(2,&unavailable)==-EOPNOTSUPP);p->size=saved;
  saved=args[4].type;args[4].type=args[0].type;assert(calculate_btf_xattr_acl(2,&unavailable)==-EOPNOTSUPP);args[4].type=saved;
  saved=f->name_off;f->name_off=0;assert(!calculate_btf_xattr_acl(2,&unavailable));f->name_off=saved;
 }
 api_mode=1;assert(calculate_btf_xattr_acl(2,&unavailable)==-ENODATA&&unavailable);api_mode=2;assert(calculate_btf_xattr_acl(2,&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(calculate_btf_xattr_acl(2,&unavailable)==expected&&!unavailable);printf("independent ACL entry=%d; present: 6 signature negatives; 2 API boundaries PASS\n",expected);
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,nargs='+',required=True);p.add_argument('--blobs',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert len(a.blobs)==len(a.fixtures);a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for n,path in enumerate(a.fixtures):
  source=(path/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source);assert source.count('free(blob);')==1
  source=source.replace('int main(int argc,char**argv)',function((ROOT/'nomount/nm_btf.c').read_text(),'calculate_btf_xattr_acl')+'\nint main(int argc,char**argv)',1).replace('free(blob);',TEST+'\nfree(blob);');assert re.findall(r'\bassert\s*\([^;]+\);',source)[:len(before)]==before
  out=a.output/f'btf-{n}';out.mkdir();(out/'btf.c').write_text(source);run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log')
  blob=a.blobs[n]
  run([str((out/'btf').resolve()),str(blob.resolve())],out/'run.log');rows.append({'fixture':str(path),'prior_assert_sites':len(before),'result':(out/'run.log').read_text().strip()})
 (a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');print(rows)
if __name__=='__main__':main()
