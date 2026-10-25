#!/usr/bin/env python3
"""DEV-055：8份真实BTF追加permission/generic的独立签名与拒绝。"""
import argparse,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;int slot=-1,second=-1;
 assert(!calculate_btf_backing_inode_abi(&unavailable)&&!unavailable);
 int abi=struct_offset.permission_abi;
 struct btf_type*ops=(void*)kpm_btf_type(&b,"inode_operations",4);
 assert(ops&&!calculate_btf_owned_permission(&unavailable,&slot,&second));
 assert(slot==kpm_btf_offset(&b,ops,"permission",8)&&second==(abi? -1:kpm_btf_offset(&b,ops,"permission2",8)));
 u32 saved_size=ops->size;ops->size=8;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EINVAL);ops->size=saved_size;
 struct btf_type*proto=(void*)nm_btf_callback_prototype(&b,ops,"permission");
 struct btf_param*args=(void*)(proto+1);unsigned n=proto->info&65535;u32 saved=proto->info;
 proto->info=(saved&~65535U)|5;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);proto->info=saved;
 saved=args[n-2].type;args[n-2].type=proto->size;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);args[n-2].type=saved;
 if(abi>=2){saved=args[0].type;args[0].type=args[1].type;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);args[0].type=saved;}
 struct btf_type*fn=(void*)kpm_btf_type(&b,"generic_permission",12);assert(fn);proto=(void*)host_type(&object,fn->size);args=(void*)(proto+1);n=proto->info&65535;
 saved=proto->info;proto->info=(saved&~65535U)|(n+1);assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);proto->info=saved;
 saved=args[n-1].type;args[n-1].type=args[n-2].type;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);args[n-1].type=saved;
 saved=proto->size;proto->size=args[n-2].type;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);proto->size=saved;
 if(abi>=2){saved=args[0].type;args[0].type=args[1].type;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-EOPNOTSUPP);args[0].type=saved;}
 api_mode=1;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_owned_permission(&unavailable,&slot,&second)==-ENODATA&&!unavailable);api_mode=0;
 assert(!calculate_btf_owned_permission(&unavailable,&slot,&second));
 printf("permission ABI=%d callback slot=%d secondary=%d; native generic and callback type negatives PASS\n",abi,slot,second);
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--blobs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 query=function((ROOT/'nomount/nm_btf.c').read_text(),'calculate_btf_owned_permission')
 for i in range(8):
  source=(a.fixtures/f'btf-{i}'/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source)
  source=source.replace('int main(int argc,char**argv)',query+'\nint main(int argc,char**argv)',1).replace('free(blob);',TEST+'\nfree(blob);',1)
  assert re.findall(r'\bassert\s*\([^;]+\);',source)[:len(before)]==before
  out=a.output/f'btf-{i}';out.mkdir();(out/'btf.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log')
  run([str((out/'btf').resolve()),str((a.blobs/f'btf-{i}'/'input.btf').resolve())],out/'run.log')
  rows.append({'index':i,'retained_assert_sites':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',source))-len(before),'result':(out/'run.log').read_text().strip()})
 (a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');print('8 BTF permission/generic signatures PASS')
if __name__=='__main__':main()
