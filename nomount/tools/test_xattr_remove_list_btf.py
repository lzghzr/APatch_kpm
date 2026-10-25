#!/usr/bin/env python3
"""8份真实BTF：追加remove二/三参与内部list三参的签名正反核对。"""
import argparse,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 const struct btf_type*fn=kpm_btf_type(&b,"vfs_removexattr",12);assert(fn);
 struct btf_type*proto=(void*)host_type(&object,fn->size);
 int context=!nm_btf_named_parameter(&b,proto,0,"dentry")?0:nm_btf_context_kind(&b,proto);
 assert(!calculate_btf_xattr_remove(context,&unavailable)&&!unavailable);
 assert(calculate_btf_xattr_remove(context?0:1,&unavailable)==-EOPNOTSUPP);
 struct btf_param*args=(void*)(proto+1);u32 n=proto->info&65535,saved=proto->info;
 proto->info=(saved&~65535U)|5;assert(calculate_btf_xattr_remove(context,&unavailable)==-EOPNOTSUPP);proto->info=saved;
 saved=args[!!context].type;args[!!context].type=proto->size;assert(calculate_btf_xattr_remove(context,&unavailable)==-EOPNOTSUPP);args[!!context].type=saved;
 if(context){saved=args[0].type;args[0].type=args[1].type;assert(calculate_btf_xattr_remove(context,&unavailable)==-EOPNOTSUPP);args[0].type=saved;}
 struct btf_type*list=(void*)kpm_btf_type(&b,"listxattr",12);assert(list);
 struct btf_type*lp=(void*)host_type(&object,list->size);struct btf_param*la=(void*)(lp+1);
 assert(!calculate_btf_xattr_internal_list(&unavailable)&&!unavailable);
 saved=lp->info;lp->info=(saved&~65535U)|2;assert(calculate_btf_xattr_internal_list(&unavailable)==-EOPNOTSUPP);lp->info=saved;
 saved=la[0].type;la[0].type=lp->size;assert(calculate_btf_xattr_internal_list(&unavailable)==-EOPNOTSUPP);la[0].type=saved;
 saved=la[2].type;la[2].type=la[0].type;assert(calculate_btf_xattr_internal_list(&unavailable)==-EOPNOTSUPP);la[2].type=saved;
 saved=lp->size;lp->size=la[0].type;assert(calculate_btf_xattr_internal_list(&unavailable)==-EOPNOTSUPP);lp->size=saved;
 struct btf_type*acl=(void*)kpm_btf_type(&b,"vfs_remove_acl",12);int aclexpected=acl?1:0;
 assert(calculate_btf_xattr_remove_acl(context,&unavailable)==aclexpected);
 if(acl){
  struct btf_type*ap=(void*)host_type(&object,acl->size);struct btf_param*aa=(void*)(ap+1);
  saved=ap->info;ap->info=(saved&~65535U)|2;assert(calculate_btf_xattr_remove_acl(context,&unavailable)==-EOPNOTSUPP);ap->info=saved;
  saved=aa[0].type;aa[0].type=aa[1].type;assert(calculate_btf_xattr_remove_acl(context,&unavailable)==-EOPNOTSUPP);aa[0].type=saved;
 }
 printf("independent ACL remove=%d; ",aclexpected);
 api_mode=1;assert(calculate_btf_xattr_remove(context,&unavailable)==-ENODATA&&unavailable);assert(calculate_btf_xattr_internal_list(&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_xattr_remove(context,&unavailable)==-ENODATA&&!unavailable);assert(calculate_btf_xattr_internal_list(&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(!calculate_btf_xattr_remove(context,&unavailable)&&!calculate_btf_xattr_internal_list(&unavailable));
 printf("remove argc=%u context=%d / internal-list3: real BTF signature negatives and API boundaries PASS\n",n,context);
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',nargs='+',type=Path,required=True);p.add_argument('--blobs',nargs='+',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert len(a.fixtures)==len(a.blobs)==8;a.output.mkdir(parents=True,exist_ok=False);rows=[]
 current=(ROOT/'nomount/nm_btf.c').read_text();query='\n'.join(function(current,n)for n in ('calculate_btf_xattr_remove','calculate_btf_xattr_internal_list','calculate_btf_xattr_remove_acl'))
 for i,(f,b)in enumerate(zip(a.fixtures,a.blobs)):
  source=(f/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source);assert source.count('free(blob);')==1
  source=source.replace('int main(int argc,char**argv)',query+'\nint main(int argc,char**argv)',1).replace('free(blob);',TEST+'\nfree(blob);',1)
  assert re.findall(r'\bassert\s*\([^;]+\);',source)[:len(before)]==before
  out=a.output/f'btf-{i}';out.mkdir();(out/'btf.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log');run([str((out/'btf').resolve()),str(b.resolve())],out/'run.log')
  rows.append({'index':i,'prior_assert_sites':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',source))-len(before),'result':(out/'run.log').read_text().strip()})
 (a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');print('8 BTF remove/internal-list signatures PASS')
if __name__=='__main__':main()
