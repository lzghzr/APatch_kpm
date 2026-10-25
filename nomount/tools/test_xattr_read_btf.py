#!/usr/bin/env python3
"""真实BTF原断言后追加xattr读取入口、具名指针及原型拒绝检查。"""
import argparse,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
TEST=r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 struct btf_type*get=(void*)kpm_btf_type(&b,"vfs_getxattr",12),*list=(void*)kpm_btf_type(&b,"vfs_listxattr",12);assert(get&&list);
 struct btf_type*proto=(void*)host_type(&object,get->size);int context=!nm_btf_named_parameter(&b,proto,0,"dentry")?0:nm_btf_context_kind(&b,proto),count=proto->info&65535;
 assert(calculate_btf_xattr_read(context,&unavailable)==count&&!unavailable);
 assert(calculate_btf_xattr_read(context==0?1:0,&unavailable)==-EOPNOTSUPP);
 u32 saved=proto->info;proto->info=(saved&~65535U)|6;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);proto->info=saved;
 struct btf_param*args=(void*)(proto+1);unsigned at=context?1:0;saved=args[at].type;args[at].type=proto->size;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);args[at].type=saved;
 saved=args[count-1].type;args[count-1].type=args[at].type;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);args[count-1].type=saved;
 saved=proto->size;proto->size=args[at].type;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);proto->size=saved;
 struct btf_type*lp=(void*)host_type(&object,list->size);saved=lp->info;lp->info=(saved&~65535U)|2;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);lp->info=saved;
 saved=list->name_off;list->name_off=get->name_off;assert(calculate_btf_xattr_read(context,&unavailable)==-ENOENT);list->name_off=saved;
 if(context){saved=args[0].type;args[0].type=args[1].type;assert(calculate_btf_xattr_read(context,&unavailable)==-EOPNOTSUPP);args[0].type=saved;}
 api_mode=1;assert(calculate_btf_xattr_read(context,&unavailable)==-ENODATA&&unavailable);api_mode=2;assert(calculate_btf_xattr_read(context,&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(calculate_btf_xattr_read(context,&unavailable)==count&&!unavailable);printf("xattr native get args=%d context=%d/list args=3; 7 core negatives + mapped-context negative + 2 API boundaries PASS\n",count,context);
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 current=(ROOT/'nomount/nm_btf.c').read_text()
 for n,path in enumerate(a.fixtures):
  source=(path/'btf.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source);assert source.count('free(blob);')==1
  # 已生成夹具保留原断言，生产新函数在main前接入。
  source=source.replace('int main(int argc,char**argv)',function(current,'calculate_btf_xattr_read')+'\nint main(int argc,char**argv)',1)
  assert 'static int calculate_btf_xattr_read' in source
  source=source.replace('free(blob);',TEST+'\nfree(blob);');assert re.findall(r'\bassert\s*\([^;]+\);',source)[:len(before)]==before
  out=a.output/f'btf-{n}';out.mkdir();(out/'btf.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(out/'btf.c'),'-o',str(out/'btf')],out/'compile.log');run([str((out/'btf').resolve()),str((path/'input.btf').resolve())],out/'run.log')
  rows.append({'fixture':str(path),'prior_assert_sites':len(before),'result':(out/'run.log').read_text().strip()})
 (a.output/'receipt.json').write_text(json.dumps(rows,indent=2)+'\n');print(rows)
if __name__=='__main__':main()
