#!/usr/bin/env python3
"""在本轮生成夹具后追加12配置接入；仅Developer自检。"""
import argparse,json,re,subprocess
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--cli-source',type=Path,required=True);p.add_argument('--configs',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 source=a.fixture.read_text();before=re.findall(r'\bassert\s*\([^;]+\);',source);source=source.replace('int main(void){nm_xattr_resident=true;', 'static int prior_matrix_main(void){nm_xattr_resident=true;',1)
 body='\nint main(void){assert(!prior_matrix_main());\n';rows=[]
 for config in a.configs:
  values=json.loads(config.read_text())['offsets'];context=values['getattr_context_kind'];assert context in (0,1)
  body+='struct_offset=(struct struct_offset){'+','.join(f'.{k}={v}' for k,v in values.items())+'};xr_reset();nm_xattr_resident=true;assert(!nm_activate_xattr_reads_locked());assert(xr_wrap_calls==2&&xr_count==2&&nm_xattr_get_args=='+str(5 if context else 4)+');\n'
  rows.append({'config':str(config),'get_args':5 if context else 4,'list_args':3,'result':'PASS'})
 body+='puts("12 static config xattr activation profiles PASS");return 0;}\n';assert re.findall(r'\bassert\s*\([^;]+\);',source)==before;source+=body
 def run(c,log):
  r=subprocess.run(c,text=True,capture_output=True);log.write_text(r.stdout+r.stderr);r.check_returncode()
 (a.output/'configs.c').write_text(source);run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I','nomount','-fsanitize=address,undefined',str(a.output/'configs.c'),str(a.cli_source),'-o',str(a.output/'configs')],a.output/'compile.log');run([str((a.output/'configs').resolve())],a.output/'run.log')
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer static signature contract activation, each mocked config is a separate instance; not real hook install/uninstall','prior_assert_sites':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',body)),'profiles':rows},indent=2)+'\n');print(len(rows),'profiles PASS')
if __name__=='__main__':main()
