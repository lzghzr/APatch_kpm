#!/usr/bin/env python3
"""虚拟 backing 入口：生产规则、身份访问器及规则 Oracle，自检不替代真机。"""
import argparse
import subprocess
import sys
from pathlib import Path
from test_nomount_v230 import ROOT, compile_run, function

TEST = r'''
static struct {void*inode_ops;void*directory_ops;void*symlink_ops;} nm_inode_engine;
'''
CASES = r'''
int main(void) {
 assert(!rules_oracle_main());
 struct fixture_inode {struct nm_inode_owner_prefix owner;struct nm_inode_ops_mapping objects;} source={0};
 struct_offset.inode_superblock=offsetof(struct fixture_inode,objects.i_sb);
 int file_ops,dir_ops,link_ops,native_ops,proxy_ops;
 nm_inode_engine.inode_ops=&file_ops;nm_inode_engine.directory_ops=&dir_ops;nm_inode_engine.symlink_ops=&link_ops;
 nm_rule_inode_is_virtual=nm_is_virtual_inode;
 file_dentry.d_inode=(void*)&source;
 const void*ops[]={&file_ops,&dir_ops,&link_ops,&native_ops,&proxy_ops,NULL};
 for(unsigned i=0;i<6;i++)for(unsigned directory=0;directory<2;directory++) {
  source.owner.i_mode=directory?0040755:0100644;source.objects.i_op=ops[i];
  int before=path_puts;
  struct nomount_rule*r=nm_alloc_rule("/data/file",10,0,0);
  if(i<3) {assert(IS_ERR(r)&&PTR_ERR(r)==-ELOOP);assert(!path_refs&&path_puts==before+1);}
  else {assert(!IS_ERR(r));assert(!!(r->flags&NM_FLAG_IS_DIR)==directory);nm_rule_put(r);}
  assert(!path_refs&&allocated==released);
 }
 source.objects.i_op=&file_ops;
 struct nomount_rule*r=nm_alloc_rule(NULL,0,NM_FLAG_WHITEOUT,0);assert(!IS_ERR(r));nm_rule_put(r);
 r=nm_alloc_rule(NULL,0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);assert(!IS_ERR(r));nm_rule_put(r);
 assert(!path_refs&&allocated==released);
 puts("PASS: virtual file/directory/link rejected; native/proxied directory permitted; path refs balanced; source-less rules preserved");
 return 0;
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--symbols',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 subprocess.run([sys.executable,str(ROOT/'nomount/tools/test_rules.py'),'--symbols',str(a.symbols),'--output',str(a.output/'oracle')],check=True)
 source=(a.output/'oracle/rules.c').read_text().replace('#include "nm_structs.h"', '').replace('int main(void) {','int rules_oracle_main(void) {')+TEST
 for name in ('nm_inode_objects','nm_inode_ops'):
  source+=function('nomount/nm_offsets.c',name)
 for name in ('nm_is_file_inode','nm_is_directory_inode','nm_is_symlink_inode','nm_is_virtual_inode'):
  source+=function('nomount/nm_inode.c',name)
 prepare=function('nomount/nm_inode.c','nm_prepare_inode_engine')
 assert 'nm_rule_inode_is_virtual = nm_is_virtual_inode;' in prepare
 for mode in ('dynamic','static'):
  compile_run(('#define CONFIG_KPM_BASELINES 1\n' if mode=='static' else '')+source+CASES,a.output/mode)
if __name__=='__main__':main()
