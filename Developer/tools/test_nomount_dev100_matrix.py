#!/usr/bin/env python3
"""DEV-100：生产回调参数/标志组合与四个 hook 失败位置的宿主补充检查。"""
import argparse
from pathlib import Path
from test_nomount_v230 import ROOT, PRE, compile_run

TEST = r'''
int main(void) {
 struct inode real={0},virtual={.virtual=true};
 struct dentry native={&real},fake={&virtual},negative={0};
 unsigned cases=0,native_calls=0;
 // Flags 0/NOREPLACE/EXCHANGE/WHITEOUT and combinations: the security hook
 // must not use flags to bypass the actual inode checks. Invalid combinations
 // are normally rejected by the VFS before this entry.
 for(unsigned flags=0;flags<8;flags++)for(unsigned mask=0;mask<16;mask++) {
  hook_fargs5_t a={.arg0=(uintptr_t)(mask&1?&virtual:&real),
   .arg1=(uintptr_t)(mask&2?&fake:&native),.arg2=(uintptr_t)(mask&4?&virtual:&real),
   .arg3=(uintptr_t)(mask&8?&fake:&native),.arg4=flags};
  hook_fargs5_t before=a;unsigned prior=native_calls;
  nm_mutation_rename(&a,NULL);if(!a.skip_origin)native_calls++;
  if(mask)assert(a.skip_origin&&(int)a.ret==-EPERM&&native_calls==prior);
  else assert(!memcmp(&a,&before,sizeof(a))&&native_calls==prior+1);
  cases++;
 }
 for(unsigned mask=0;mask<4;mask++) {
  hook_fargs2_t a={.arg0=(uintptr_t)(mask&1?&virtual:&real),.arg1=(uintptr_t)(mask&2?&fake:&native)};
  hook_fargs2_t before=a;nm_mutation_remove(&a,NULL);
  if(mask)assert(a.skip_origin&&(int)a.ret==-EPERM);else assert(!memcmp(&a,&before,sizeof(a)));
  hook_fargs3_t b={.arg0=(uintptr_t)(mask&1?&fake:&native),.arg1=(uintptr_t)(mask&2?&virtual:&real),.arg2=(uintptr_t)&negative};
  hook_fargs3_t prior=b;nm_mutation_link(&b,NULL);
  if(mask)assert(b.skip_origin&&(int)b.ret==-EPERM);else assert(!memcmp(&b,&prior,sizeof(b)));
  cases+=2;
 }
 for(unsigned stage=1;stage<=4;stage++) {
  memset(nm_mutation_installed,0,sizeof(nm_mutation_installed));
  memset(nm_mutation_targets,0,sizeof(nm_mutation_targets));nm_mutation_ready=false;
  nm_xattr_resident=true;btf_rc=0;btf_missing=false;missing=0;fail_hook=stage;hook_calls=0;
  assert(nm_activate_mutation_guards_locked()==-EINVAL&&!nm_mutation_ready);
  assert(hook_calls==stage&&allocations==0);
  for(unsigned i=0;i<4;i++)assert(nm_mutation_installed[i]==(i<stage-1));
  fail_hook=0;assert(!nm_activate_mutation_guards_locked()&&nm_mutation_ready&&hook_calls==5);
  assert(!nm_activate_mutation_guards_locked()&&hook_calls==5);
  cases++;
 }
 printf("PASS %u mutation/activation cases; original callbacks compiled with ASan/UBSan\n",cases);
 return 0;
}
'''

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    compile_run(PRE+(ROOT/'nomount/nm_mutation.c').read_text()+TEST,args.output/'mutation')
