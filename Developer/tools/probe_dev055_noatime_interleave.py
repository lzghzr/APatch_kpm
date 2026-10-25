#!/usr/bin/env python3
"""从真实setfl/owner函数复现前置新增检查与另一次F_SETFL清位的交错。"""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'nomount/tools'))
from test_directory_abis import function
from test_file_control import run
PRE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
struct user_namespace {int unused;};
struct inode {unsigned i_uid,i_mode;};
struct ops {int(*check_flags)(int);int(*fasync)(int,void*,int);};
struct aops {void*direct_IO;};
struct mapping {struct aops*a_ops;};
struct file {struct inode*inode;unsigned f_flags;struct ops*f_op;struct mapping*f_mapping;bool f_lock;};
static unsigned fsuid=1000;
#define file_inode(f) ((f)->inode)
#define IS_APPEND(i) 0
#define S_ISFIFO(m) (((m)&0170000)==0010000)
#define uid_eq(a,b) ((a)==(b))
#define current_fsuid() fsuid
#define current_user_ns() ((struct user_namespace*)0)
#define kuid_has_mapping(n,u) ((void)(n),(void)(u),0)
#define ns_capable(n,c) 0
#define CAP_FOWNER 3
static void spin_lock(bool*l){assert(!*l);*l=true;}
static void spin_unlock(bool*l){assert(*l);*l=false;}
'''
TEST=r'''
// 候选前置检查：以此刻f_flags区分新增与保留；仅用于反例，不接入生产。
static int proposed_guard(struct file*f,unsigned arg){return (arg&O_NOATIME)&&!(f->f_flags&O_NOATIME)?-EOPNOTSUPP:0;}
int main(void){
 struct inode outer={.i_uid=1000,.i_mode=0100644},source={.i_uid=2000,.i_mode=0100644};
 struct ops ops={0};struct file f={.inode=&outer,.f_op=&ops};
 assert(proposed_guard(&f,O_NOATIME)==-EOPNOTSUPP&&!f.f_flags);
 assert(inode_owner_or_capable(&outer)&&!inode_owner_or_capable(&source));
 f.f_flags=O_NOATIME|O_NONBLOCK;
 unsigned requested=O_NOATIME|O_NONBLOCK;
 assert(!proposed_guard(&f,requested)); // A：目前仅保留已有位，放行。
 assert(!proposed_guard(&f,O_NONBLOCK));
 assert(!setfl(9,&f,O_NONBLOCK)&&!(f.f_flags&O_NOATIME)); // B：完整原生清位。
 assert(!setfl(9,&f,requested)&&(f.f_flags&O_NOATIME)); // A：旧owner通过后重新增加。
 assert(!f.f_lock);
 puts("counterexample PASS: precheck allowed retain; native B cleared; native A added using stale outer owner");
 return 0;
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('native-fcntl','native-inode','flags-header','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 fcntl=a.native_fcntl.read_text();inode=a.native_inode.read_text().replace('bool inode_owner_or_capable(', 'static bool inode_owner_or_capable(',1)
 names={'O_APPEND','O_NONBLOCK','O_NDELAY','O_DIRECT','O_NOATIME','FASYNC'}
 flags=[]
 for line in a.flags_header.read_text().splitlines():
  if re.match(r'#define\s+(\w+)',line) and line.split()[1] in names:flags.append(line)
 assert len(flags)==6
 mask=re.search(r'^#define SETFL_MASK .+$',fcntl,re.M).group()
 source=PRE+'\n'+'\n'.join(flags)+'\n'+mask+'\n'+function(inode,'inode_owner_or_capable')+'\n'+function(fcntl,'setfl')+'\n'+TEST
 (a.output/'probe.c').write_text(source)
 run(['/usr/bin/clang','-Wall','-Werror','-fsanitize=address,undefined',str(a.output/'probe.c'),'-o',str(a.output/'probe')],a.output/'compile.log')
 run([str((a.output/'probe').resolve())],a.output/'run.log')
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer deterministic interleaving of extracted native functions with field/lock/capability scaffolding; no target syscall or concurrent kernel execution','native_bodies':['setfl','inode_owner_or_capable'],'result':'counterexample reproduced','production_hook_installed':False},indent=2)+'\n')
 print((a.output/'run.log').read_text())
if __name__=='__main__':main()
