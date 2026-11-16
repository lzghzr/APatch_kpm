#!/usr/bin/env python3
"""生产虚拟目录枚举：索引移动、actor 间更新、seek/rewind 和 compat 边界。"""
import argparse
import subprocess
import sys
from pathlib import Path
from test_nomount_v230 import ROOT, compile_run, function

PRE=r'''
static char seen[32][256];static unsigned seen_count,capacity;static int edit;
static struct nm_directory_node*editing_node;
static struct nomount_child_array*replacement;
static int collect(struct nm_dir_context*c,const char*n,int len,int64_t off,u64 ino,unsigned type) {
 assert(!depth&&len<256&&off==c->pos);
 if(seen_count==capacity)return -ENOSPC;
 memcpy(seen[seen_count],n,len);seen[seen_count++][len]=0;
 if(edit){editing_node->children=replacement;edit=0;}
 return 0;
}
static bool collect_bool(struct nm_dir_context*c,const char*n,int len,int64_t off,u64 ino,unsigned type) {
 return !collect(c,n,len,off,ino,type);
}
static void read_view(struct nm_directory_node*n,struct nm_dir_context*c,unsigned cap) {
 capacity=cap;seen_count=0;
 if(struct_offset.dir_actor_abi)c->actor_bool=collect_bool;else c->actor=collect;
 assert(!nm_emit_children(n,c,0,false));
}
static void attach(struct nomount_child_array*a,unsigned i,struct nomount_leaf*l,u32 hash){
 nm_entries(a)[i]=(struct nm_child){hash,0,l};
}
int main(void) {
 assert(!rules_oracle_main());
 struct nomount_leaf*a=alloc_leaf("/a"),*b=alloc_leaf("/b"),*c=alloc_leaf("/c"),*x=alloc_leaf("/x");
 struct nomount_leaf*leaves[]={a,b,c,x};struct nm_rule_updates updates={0};
 for(unsigned i=0;i<4;i++)assert(!nm_set_leaf_rule(leaves[i],alloc_rule(0,0),&updates));
 struct nomount_child_array*abc=nm_alloc_children(3),*xabc=nm_alloc_children(4),*bc=nm_alloc_children(2),*ac=nm_alloc_children(2);
 attach(abc,0,a,0x11110001);attach(abc,1,b,0x22220001);attach(abc,2,c,0x33330001);
 attach(xabc,0,x,0x01010001);for(unsigned i=0;i<3;i++)nm_entries(xabc)[i+1]=nm_entries(abc)[i];
 nm_entries(bc)[0]=nm_entries(abc)[1];nm_entries(bc)[1]=nm_entries(abc)[2];
 nm_entries(ac)[0]=nm_entries(abc)[0];nm_entries(ac)[1]=nm_entries(abc)[2];
 struct nm_directory_node node={.children=abc};editing_node=&node;
 for(unsigned abi=0;abi<2;abi++) {
  struct_offset.dir_actor_abi=abi;struct nm_dir_context ctx={0};
  node.children=abc;read_view(&node,&ctx,1);assert(seen_count==1&&!strcmp(seen[0],"a"));
  int64_t saved=ctx.pos;assert(nm_virtual_position(saved,false));
  node.children=xabc;read_view(&node,&ctx,32);assert(seen_count==2&&!strcmp(seen[0],"b")&&!strcmp(seen[1],"c"));
  ctx.pos=saved;node.children=bc;read_view(&node,&ctx,32);assert(seen_count==2&&!strcmp(seen[0],"b"));
  ctx.pos=0;node.children=abc;replacement=xabc;edit=1;read_view(&node,&ctx,32);
  assert(seen_count==3&&!strcmp(seen[0],"a")&&!strcmp(seen[1],"b")&&!strcmp(seen[2],"c"));
  ctx.pos=0;node.children=abc;read_view(&node,&ctx,0);assert(!seen_count);
  read_view(&node,&ctx,32);assert(seen_count==3&&!strcmp(seen[0],"a"));
  // 删除恢复锚点、片段碰撞和零片段保持上游 best-effort，但必须有界结束。
  ctx.pos=saved;node.children=ac;
  read_view(&node,&ctx,32);assert(seen_count<=3);
  assert(seen_count==1&&!strcmp(seen[0],"c"));node.children=abc;
  ctx.pos=nm_directory_cookie(0,0x22220001,false);read_view(&node,&ctx,32);assert(seen_count==2);
  nm_entries(abc)[0].hash=0x22220002;ctx.pos=nm_directory_cookie(0,0x22220001,false);
  read_view(&node,&ctx,32);assert(seen_count==3);nm_entries(abc)[0].hash=0x11110001;
  ctx.pos=nm_directory_cookie(1,0,false);read_view(&node,&ctx,32);assert(seen_count==2);
  ctx.pos=nm_directory_position(1,true);capacity=32;seen_count=0;
  assert(!nm_emit_children(&node,&ctx,0,true)&&seen_count==2&&ctx.pos==nm_directory_position(3,true));
  abc->count=0x10000;ctx.pos=nm_directory_position(0,true);
  assert(nm_emit_children(&node,&ctx,0,true)==-EOVERFLOW);abc->count=3;
 }
 nm_free(abc);nm_free(xabc);nm_free(bc);nm_free(ac);
 for(unsigned i=0;i<4;i++)release_leaf(leaves[i]);flush_callbacks();
 assert(!path_refs&&allocated==released&&!depth);
 puts("PASS int/bool: insertion/removal before cursor, actor update, rewind, full buffer, collision/zero/deleted anchor, compat overflow");return 0;
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 subprocess.run([sys.executable,str(ROOT/'nomount/tools/test_rules.py'),'--symbols',str(a.symbols),'--output',str(a.output/'oracle')],check=True)
 source=(a.output/'oracle/rules.c').read_text().replace('#include "nm_structs.h"','').replace('int main(void) {','int rules_oracle_main(void) {')
 source+=function('nomount/nm_offsets.c','nm_dir_emit')+(ROOT/'nomount/nm_directory_nodes.c').read_text()+PRE
 compile_run(source,a.output/'cursor')
if __name__=='__main__':main()
