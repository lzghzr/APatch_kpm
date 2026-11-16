#!/usr/bin/env python3
"""TST-004：实际拓扑发布与物化入口的目标 tmpfs 边界，宿主自检。"""
import argparse
import json
from pathlib import Path
import re
import sys
import test_nomount_failure_scope as scope
from test_nomount_v230 import function, compile_run

TOPOLOGY = r'''
static int add_directory(const char *path,unsigned flags) {
 struct nomount_rule*r=nm_alloc_rule(flags&NM_FLAG_VIRTUAL_DIR?NULL:"/data/dir",flags&NM_FLAG_VIRTUAL_DIR?0:9,flags,0);
 assert(!IS_ERR(r));struct nm_topology_updates u={0};
 int rc=nm_topology_add_locked(path,strlen(path),r,&u);if(rc)nm_rule_put(r);nm_finish_topology_updates(&u);return rc;
}
int main(void) {
 assert(!original_scope_main());fail_stage=0;
 // Exact parent/automatic-chain shape of /dev/nmprobe/sub/x, using the existing host namespace.
 fixture_target_super.s_magic=0x01021994UL;
 assert(!add_request("/data/dir/retained",true));
 assert(add_request("/data/dir/nmprobe/sub/x",false)==-EOPNOTSUPP);
 assert(!has_path("/data/dir/nmprobe")&&!has_path("/data/dir/nmprobe/sub")&&!has_path("/data/dir/nmprobe/sub/x"));
 assert(add_request("/data/dir/regular",false)==-EOPNOTSUPP);
 assert(add_request("/data/dir/nmprobe/hidden",true)==-EOPNOTSUPP);
 for(unsigned i=0;i<3;i++) {
  unsigned f=NM_FLAG_IS_DIR|(i==0?NM_FLAG_VIRTUAL_DIR:i==1?0:NM_FLAG_OPAQUE);
  assert(add_directory("/data/dir/direct",f)==-EOPNOTSUPP);
 }
 // Direct whiteout remains usable; replacement cannot turn it into a real inode rule.
 assert(!add_request("/data/dir/retained",true));
 assert(add_request("/data/dir/retained",false)==-EOPNOTSUPP);
 assert(add_directory("/data/dir/retained",NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR)==-EOPNOTSUPP);
 assert(nm_topology_find("/data/dir/retained",18)->leaf->rules->rules[0]->flags==NM_FLAG_WHITEOUT);
 struct nm_topology_updates u={0};
 assert(!nm_topology_remove_locked("/data/dir/retained",18,0,&u));nm_finish_topology_updates(&u);clear_tree();
 // Other targets still publish, including ramfs. No filesystem-name/path heuristic.
 unsigned long good[]={0x858458f6UL,0xEF53UL,0xE0F5E1E2UL,0xF2F52010UL};
 for(unsigned i=0;i<4;i++) {
  fixture_target_super.s_magic=good[i];assert(!add_request("/data/dir/nmprobe/sub/x",false));
  assert(has_path("/data/dir/nmprobe/sub/x"));clear_tree();
 }
 // Replacement and DEL -> retained-directory both go through the same guard.
 fixture_target_super.s_magic=0xEF53UL;
 assert(!add_directory("/data/dir/parent",NM_FLAG_IS_DIR));
 assert(!add_request("/data/dir/parent/x",false));
 fixture_target_super.s_magic=0x01021994UL; // synthetic existing-tree precondition, not a runtime fs mutation
 assert(add_directory("/data/dir/parent",NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR)==-EOPNOTSUPP);
 u=(struct nm_topology_updates){0};
 assert(nm_topology_remove_locked("/data/dir/parent",16,0,&u)==-EOPNOTSUPP);
 assert(has_path("/data/dir/parent/x"));nm_finish_topology_updates(&u);clear_tree();
 // A node can be owned by a virtual parent and also have an old native anchor.
 struct nm_directory_node outer={0},inner={0};struct nm_topology_leaf owner={.parent=&outer};inner.owner=&owner;
 struct nm_dentry_head secondary={.d_inode=(struct inode*)0x1234};
 struct nm_topology_anchor a={.node=&outer,.path={.dentry=(void*)&dir_dentry}},b={.node=&inner,.path={.dentry=(void*)&secondary},.next=&a};
 nm_topology_anchors=&b;fixture_target_super.s_magic=0xEF53UL;fixture_secondary_super.s_magic=0x01021994UL;
 assert(nm_topology_check_inode_allocation(&inner,NULL)==-EOPNOTSUPP);
 fixture_target_super.s_magic=0x01021994UL;fixture_secondary_super.s_magic=0xEF53UL;
 assert(nm_topology_check_inode_allocation(&inner,NULL)==-EOPNOTSUPP);
 fixture_target_super.s_magic=0xEF53UL;assert(!nm_topology_check_inode_allocation(&inner,NULL));
 nm_topology_anchors=NULL;
 assert(!allocated||allocated==released);assert(!path_refs);
 puts("PASS TST-004 topology: auto/direct/backed/opaque, regular rejection, whiteout keep/replace/delete, ramfs/ext4/erofs/f2fs, retained-directory, mixed owner/anchor, refs");return 0;
}
'''
MATERIALIZE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
typedef uint64_t u64;typedef uint32_t u32;
#define NM_FLAG_IS_DIR 1
#define NM_FLAG_VIRTUAL_DIR 2
#define NM_FLAG_WHITEOUT 4
#define NM_FLAG_OPAQUE 8
#define kfunc(n) kf_##n
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR(n) ((uintptr_t)(n)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(n) (!(n)||IS_ERR(n))
#define nm_log_error(...) fprintf(stderr,__VA_ARGS__)
struct super_block {unsigned long magic;};
struct nm_super_head {unsigned long s_magic;};
struct nm_inode_info;
struct inode {unsigned mode;struct super_block*sb;struct nm_inode_info*info;};
struct nm_inode_owner_prefix {unsigned short i_opflags;};
struct dentry {struct inode*inode;};struct nm_path {void*mnt;struct dentry*dentry;};
struct nomount_rule {unsigned flags;struct nm_path r_path;bool inherit_backing;};
struct nm_inode_info {unsigned secid;void*dir_node;bool initialized;int init_error;void(*link_put)(struct inode*,void*);};
struct nm_security_context {unsigned secid;};struct nm_inode_lookup_ops {void*lookup;};
static struct {void*file_ops,*inode_ops,*symlink_ops,*directory_ops,*lookup_backing;struct nomount_rule*(*inherit_directory)(struct inode*,struct dentry*);}nm_inode_engine={(void*)1,(void*)2,(void*)3,(void*)4,(void*)5};
static bool nm_legacy_links;static struct {void*put;}nm_follow_pairs[1];
static void*nm_virtual_directory_fops=(void*)1,*nm_owned_dentry_ops=(void*)2;
static unsigned calls,allocs,frees,refs,wrapped,security;
static struct inode*nm_dentry_inode(struct dentry*d){return d->inode;}
static unsigned nm_inode_mode(struct inode*i){return i->mode;}
static struct super_block*nm_inode_superblock(struct inode*i){return i->sb;}
static bool nm_plain_symlink_source(struct inode*i){return i->mode==0120000;}
static int nm_follow_pair_index(struct inode*i){return 0;}
static const void*nm_inode_ops(struct inode*i){return NULL;}
static bool nm_is_virtual_inode(struct inode*i){return false;}
static void nm_directory_lookup(void){}
static void*nm_super_ops(struct super_block*s){return (void*)1;}
static void*nm_super_proxy(const void*s){return (void*)1;}
static void*nm_zalloc(size_t n){allocs++;return calloc(1,n);}
static void nm_free(void*p){frees++;free(p);}
static int nm_get_security_context(struct inode*i,struct nm_security_context*c){security++;c->secid=1;return 0;}
static void nm_release_security_context(struct nm_security_context*c){security--;}
static int nm_wrap_dentry(struct dentry*d,bool owned){wrapped++;return 0;}
static void nm_bind_inode_path(struct nm_inode_info*i,struct nomount_rule*r){refs++;}
static void nm_put_inode_binding(struct nm_inode_info*i){refs--;}
static void nm_directory_node_get(void*n){}
// Positive target tests inject allocation failure: reaching the native allocator is observable.
static struct inode*kf_nm_new_inode(struct super_block*s){calls++;return NULL;}
static struct inode*kf_nm_iget5_locked(struct super_block*s,unsigned long n,int(*t)(struct inode*,void*),int(*set)(struct inode*,void*),void*p){calls++;return NULL;}
static void unexpected(void){assert(!"unexpected post-allocation callback");}
#define nm_copy_backing_inode_attributes(...) unexpected()
#define nm_publish_inode_ops(...) unexpected()
#define nm_set_inode_private(...) unexpected()
#define nm_initialize_file_inode(...) unexpected()
#define nm_initialize_backing_directory_inode(...) unexpected()
#define nm_initialize_directory_inode(...) unexpected()
static int nm_initialize_inode_security(struct inode*i,struct nm_security_context*c){unexpected();return 0;}
static void kf_nm_iput(struct inode*i){unexpected();}
static struct dentry*kf_nm_d_splice_alias(struct inode*i,struct dentry*d){unexpected();return NULL;}
static void*nm_inode_private(struct inode*i){return i->info;}
static int nm_cached_directory_test(struct inode*i,void*p){unexpected();return 0;}
static int nm_cached_directory_set(struct inode*i,void*p){unexpected();return 0;}
static void kf_nm_set_nlink(struct inode*i,unsigned n){unexpected();}
static unsigned nm_inode_nlink(struct inode*i){return 2;}
static void kf_nm_unlock_new_inode(struct inode*i){unexpected();}
static void*nm_dentry_ops(struct dentry*d){return NULL;}
static void kf_nm_d_drop(struct dentry*d){unexpected();}
static void kf_nm_dput(struct dentry*d){unexpected();}
static struct nomount_rule inherited;static unsigned inherited_puts;
static struct nomount_rule*inherit(struct inode*i,struct dentry*d){return &inherited;}
static void nm_rule_put(struct nomount_rule*r){assert(r==&inherited);inherited_puts++;}
'''
MAT_TEST = r'''
int main(void){
 struct super_block target={0x01021994UL},source={0xEF53UL};struct inode parent={0040000,&target},backing={0040000,&source};
 struct dentry real={&backing},out={0};int node;
 struct nomount_rule pure={.flags=3},dir={.flags=1,.r_path={.mnt=(void*)1,.dentry=&real}};
 for(unsigned kind=0;kind<4;kind++){
  dir.flags=kind==2?9:1;pure.inherit_backing=kind==3;inherited=dir;
  nm_inode_engine.inherit_directory=kind==3?inherit:NULL;
  struct nomount_rule*r=kind==0||kind==3?&pure:&dir;
  assert(nm_materialize_virtual_directory(&parent,&out,r,&node,1)==ERR_PTR(-EOPNOTSUPP));
 }
 assert(inherited_puts==1&&!calls&&!allocs&&!wrapped&&!security&&!refs);
 for(unsigned symlink=0;symlink<2;symlink++){
  backing.mode=symlink?0120000:0100000;struct nomount_rule r={.r_path={.mnt=(void*)1,.dentry=&real}};
  assert(nm_materialize_backed_inode(&parent,&out,&r,1,symlink)==ERR_PTR(-EOPNOTSUPP));
 }
 assert(!calls&&!allocs&&!wrapped&&!security&&!refs);
 // Source tmpfs is allowed: only the actual target sb controls allocation eligibility.
 source.magic=0x01021994UL;unsigned long good[]={0x858458f6UL,0xEF53UL,0xE0F5E1E2UL,0xF2F52010UL};
 for(unsigned i=0;i<4;i++){
  target.magic=good[i];backing.mode=0040000;pure.inherit_backing=false;unsigned n=calls;
  assert(nm_materialize_virtual_directory(&parent,&out,&pure,&node,1)==ERR_PTR(-ENOMEM));
  assert(calls==n+1&&!refs&&!security&&allocs==frees);
  backing.mode=0100000;struct nomount_rule r={.r_path={.mnt=(void*)1,.dentry=&real}};
  assert(nm_materialize_backed_inode(&parent,&out,&r,1,false)==ERR_PTR(-ENOMEM));
  assert(calls==n+2&&!refs&&!security&&allocs==frees);
 }
 puts("PASS TST-004 actual materializers: tmpfs allocators=0 for pure/backed/opaque/inherited/file/link; four other target types reach allocator; tmpfs source allowed");return 0;
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    # Keep the complete failure-scope Oracle, with a second sb for mixed anchor/owner topology.
    old=scope.C_TEST
    scope.C_TEST=old.replace('int main(void)','static int original_scope_main(void)',1)+TOPOLOGY
    assert re.findall(r'\bassert\([^;]+;',old)==re.findall(r'\bassert\([^;]+;',scope.C_TEST[:scope.C_TEST.index(TOPOLOGY)])
    scope.C_PRE=scope.C_PRE.replace('static struct nm_super_head fixture_target_super', 'static struct nm_super_head fixture_secondary_super;\nstatic struct nm_super_head fixture_target_super')
    scope.C_PRE=scope.C_PRE.replace('(void)inode; return (void*)&fixture_target_super;', 'return inode==(void*)0x1234?(void*)&fixture_secondary_super:(void*)&fixture_target_super;')
    sys.argv=['scope','--symbols',str(a.symbols),'--output',str(a.output/'topology')];scope.main()
    body=MATERIALIZE+function('nomount/nm_inode.c','nm_check_inode_allocation')
    body+=function('nomount/nm_inode.c','nm_materialize_backed_inode')+function('nomount/nm_virtual_directory.c','nm_materialize_virtual_directory')
    compile_run(body+MAT_TEST,a.output/'materialize')
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer host fixtures, not a device/kernel lifetime conclusion','topology':'PASS','materializers':'PASS','oracle_assertions':'Existing failure-scope assertions unchanged','native_boundary':'Non-tmpfs allocator deliberately returns NULL; tmpfs must not reach allocator'},indent=2)+'\n')

if __name__=='__main__': main()
