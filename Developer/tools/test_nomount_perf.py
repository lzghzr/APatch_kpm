#!/usr/bin/env python3
"""Optimization candidate: production inode cache, child hints and deferred retirement; host stubs."""
import argparse
import json
from pathlib import Path
import sys
import test_nomount_failure_scope as scope
from test_nomount_v230 import compile_run, function

ROOT = Path(__file__).resolve().parents[2]

TOPOLOGY = r'''
static struct {void(*fn)(void*,u64);void*data;} jobs[128];
static unsigned async_queued;
static u64 schedule_node(void(*fn)(void*,u64),void*data,int node) {
 assert(node==-1 && async_queued<128);jobs[async_queued].fn=fn;jobs[async_queued++].data=data;return async_queued;
}
static u64 schedule_inline(void(*fn)(void*,u64),void*data) {fn(data,1);return 1;}
static void drain_jobs(void) {
 while(async_queued){unsigned i=--async_queued;jobs[i].fn(jobs[i].data,i);}
}
static void remove_path(const char*p,struct nm_topology_updates*u) {
 assert(!nm_topology_remove_locked(p,strlen(p),0,u));assert(!has_path(p));
}
int main(void) {
 assert(!original_scope_main());fail_stage=0;
 // The hint is a checked index into the current array, not a retained leaf pointer.
 struct nomount_child_array *a=NULL;struct nomount_leaf*leaves[260];
 for(unsigned i=0;i<260;i++) {
  char p[64];snprintf(p,sizeof(p),"/data/dir/file-%03u",i);leaves[i]=nm_alloc_leaf(p,strlen(p));
  assert(!IS_ERR(leaves[i])&&!nm_insert_child(&a,leaves[i]));
 }
 u16 hint=65535;
 for(unsigned i=0;i<260;i++) {
  char name[32];snprintf(name,sizeof(name),"file-%03u",i);
  assert(nm_find_child_hint(a,name,strlen(name),&hint)==leaves[i]);
  assert(nm_entries(a)[hint].leaf==leaves[i]);
  assert(nm_find_child_hint(a,name,strlen(name),&hint)==nm_find_child(a,name,strlen(name)));
 }
 assert(!nm_find_child_hint(a,"absent",6,&hint));assert(!nm_find_child_hint(NULL,"x",1,&hint));
 assert(!nm_find_child_hint(a,NULL,1,&hint));assert(!nm_find_child_hint(a,"",0,&hint));
 // Snapshot replacement and index shifts cannot return a stale/wrong child.
 hint=0;
 for(unsigned i=0;i<260;i++) {
  char name[32];snprintf(name,sizeof(name),"file-%03u",i);
  assert(!nm_remove_child(&a,leaves[i]));
  assert(!nm_find_child_hint(a,name,strlen(name),&hint));
  if(i+1<260){snprintf(name,sizeof(name),"file-%03u",i+1);assert(nm_find_child_hint(a,name,strlen(name),&hint)==leaves[i+1]);}
  release_leaf(leaves[i]);
 }
 flush_callbacks();assert(!a&&allocated==released);
 const char*p="/data/dir/perf/sub/value";
 nm_async_schedule_node=schedule_node;
 for(unsigned i=0;i<12;i++) {
  assert(!add_request(p,false));struct nm_topology_updates u={0};remove_path(p,&u);
  int before=syncs;nm_finish_topology_updates(&u);
  assert(syncs==before && !u.rules.rules&&!u.leaves&&!u.anchors && async_queued==i+1);
 }
 assert(path_refs>0); // Delayed native path release, despite immediately invisible rules.
 // An old retired anchor can share a native node with a newly active anchor.
 assert(!add_request(p,false));struct nm_topology_leaf*active=nm_topology_find(p,strlen(p));
 struct nm_directory_node*active_parent=active->parent;unsigned pending=async_queued;
 drain_jobs();assert(pending==12&&has_path(p)&&nm_topology_find(p,strlen(p))==active&&active->parent==active_parent);
 assert(nm_select_rule(active->leaf,0)&&native_node->children);
 nm_async_schedule_node=NULL;clear_tree();
 // Job-allocation failure keeps the original synchronous cleanup, not an ADD/DEL failure.
 assert(!add_request(p,false));struct nm_topology_updates u={0};remove_path(p,&u);
 nm_async_schedule_node=schedule_node;fail_next=1;int before=syncs;nm_finish_topology_updates(&u);
 assert(!async_queued&&syncs==before+1);nm_async_schedule_node=NULL;clear_tree();
 // Native async can itself execute inline under memory pressure.
 nm_async_schedule=schedule_inline;
 assert(!add_request(p,false));u=(struct nm_topology_updates){0};remove_path(p,&u);nm_finish_topology_updates(&u);
 assert(!u.rules.rules&&!u.leaves&&!u.anchors);nm_async_schedule=NULL;clear_tree();
 // CLEAR follows the same deferred ownership path; active topology is empty before drain.
 nm_async_schedule_node=schedule_node;
 assert(!add_request(p,false));u=(struct nm_topology_updates){0};assert(!nm_topology_clear_locked(&u));
 nm_finish_topology_updates(&u);assert(!nm_topology_leaves&&!nm_topology_anchors&&async_queued==1);
 drain_jobs();nm_async_schedule_node=NULL;clear_tree();
 assert(sizeof(struct nm_inode_info)==64&&sizeof(struct nomount_rule)==56);
 puts("PASS hints: current snapshot/name/shift/miss; retirement: async_queued, reverse order, re-add, CLEAR, OOM, inline fallback, reference balance");
 return 0;
}
'''

INODE_PRE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;typedef uint32_t u32;typedef uint16_t u16;
#define kfunc(n) kf_##n
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define PTR_ERR(n) ((int)(intptr_t)(n))
#define IS_ERR(n) ((uintptr_t)(n)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(n) (!(n)||IS_ERR(n))
#define NM_FLAG_IS_DIR 1
#define NM_FLAG_VIRTUAL_DIR 2
#define NM_FLAG_WHITEOUT 4
#define nm_log_error(...) ((void)0)
struct inode;struct dentry;struct nm_path {void*mnt;struct dentry*dentry;};
struct rcu_head {void*p[2];};
'''
INODE_STUBS = r'''
struct nm_inode_owner_prefix {u16 i_mode,i_opflags;u32 i_uid,i_gid;};
struct super_block {unsigned long s_magic;};struct nm_super_head {unsigned long s_magic;};
struct inode {struct nm_inode_owner_prefix owner;u64 number;struct super_block*sb;struct nm_inode_info*info;void*ops;unsigned refs;};
struct dentry {struct inode*inode;};struct nm_security_context {u32 secid;};
static struct {int inode_number;}struct_offset={offsetof(struct inode,number)};
static struct {void*inode_ops,*file_ops,*symlink_ops;}nm_inode_engine={(void*)1,(void*)2,(void*)3};
static bool nm_legacy_links;static struct{void*put;}nm_follow_pairs[1];
static unsigned allocations,frees,paths,contexts,notifies,new_calls,iget_calls,unlocks,depth;
static int security_error,fail_alloc;static u32 sid=5;
static struct inode*cache[64];static unsigned cache_count;
static struct inode* forced_hit;
static void*nm_zalloc(size_t n){if(fail_alloc){fail_alloc=0;return NULL;}allocations++;return calloc(1,n);}
static void nm_free(void*p){assert(p);frees++;free(p);}
static void kf_nm_path_get(struct nm_path*p){assert(p->dentry);paths++;}
static void kf_nm_path_put(struct nm_path*p){assert(p->dentry&&paths&&!depth);paths--;}
static void nm_rcu_read_lock(void){depth++;}static void nm_rcu_read_unlock(void){assert(depth);depth--;}
static struct inode*nm_dentry_inode(struct dentry*d){return d->inode;}
static unsigned nm_inode_mode(struct inode*i){return i->owner.i_mode;}
static void*nm_inode_private(struct inode*i){return i->info;}
static void nm_set_inode_private(struct inode*i,void*p){i->info=p;}
static u64 nm_inode_number(struct inode*i){return i->number;}
static struct super_block*nm_inode_superblock(struct inode*i){return i->sb;}
static u16 nm_virtual_mode(u16 m){return m&~06000;}
static bool nm_is_file_inode(struct inode*i){return i->ops==nm_inode_engine.inode_ops;}
static bool nm_plain_symlink_source(struct inode*i){return (nm_inode_mode(i)&0170000)==0120000;}
static int nm_follow_pair_index(struct inode*i){return 0;}
static void*nm_super_ops(struct super_block*s){return (void*)1;}
static void*nm_super_proxy(void*p){return p;}
static int nm_get_security_context(struct inode*i,struct nm_security_context*c){contexts++;c->secid=sid;return 0;}
static void nm_release_security_context(struct nm_security_context*c){assert(contexts);contexts--;}
static int nm_initialize_inode_security(struct inode*i,struct nm_security_context*c){notifies++;return security_error;}
static void nm_publish_inode_ops(struct inode*i,void*ops,void*fops){i->ops=ops;}
static void nm_copy_backing_inode_attributes(struct inode*i,struct inode*b,u64 n){i->owner=b->owner;i->owner.i_mode=nm_virtual_mode(b->owner.i_mode);i->number=n;}
static void nm_initialize_file_inode(struct inode*i,struct inode*b,u64 n,void*info,void*ops,void*fops){nm_copy_backing_inode_attributes(i,b,n);i->info=info;i->ops=ops;}
static struct inode*kf_nm_new_inode(struct super_block*s){new_calls++;struct inode*i=calloc(1,sizeof(*i));i->refs=1;i->sb=s;return i;}
static void kf_nm_unlock_new_inode(struct inode*i){assert(i->info->initialized);unlocks++;}
static void put_binding(struct nm_inode_info*info){if(info->r_path.dentry)kf_nm_path_put(&info->r_path);}
static void nm_put_inode_binding(struct nm_inode_info*info){put_binding(info);}
static void kf_nm_iput(struct inode*i){assert(i->refs);if(--i->refs)return;for(unsigned n=0;n<cache_count;n++)if(cache[n]==i)cache[n]=NULL;put_binding(i->info);nm_free(i->info);free(i);}
static struct dentry*kf_nm_d_splice_alias(struct inode*i,struct dentry*d){d->inode=i;return NULL;}
static struct inode*kf_nm_iget5_locked(struct super_block*s,unsigned long key,int(*test)(struct inode*,void*),int(*set)(struct inode*,void*),void*p){
 iget_calls++;if(forced_hit){struct inode*i=forced_hit;forced_hit=NULL;i->refs++;return i;}
 for(unsigned n=0;n<cache_count;n++){struct inode*i=cache[n];if(i&&i->sb==s&&test(i,p)){i->refs++;return i;}}
 assert(cache_count<64);struct inode*i=kf_nm_new_inode(s);assert(!set(i,p));cache[cache_count++]=i;return i;
}
'''
INODE_TEST = r'''
static void close_dentry(struct dentry*d){kf_nm_iput(d->inode);d->inode=NULL;}
int main(void){
 struct super_block sb={0xEF53},source={0xF2F52010};struct inode parent={.sb=&sb},backing={.owner={0100644,0,1000,1000},.sb=&source};
 struct dentry real={&backing},a={0},b={0};struct nomount_rule r={.r_path={(void*)1,&real}};
 assert(!nm_materialize_backed_inode(&parent,&a,&r,17,false));struct inode*first=a.inode;
 assert(paths==1&&notifies==1&&unlocks==1&&!contexts&&first->info->initialized);
 assert(!nm_materialize_backed_inode(&parent,&b,&r,17,false));assert(b.inode==first&&first->refs==2&&paths==1&&notifies==1&&unlocks==1);
 close_dentry(&b);
 struct nm_inode_info probeinfo=*first->info;struct nm_file_cache_probe probe={&probeinfo,17};
 assert(nm_cached_file_test(first,&probe));first->info->initialized=false;assert(nm_cached_file_test(first,&probe));first->info->initialized=true;
 first->info->init_error=-EIO;assert(!nm_cached_file_test(first,&probe));forced_hit=first;
 assert(nm_materialize_backed_inode(&parent,&b,&r,17,false)==ERR_PTR(-EIO)&&first->refs==1);first->info->init_error=0;
 probe.number=18;assert(!nm_cached_file_test(first,&probe));probe.number=17;
 probeinfo.r_path.mnt=(void*)2;assert(!nm_cached_file_test(first,&probe));probeinfo=*first->info;
 struct dentry other={&backing};probeinfo.r_path.dentry=&other;assert(!nm_cached_file_test(first,&probe));probeinfo=*first->info;
 probeinfo.flags=8;assert(!nm_cached_file_test(first,&probe));probeinfo=*first->info;
 // Attribute/label changes allocate another inode while old open objects remain bound.
 backing.owner.i_mode=0100600;assert(!nm_materialize_backed_inode(&parent,&b,&r,17,false)&&b.inode!=first);close_dentry(&b);backing.owner.i_mode=0100644;
 backing.owner.i_uid++;assert(!nm_cached_file_test(first,&probe));backing.owner.i_uid--;
 backing.owner.i_gid++;assert(!nm_cached_file_test(first,&probe));backing.owner.i_gid--;
 sid++;assert(!nm_materialize_backed_inode(&parent,&b,&r,17,false)&&b.inode!=first);close_dentry(&b);sid--;
 r.inherited_child=true;unsigned hits=iget_calls;assert(!nm_materialize_backed_inode(&parent,&b,&r,17,false)&&b.inode!=first&&iget_calls==hits);close_dentry(&b);r.inherited_child=false;
 // Allocator and security failure preserve refs and never publish a failed alias.
 unsigned held=paths;fail_alloc=1;assert(nm_materialize_backed_inode(&parent,&b,&r,17,false)==ERR_PTR(-ENOMEM)&&paths==held);
 security_error=-EACCES;assert(nm_materialize_backed_inode(&parent,&b,&r,18,false)==ERR_PTR(-EACCES)&&!b.inode&&paths==held);security_error=0;
 sb.s_magic=0x01021994;hits=iget_calls;assert(nm_materialize_backed_inode(&parent,&b,&r,17,false)==ERR_PTR(-EOPNOTSUPP)&&iget_calls==hits);sb.s_magic=0xEF53;
 close_dentry(&a);assert(!paths&&!contexts&&!depth&&allocations==frees);
 puts("PASS inode cache: miss/hit, I_NEW/failed waiter, binding/ino/UID/GID/mode/SID, inherited bypass, allocation/security/tmpfs failures and refs");return 0;
}
'''

def declaration(text, name):
    start = text.index('struct ' + name + ' {')
    return text[start:text.index('\n};', start) + 3] + '\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--symbols',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.argv=['scope','--symbols',str(a.symbols),'--output',str(a.output/'oracle')];scope.main()
    source=(a.output/'oracle/publication.c').read_text()
    source=source.replace('int main(void)', 'static int original_scope_main(void)',1)
    topo=a.output/'topology'
    topo.with_suffix('.c').write_text(source+TOPOLOGY)
    scope.execute(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(ROOT/'nomount'),
                   '-fsanitize=address,undefined','-g',str(topo.with_suffix('.c')),'-o',str(topo)],topo.with_suffix('.compile.log'))
    print(scope.execute([str(topo.resolve())],topo.with_suffix('.run.log')))
    rules=(ROOT/'nomount/nm_rules.h').read_text();inode=(ROOT/'nomount/nm_inode.c').read_text()
    source=INODE_PRE+declaration(rules,'nomount_rule')+declaration(rules,'nm_inode_info')+INODE_STUBS
    source+=declaration(inode,'nm_file_cache_probe')
    for name in ('nm_bind_inode_path','nm_inode_matches_binding','nm_cached_file_test','nm_cached_file_set','nm_check_inode_allocation','nm_materialize_backed_inode'):
        source+=function('nomount/nm_inode.c',name)
    compile_run(source+INODE_TEST,a.output/'inode')
    result={'scope':'Developer ASan/UBSan host fixtures; native VFS cache/concurrency/performance require device evidence',
            'inode_cache':'PASS','lookup_hint':'PASS','async_retirement':'PASS','existing_rule_oracle':'unchanged, PASS'}
    (a.output/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
