#!/usr/bin/env python3
"""DEV-102：生产 open/UID/枚举/filter/seek 链与 POSIX 实目录联合测试。"""
import argparse
import re
import subprocess
import sys
from pathlib import Path
from test_nomount_v230 import ROOT, compile_run, function

PRE = r'''
#include <dirent.h>
#include <unistd.h>
struct inode {struct nm_inode_owner_prefix owner;const void*ops;struct nm_inode_info*info;};
struct dentry {struct nm_dentry_head head;const char*host_path;};
struct file {struct inode*inode;struct nm_path path;struct file*backing;DIR*stream;int64_t pos;const void*ops;};
static struct nm_inode_lookup_ops directory_ops_token,native_ops_token;
static void*nm_virtual_directory_fops=&directory_ops_token;
static struct {const void*directory_ops;int(*iterate_backing)(struct file*,struct nm_dir_context*,void*);
 int64_t(*seek_backing)(struct file*,int64_t,int);} nm_inode_engine={.directory_ops=&directory_ops_token};
static u32 host_directory_hash(const void*salt,const char*name,unsigned length){
 u32 h=(uintptr_t)salt;while(length--)h=(h*33)^(unsigned char)*name++;return h;
}
static u32 fsuid=10001;static bool compat_mode;
static unsigned host_reads,host_seeks,opens,closes;
static struct inode*nm_file_inode(struct file*f){return f->inode;}
static struct nm_path*nm_file_path(struct file*f){return &f->path;}
static struct file*nm_file_private(struct file*f){return f->backing;}
static void nm_set_file_private(struct file*f,struct file*b){f->backing=b;}
static int64_t*nm_file_position(struct file*f){return &f->pos;}
static const void*nm_file_ops(struct file*f){return f->ops;}
static const void*nm_inode_ops(struct inode*i){return i->ops;}
static void*nm_inode_private(struct inode*i){return i->info;}
static u64 nm_inode_number(struct inode*i){return (uintptr_t)i;}
static u32 nm_current_fsuid(void){return fsuid;}
static bool nm_current_compat(void){return compat_mode;}
static bool nm_is_directory_inode(struct inode*i){return i&&i->ops==nm_inode_engine.directory_ops;}
static bool nm_is_virtual_inode(struct inode*i){return nm_is_directory_inode(i);}
static void*nm_directory_file_proxy(const void*p){return NULL;}
static unsigned nm_file_flags(struct file*f){return 0;}
static const void*nm_file_cred(struct file*f){return NULL;}
static int(*nm_backing_open_permission)(const struct nm_path*);
static int(*nm_backing_write_open_permission)(const struct nm_path*,unsigned int);
static struct dentry*nm_directory_lookup(struct inode*i,struct dentry*d,unsigned f){abort();}
static struct dentry*kf_nm_dget_parent(struct dentry*d){return d;}
static void kf_nm_dput(struct dentry*d){}
static struct file*kf_nm_dentry_open(const struct nm_path*p,unsigned flags,const void*cred){
 struct file*f=calloc(1,sizeof(*f));assert(f);
 f->stream=opendir(((struct dentry*)p->dentry)->host_path);assert(f->stream);f->inode=nm_dentry_inode(p->dentry);
 f->path=*p;f->ops=&native_ops_token;opens++;return f;
}
static void kf_nm_fput(struct file*f){assert(!closedir(f->stream));closes++;free(f);}
static int64_t kf_nm_vfs_setpos(struct file*f,int64_t pos,int64_t max){if(pos<0||pos>max)return -EINVAL;return f->pos=pos;}
// Host kernel boundary: seekdir/readdir/telldir supply real entries/cookies.
// VFS locking/permission and ABI are not emulated by this adapter.
static int kf_nm_iterate_dir(struct file*f,struct nm_dir_context*c){
 host_reads++;seekdir(f->stream,f->pos);c->pos=f->pos;
 for(;;){
  long before=telldir(f->stream);errno=0;struct dirent*d=readdir(f->stream);
  if(!d){assert(!errno);break;}
  c->pos=before;
  int rc=struct_offset.dir_actor_abi==1 ? (c->actor_bool(c,d->d_name,strlen(d->d_name),before,d->d_ino,d->d_type)?0:-ENOSPC)
                                      : c->actor(c,d->d_name,strlen(d->d_name),before,d->d_ino,d->d_type);
  if(rc){seekdir(f->stream,before);break;}
  c->pos=telldir(f->stream);
 }
 f->pos=c->pos;return 0;
}
static int64_t kf_nm_vfs_llseek(struct file*f,int64_t offset,int whence){
 host_seeks++;int64_t next=whence==SEEK_SET?offset:whence==SEEK_CUR?f->pos+offset:-1;
 if(next<0)return -EINVAL;
 seekdir(f->stream,next);return f->pos=telldir(f->stream);
}
static int64_t kf_nm_generic_file_llseek(struct file*f,int64_t offset,int whence){
 int64_t next=whence==SEEK_SET?offset:whence==SEEK_CUR?f->pos+offset:-1;
 return kf_nm_vfs_setpos(f,next,INT64_MAX);
}
'''
TEST = r'''
struct capture {struct nm_dir_context context;unsigned count,capacity;char names[32][256];int64_t cookies[32];};
static int collect(struct nm_dir_context*c,const char*name,int len,int64_t off,u64 ino,unsigned type){
 struct capture*out=(void*)c;if(out->count==out->capacity)return -ENOSPC;
 assert(len<256&&out->count<32);memcpy(out->names[out->count],name,len);out->names[out->count][len]=0;
 out->cookies[out->count++]=off;return 0;
}
static bool collect_bool(struct nm_dir_context*c,const char*n,int len,int64_t off,u64 ino,unsigned type){return !collect(c,n,len,off,ino,type);}
static struct capture read_outer(struct file*f,unsigned capacity){
 struct capture c={.context={.actor=collect,.pos=f->pos},.capacity=capacity};
 if(struct_offset.dir_actor_abi==1)c.context.actor_bool=collect_bool;
 assert(!nm_virtual_directory_iterate(f,&c.context));f->pos=c.context.pos;return c;
}
// Independent POSIX oracle, bypassing all production filters and dispatch.
static struct capture native_from(const char*path,long pos,unsigned capacity){
 struct capture c={.capacity=capacity};DIR*d=opendir(path);assert(d);
 // telldir cookies belong to this DIR stream on macOS: establish its own cookie.
 while(telldir(d)!=pos){struct dirent*e=readdir(d);assert(e);}
 seekdir(d,pos);
 while(c.count<capacity){long before=telldir(d);struct dirent*e=readdir(d);if(!e)break;
  strcpy(c.names[c.count],e->d_name);c.cookies[c.count++]=before;}
 closedir(d);return c;
}
static bool contains(struct capture*c,const char*n){for(unsigned i=0;i<c->count;i++)if(!strcmp(c->names[i],n))return true;return false;}
static void same_names(struct capture*a,struct capture*b){
 if(a->count!=b->count){fprintf(stderr,"counts actual=%u expected=%u pos=%lld\n",a->count,b->count,(long long)a->context.pos);
 for(unsigned i=0;i<a->count;i++)fprintf(stderr,"actual %s\n",a->names[i]);
 for(unsigned i=0;i<b->count;i++)fprintf(stderr,"expected %s\n",b->names[i]);}
 assert(a->count==b->count);for(unsigned i=0;i<a->count;i++)assert(!strcmp(a->names[i],b->names[i]));}
static struct nomount_leaf*add_virtual(struct nm_directory_node*n,const char*path,struct nomount_rule*r){
 struct nomount_leaf*l=nm_alloc_leaf(path,strlen(path));assert(!IS_ERR(l));
 struct nm_rule_updates updates={0};assert(!nm_set_leaf_rule(l,r,&updates));nm_finish_rule_updates(&updates);
 assert(!nm_insert_child(&n->children,l));flush_callbacks();return l;
}
static void exercise(const char*path,bool bool_actor,bool compat){
 struct_offset.dir_actor_abi=bool_actor;compat_mode=compat;fsuid=10001;
 struct nm_directory_node*node=nm_new_directory_node();assert(node);
 struct inode native={.owner={.i_mode=0040755},.ops=&native_ops_token};
 struct dentry native_d={.head={.d_inode=&native},.host_path=path};
 struct nm_inode_info info={.flags=NM_FLAG_IS_DIR,.dir_node=node,.r_path={.dentry=&native_d}};
 struct inode outer_inode={.owner={.i_mode=0040755},.ops=&directory_ops_token,.info=&info};
 struct dentry outer_d={.head={.d_inode=&outer_inode}};
 struct file outer={.inode=&outer_inode,.path={.dentry=&outer_d}};
 assert(!nm_open(&outer_inode,&outer));struct file*pinned=outer.backing;
 // Non-opaque, identical child set: global exclusion preserves native output.
 struct capture expected=native_from(path,0,32),a=read_outer(&outer,32);
 same_names(&a,&expected);assert(!nm_uid_add(fsuid));
 assert(!nm_virtual_directory_llseek(&outer,0,SEEK_SET));a=read_outer(&outer,32);same_names(&a,&expected);
 nm_uid_clear();flush_callbacks();
 // A real overlay difference must remain visible: native 'real-a' is masked,
 // virtual-only is added. Global exclusion restores the native directory set.
 struct nomount_rule*rule=nm_alloc_rule("/data/file",10,0,0);assert(!IS_ERR(rule));
 struct nomount_leaf*leaf=add_virtual(node,"/view/virtual-only",rule);
 struct nomount_rule*white=nm_alloc_rule(NULL,0,NM_FLAG_WHITEOUT,0);assert(!IS_ERR(white));
 struct nomount_leaf*hidden=add_virtual(node,"/view/real-a",white);
 assert(!nm_virtual_directory_llseek(&outer,0,SEEK_SET));a=read_outer(&outer,32);
 if(!contains(&a,"virtual-only")){struct capture tail=read_outer(&outer,32);assert(contains(&tail,"virtual-only"));}
 assert(!contains(&a,"real-a"));assert(!nm_uid_add(fsuid));assert(!nm_virtual_directory_llseek(&outer,0,SEEK_SET));
 a=read_outer(&outer,32);same_names(&a,&expected);nm_uid_clear();flush_callbacks();
 // Opaque unblocked: virtual entries only; no backing read or seek.
 info.flags|=NM_FLAG_OPAQUE;outer.pos=0;unsigned reads=host_reads,seeks=host_seeks;
 a=read_outer(&outer,32);assert(contains(&a,"virtual-only")&&!contains(&a,"real-a")&&!contains(&a,"real-b"));
 assert(host_reads==reads&&host_seeks==seeks&&nm_virtual_position(outer.pos,compat));
 // Open before policy update: virtual cookie never leaks into backing cursor.
 assert(!nm_uid_add(fsuid));int64_t virtual_cookie=outer.pos;
 a=read_outer(&outer,32);assert(!a.count&&outer.pos==virtual_cookie&&host_reads==reads);
 assert(nm_virtual_directory_llseek(&outer,0,SEEK_CUR)==virtual_cookie&&host_seeks==seeks);
 assert(nm_virtual_directory_llseek(&outer,virtual_cookie,SEEK_SET)==virtual_cookie&&host_seeks==seeks);
 assert(!nm_virtual_directory_llseek(&outer,0,SEEK_SET));a=read_outer(&outer,32);same_names(&a,&expected);
 assert(outer.backing==pinned); // No path reopen or binding replacement.
 // Normal-cookie continuation, including the boundary positions 0/1/2.
 for(long pos=0;pos<=2;pos++){
  assert(nm_virtual_directory_llseek(&outer,pos,SEEK_SET)==pos);
  struct capture native_tail=native_from(path,pos,32);a=read_outer(&outer,32);same_names(&a,&native_tail);
 }
 assert(!nm_virtual_directory_llseek(&outer,0,SEEK_SET));a=read_outer(&outer,1);assert(a.count==1);
 long saved=outer.pos;struct capture tail=native_from(path,saved,32);a=read_outer(&outer,32);same_names(&a,&tail);
 assert(nm_virtual_directory_llseek(&outer,0,SEEK_CUR)==outer.pos);
 saved=outer.pos;assert(nm_virtual_directory_llseek(&outer,-1,SEEK_SET)==-EINVAL&&outer.pos==saved);
 struct nm_dir_context bad={.pos=-1};assert(nm_virtual_directory_iterate(&outer,&bad)==-EINVAL);
 // Exclusion while the opaque cursor is still normal (before virtual segment).
 nm_uid_clear();flush_callbacks();outer.pos=0;a=read_outer(&outer,1);assert(outer.pos==1);
 assert(!nm_uid_add(fsuid));tail=native_from(path,1,32);a=read_outer(&outer,32);same_names(&a,&tail);
 nm_uid_clear();flush_callbacks();outer.pos=0;a=read_outer(&outer,2);assert(a.count==2&&nm_virtual_position(outer.pos,compat));
 // The attempted first virtual entry moves to its virtual cookie even if full.
 // A deliberately selected normal cookie 2 still resumes backing at that cookie.
 assert(nm_virtual_directory_llseek(&outer,2,SEEK_SET)==2);
 assert(!nm_uid_add(fsuid));tail=native_from(path,2,32);a=read_outer(&outer,32);same_names(&a,&tail);
 // Single-rule deny is not global policy and must not open opaque backing.
 nm_uid_clear();flush_callbacks();rule->deny_start=rule->deny_end=fsuid;outer.pos=0;reads=host_reads;
 a=read_outer(&outer,32);assert(!contains(&a,"virtual-only")&&!contains(&a,"real-a")&&host_reads==reads);
 assert(!nomount_is_uid_blocked(fsuid));rule->deny_start=rule->deny_end=0;
 // Isolated policy uses the same global dispatch, without populating UID array.
 fsuid=90001;nm_block_isolated_uids=true;assert(!nomount_uids);outer.pos=0;
 a=read_outer(&outer,32);same_names(&a,&expected);nm_block_isolated_uids=false;
 assert(!nm_release(&outer_inode,&outer)&&!outer.backing);
 nm_directory_node_put(node);flush_callbacks();nm_free_leaf(leaf);nm_free_leaf(hidden);flush_callbacks();
 printf("PASS actor=%s cookie=%s: merged/opaque/open-policy/rewind/continuation/deny/isolated/positions; native entries=%u\n",bool_actor?"bool":"int",compat?"compat":"64",expected.count);
}
int main(int argc,char**argv){
 assert(argc==2);assert(!rules_oracle_main());
 kf_nm_full_name_hash=host_directory_hash;
 nm_inode_engine.iterate_backing=nm_iterate_backing_view;
 nm_inode_engine.seek_backing=nm_backing_directory_llseek;
 for(unsigned actor=0;actor<2;actor++)for(unsigned compat=0;compat<2;compat++)exercise(argv[1],actor,compat);
 assert(opens==4&&closes==4);assert(!depth&&allocated==released);
 printf("PASS real backing reads=%u seeks=%u opens=%u closes=%u\n",host_reads,host_seeks,opens,closes);
 return 0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--symbols',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    result=subprocess.run([sys.executable,str(ROOT/'nomount/tools/test_rules.py'),'--symbols',str(args.symbols.resolve()),'--output',str(out/'oracle')],capture_output=True,text=True)
    (out/'oracle.log').write_text(result.stdout+result.stderr);result.check_returncode()
    original=(out/'oracle/rules.c').read_text();source=original.replace('int main(void) {','int rules_oracle_main(void) {')+PRE
    source=source.replace('#include "nm_structs.h"', '')  # Already embedded by the rule Oracle.
    source+=function('nomount/nm_offsets.c','nm_dir_emit')
    source+=(ROOT/'nomount/nm_directory_nodes.c').read_text()
    source+=function('nomount/nm_file.c','nm_open')+function('nomount/nm_file.c','nm_release')
    source+=function('nomount/nm_file.c','nm_llseek')+function('nomount/nm_native.c','nm_iterate_backing')
    directory=(ROOT/'nomount/nm_directory.c').read_text()
    start=directory.index('struct nm_directory_actor {')
    source+=directory[start:directory.index('static int nm_directory_iterate(',start)]
    backing=(ROOT/'nomount/nm_backing_directory.c').read_text()
    source+=backing[backing.index('struct nm_backing_directory_actor {'):]
    source+=function('nomount/nm_backing_inode.c','nm_iterate_backing_view')
    for name in ('nm_directory_uses_backing','nm_virtual_directory_llseek','nm_virtual_directory_iterate'):
        source+=function('nomount/nm_virtual_directory.c',name)
    # All original rule assertions survive byte-for-byte, in order, and execute.
    cursor=0
    for expression in re.findall(r'\bassert\s*\([^;]+\);',original):
        cursor=source.index(expression,cursor)+len(expression)
    directory=out/'backing';directory.mkdir()
    for name in ('real-a','real-b','中文.txt'):(directory/name).write_text(name)
    compile_run(source+TEST,out/'backing-joint',[directory])

if __name__=='__main__':main()
