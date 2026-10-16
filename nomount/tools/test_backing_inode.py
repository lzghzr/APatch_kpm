#!/usr/bin/env python3
"""执行backing 目录物化、递归查询及源权限；宿主夹具不证明原生并发。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('symbols','reference','inode-reference','ops-reference','file-reference','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    symbols = {name: kind for _,kind,name in json.loads(args.symbols.read_text())}
    assert all(symbols.get(name) in ('t','T') for name in ('inode_permission2',))
    command = [sys.executable,str(root/'nomount/tools/test_backing_directory.py')]
    for name in ('symbols','reference','inode_reference','ops_reference','file_reference'):
        command += ['--'+name.replace('_','-'),str(getattr(args,name))]
    command += ['--output',str(args.output/'backing-contract')]
    subprocess.run(command, check=True)
    base = (args.output/'backing-contract/backing-directory.c').read_text()
    base = base.replace('int main(void)', 'int backing_contract_main(void)')
    source = base + 'static unsigned long inode_native_lookup(const char*);\n'
    source += (root/'nomount/nm_backing_inode.c').read_text().replace('kallsyms_lookup_name_by_suffix','inode_native_lookup')
    entry = (root/'nomount/nm_directory_entry.c').read_text()
    source += entry[entry.index('static void nm_discard_directory_view'):entry.index('int nm_prepare_directory_view')]
    source += r'''
static _Alignas(8) unsigned char source_root_inode[768],source_file_inode[768],source_new_inode[768],source_sub_inode[768],source_link_inode[768];
static _Alignas(8) unsigned char source_root_dentry[256],source_file_dentry[256],source_new_dentry[256],source_sub_dentry[256],source_link_dentry[256];
static _Alignas(8) unsigned char outer_root[256],outer_again[256],outer_child[256],outer_sub[256],outer_nested[256],outer_negative[256];
static _Alignas(8) unsigned char outer_file[512],native_root_file[512],native_regular_file[512];
static int data_gets,data_puts,anchor_gets,anchor_puts,read_denied,path_denied,path_queries,native_opens,native_closes,native_refs;
static int file_exists=1,replaced_file,cache_unlocks,port_splice_error,port_alias_mode;
static int permission_calls;static struct inode* permission_inode;
struct port_inode {struct inode* inode;int refs;};static struct port_inode cache[32];
static int port_slot(struct inode* inode) {for(int i=0;i<32;i++)if(cache[i].inode==inode)return i;assert(0);return -1;}
static struct inode* port_new(struct super_block* super) {
  struct inode* inode=host_new(super);if(!inode)return NULL;
  for(int i=0;i<32;i++)if(!cache[i].inode){cache[i]=(struct port_inode){inode,1};return inode;}
  assert(0);return NULL;
}
static struct inode* port_iget(struct super_block* super,unsigned long hash,int (*test)(struct inode*,void*),int (*set)(struct inode*,void*),void* data) {
  assert(!rcu_depth&&!spin_depth&&!hash_depth&&hash==(uintptr_t)((struct nm_inode_info*)data)->rule);
  if(iget_error)return iget_error==-ENOMEM?NULL:ERR_PTR(iget_error);
  for(int i=0;i<32;i++)if(cache[i].inode){hash_depth=1;int match=test(cache[i].inode,data);hash_depth=0;if(match){cache[i].refs++;return cache[i].inode;}}
  struct inode* inode=port_new(super);if(!inode)return NULL;hash_depth=1;assert(!set(inode,data));hash_depth=0;return inode;
}
static void port_nlink(struct inode* inode,unsigned int count){*(u32*)((uintptr_t)inode+struct_offset.inode_nlink)=count;}
static void port_unlock(struct inode* inode) {
  assert(!hash_depth&&nm_is_directory_inode(inode)&&nm_inode_mapping(inode)==nm_inode_data(inode));
  struct nm_inode_info* info=nm_inode_private(inode);assert(info&&info->rule&&info->dir_node);
  assert(nm_inode_file_ops(inode)==nm_virtual_directory_fops);
  if(info->rule->r_path.dentry){struct inode* real=nm_dentry_inode(info->rule->r_path.dentry);assert(nm_inode_mode(inode)==nm_inode_mode(real)&&nm_inode_size(inode)==nm_inode_size(real)&&nm_inode_nlink(inode)==nm_inode_nlink(real));}
  cache_unlocks++;
}
static void port_iput(struct inode* inode) {
  int index=port_slot(inode);assert(cache[index].refs>0);
  if(--cache[index].refs)return;
  eviction_target=inode;nm_proxy_evict_inode(inode);assert(!nm_inode_private(inode)&&nm_inode_mapping(inode)==nm_inode_data(inode));
  free(inode);cache[index].inode=NULL;created=NULL;drain();flush_rcu();
}
static struct dentry* port_splice(struct inode* inode,struct dentry* d) {
  assert(!rcu_depth&&!spin_depth&&!hash_depth);
  if(inode&&port_splice_error){port_iput(inode);return ERR_PTR(-ELOOP);}
  if(inode&&port_alias_mode){port_iput(inode);return (void*)outer_again;}
  ((struct nm_dentry_head*)d)->d_inode=inode;return NULL;
}
static int port_permission(struct vfsmount* mnt,struct inode* inode,int mask) {
  assert((void*)mnt==(void*)0x123&&!rcu_depth&&!spin_depth&&!manager_depth&&mask==(0x20|0x04));
  permission_calls++;permission_inode=inode;return read_denied;
}
static unsigned long inode_native_lookup(const char* name) {assert(!strcmp(name,"inode_permission2"));return missing?0:(uintptr_t)port_permission;}
static int port_kern_path(const char* name,unsigned int flags,struct nm_path* path) {
  assert(flags==1&&!rcu_depth&&!spin_depth);
  if(!strcmp(name,"/back-root")){*path=(struct nm_path){(void*)0x123,source_root_dentry};data_gets++;return 0;}
  if(!strcmp(name,"/file")){*path=(struct nm_path){(void*)0x123,source_file_dentry};data_gets++;return 0;}
  if(!strcmp(name,"/system/app")){*path=(struct nm_path){(void*)1,root_dentry};anchor_gets++;return 0;}
  return -ENOENT;
}
static void port_path_put(const struct nm_path* path) {
  assert(!rcu_depth&&!spin_depth&&!in_rcu);
  if(path->dentry==root_dentry){assert(path->mnt==(void*)1);anchor_puts++;return;}
  assert(path->mnt==(void*)0x123&&(path->dentry==source_root_dentry||path->dentry==source_file_dentry||path->dentry==source_new_dentry||path->dentry==source_sub_dentry||path->dentry==source_link_dentry));data_puts++;
}
static int port_path_lookup(struct dentry* base,struct vfsmount* mnt,const char* name,unsigned int flags,struct nm_path* path) {
  assert((base==(void*)source_root_dentry||base==(void*)source_sub_dentry)&&(void*)mnt==(void*)0x123&&flags==0&&!rcu_depth&&!spin_depth&&!manager_depth);
  path_queries++;if(path_denied)return path_denied;
  void* d=NULL;
  if((!strcmp(name,"base.apk")||!strcmp(name,"extra")||!strcmp(name,"nested"))&&file_exists)d=replaced_file?source_new_dentry:source_file_dentry;
  if(!strcmp(name,"sub"))d=source_sub_dentry;
  if(!strcmp(name,"link"))d=source_link_dentry;
  if(!d)return -ENOENT;*path=(struct nm_path){(void*)0x123,d};data_gets++;return 0;
}
static struct file* port_open(const struct nm_path* path,int flags,const struct cred* cred) {
  assert(!flags&&cred==(void*)0xabc&&!rcu_depth&&permission_inode==nm_dentry_inode(path->dentry));native_opens++;native_refs++;
  struct file* file=nm_inode_mode(permission_inode)==0040755?(void*)native_root_file:(void*)native_regular_file;
  ((struct nm_file_inode_ops*)((char*)file+struct_offset.file_inode_ops))->f_inode=permission_inode;
  ((struct nm_file_inode_ops*)((char*)file+struct_offset.file_inode_ops))->f_op=native_fops;
  return file;
}
static void port_fput(struct file* file) {assert((file==(void*)native_root_file||file==(void*)native_regular_file)&&native_refs>0&&!rcu_depth&&!in_rcu);native_closes++;native_refs--;}
static int port_stat(const struct nm_path* path,struct kstat* stat,u32 mask,unsigned int flags) {
  assert(mask==77&&flags==88&&!rcu_depth);if(attr_error)return attr_error;
  struct inode* inode=nm_dentry_inode(path->dentry);struct nm_kstat_prefix* prefix=(void*)stat;
  memset(stat,0,256);prefix->ino=9999;prefix->dev=8888;prefix->mode=nm_inode_mode(inode);prefix->size=nm_inode_size(inode);prefix->nlink=nm_inode_nlink(inode);return 0;
}
static int port_iterate(void* file,struct nm_dir_context* context) {
  assert(file==native_root_file&&!rcu_depth&&!spin_depth&&*nm_file_position(file)==context->pos);
  const char* names[]={".","..","base.apk","extra"};
  for(int i=context->pos;i<4;i++){context->pos=i;if(context->actor(context,names[i],strlen(names[i]),i,i+10,i<2?4:8))return 0;context->pos=i+1;}
  *nm_file_position(file)=context->pos;return 0;
}
static long port_read(struct kiocb* request,struct iov_iter* iter) {
  struct nm_kiocb_head* iocb=(void*)request;assert(iocb->ki_filp==(void*)native_regular_file&&iter==(void*)0xbeef);
  iocb->ki_pos+=17;return 17;
}
static void port_query_dentry(void* d,const char* name,void* parent_dentry){reset_dentry(d,name,NULL);((struct nm_dentry_head*)d)->d_parent=parent_dentry;}
static struct nomount_rule* port_rule(const char* path,u32 uid){struct nomount_rule* rule=nm_alloc_rule(path,strlen(path),0,uid);assert(!IS_ERR(rule));return rule;}
int main(void) {
  assert(!backing_contract_main());nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;
  assert(nm_prepare_backing_inode_engine()==-ENODEV);target();directory_target();set_uid(1000);thread.flags=0;
  assert(!nm_prepare_inode_engine());assert(!nm_prepare_directory_engine());assert(!nm_prepare_virtual_directory_engine());
  missing="inode_permission2";assert(nm_prepare_backing_inode_functions()==-ENOENT&&!nm_backing_open_permission&&!nm_inode_engine.lookup_backing);missing=NULL;
  assert(!nm_prepare_backing_inode_engine()&&nm_backing_open_permission&&nm_inode_engine.lookup_backing&&nm_inode_engine.iterate_backing&&nm_inode_engine.seek_backing);
  assert(nm_prepare_backing_inode_engine()==-EALREADY);assert(!nm_prepare_topology_functions());
  memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;nm_inode_objects(parent)->i_op=native_iops;
  *(const void**)((char*)parent+struct_offset.inode_file_ops)=native_fops;((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;
  ((struct nm_dentry_head*)root_dentry)->d_inode=parent;sb.s_op=original_sops;sb.s_dev=456;
  nm_set_operation_callback(native_fops,struct_offset.fop_iterate_shared,port_iterate);
  ((struct nm_file_io_ops*)native_fops)->read_iter=port_read;
  nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
  void* native_inodes[]={source_root_inode,source_file_inode,source_new_inode,source_sub_inode,source_link_inode};
  void* native_dentries[]={source_root_dentry,source_file_dentry,source_new_dentry,source_sub_dentry,source_link_dentry};
  for(int i=0;i<5;i++){nm_inode_objects(native_inodes[i])->i_sb=(void*)&sb;nm_inode_objects(native_inodes[i])->i_op=native_iops;nm_inode_objects(native_inodes[i])->i_mapping=nm_inode_data(native_inodes[i]);((struct nm_inode_owner_prefix*)native_inodes[i])->i_mode=i==0||i==3?0040755:i==4?0120777:0100644;((struct nm_dentry_head*)native_dentries[i])->d_inode=native_inodes[i];*(u64*)((char*)native_inodes[i]+struct_offset.inode_size)=8192+i;*(u32*)((char*)native_inodes[i]+struct_offset.inode_nlink)=i==0||i==3?3:1;}
  kf_nm_kern_path=port_kern_path;kf_nm_path_put=port_path_put;kf_nm_vfs_path_lookup=port_path_lookup;
  kf_nm_new_inode=port_new;kf_nm_iget5_locked=port_iget;kf_nm_unlock_new_inode=port_unlock;kf_nm_set_nlink=port_nlink;
  kf_nm_d_splice_alias=port_splice;kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;kf_nm_d_drop=virtual_drop;
  kf_nm_dentry_open=port_open;kf_nm_fput=port_fput;kf_nm_vfs_getattr_nosec=port_stat;kf_nm_vfs_setpos=fixture_setpos;kf_nm_iterate_dir=port_iterate;kf_nm_vfs_llseek=fixture_seek;
  struct nm_topology_updates updates={0};struct nomount_rule* root_rule=port_rule("/back-root",1000);
  manager_depth=1;assert(!nm_topology_add_locked("/system/app/Package",19,root_rule,&updates));manager_depth=0;
  struct nm_topology_leaf* record=nm_topology_find("/system/app/Package",19);assert(record&&record->leaf->this_dir);
  for(int n=1;n<=1;n++){port_query_dentry(outer_root,"Package",root_dentry);fail_alloc=n;assert(PTR_ERR(nm_directory_lookup(parent,(void*)outer_root,0))==-ENOMEM&&root_rule->refs==1);fail_alloc=0;}
  iget_error=-ESTALE;assert(PTR_ERR(nm_directory_lookup(parent,(void*)outer_root,0))==-ESTALE&&root_rule->refs==1);iget_error=0;
  port_splice_error=1;assert(PTR_ERR(nm_directory_lookup(parent,(void*)outer_root,0))==-ELOOP&&root_rule->refs==1);port_splice_error=0;
  assert(!nm_directory_lookup(parent,(void*)outer_root,0));struct inode* root_inode=nm_dentry_inode(outer_root);assert(root_inode&&nm_is_directory_inode(root_inode)&&!nm_directory_proxy(nm_inode_ops(root_inode))&&root_rule->refs==2);
  int unlocked=cache_unlocks;port_query_dentry(outer_again,"Package",root_dentry);assert(!nm_directory_lookup(parent,(void*)outer_again,0)&&nm_dentry_inode(outer_again)==root_inode&&cache_unlocks==unlocked);
  assert(nm_dentry_revalidate((void*)outer_root,0)==1);
  port_alias_mode=1;port_query_dentry(outer_child,"Package",root_dentry);
  assert(nm_directory_lookup(parent,(void*)outer_child,0)==(void*)outer_again);
  nm_dentry_objects(outer_again)->d_op=NULL;
  port_query_dentry(outer_child,"Package",root_dentry);assert(PTR_ERR(nm_directory_lookup(parent,(void*)outer_child,0))==-EOPNOTSUPP);
  nm_dentry_objects(outer_again)->d_op=nm_owned_dentry_ops;port_alias_mode=0;
  ((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_inode=root_inode;
  ((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_op=nm_virtual_directory_fops;
  ((struct nm_path*)nm_file_path(outer_file))->dentry=outer_root;*(const void**)(outer_file+struct_offset.file_cred)=(void*)0xabc;
  read_denied=-EACCES;int opened=native_opens;assert(nm_open(root_inode,(void*)outer_file)==-EACCES&&native_opens==opened&&!nm_file_private(outer_file));read_denied=0;
  assert(!nm_open(root_inode,(void*)outer_file)&&nm_file_private(outer_file)==native_root_file&&permission_inode==(void*)source_root_inode);
  unsigned char stat[256];struct nm_path stat_path={.dentry=outer_root};assert(!nm_virtual_directory_getattr(&stat_path,(void*)stat,77,88)&&((struct nm_kstat_prefix*)stat)->ino==record->leaf->v_ino&&((struct nm_kstat_prefix*)stat)->dev==456&&((struct nm_kstat_prefix*)stat)->nlink==3);
  attr_error=-EIO;assert(nm_virtual_directory_getattr(&stat_path,(void*)stat,77,88)==-EIO);attr_error=0;
  struct nomount_rule* overlay=port_rule("/file",1000);manager_depth=1;assert(!nm_topology_add_locked("/system/app/Package/extra",25,overlay,&updates));manager_depth=0;
  port_query_dentry(outer_child,"extra",outer_root);int queried=path_queries;assert(!nm_directory_lookup(root_inode,(void*)outer_child,0)&&path_queries==queried&&nm_dentry_revalidate((void*)outer_child,0)==1);struct inode* overlay_inode=nm_dentry_inode(outer_child);
  struct nm_dir_context context={.actor=fixture_actor};reset_emit();
  int (*iterate)(struct file*,struct nm_dir_context*)=nm_operation_callback(nm_inode_file_ops(root_inode),struct_offset.fop_iterate_shared);
  assert(!iterate((void*)outer_file,&context)&&has_name("base.apk")&&!has_name("extra"));reset_emit();assert(!iterate((void*)outer_file,&context)&&has_name("extra"));
  assert(nm_virtual_directory_llseek((void*)outer_file,context.pos,0)==context.pos&&nm_virtual_directory_llseek((void*)outer_file,0,1)==context.pos);
  assert(!nm_virtual_directory_llseek((void*)outer_file,0,0));
  port_query_dentry(outer_child,"base.apk",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_child,0));struct inode* first_file=nm_dentry_inode(outer_child);assert(nm_is_file_inode(first_file)&&!nm_dentry_revalidate((void*)outer_child,0));
  struct nm_inode_info* first_info=nm_inode_private(first_file);assert(first_info->rule->published&&first_info->rule->refs==1&&first_info->rule->r_path.dentry==source_file_dentry);
  replaced_file=1;port_query_dentry(outer_child,"base.apk",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_child,0));struct inode* replacement_file=nm_dentry_inode(outer_child);assert(((struct nm_inode_info*)nm_inode_private(replacement_file))->rule->r_path.dentry==source_new_dentry&&first_info->rule->r_path.dentry==source_file_dentry);
  file_exists=0;port_query_dentry(outer_negative,"base.apk",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_negative,0)&&!nm_dentry_inode(outer_negative)&&!nm_dentry_revalidate((void*)outer_negative,0));file_exists=1;
  port_query_dentry(outer_negative,"base.apk",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_negative,0)&&nm_is_file_inode(nm_dentry_inode(outer_negative)));struct inode* appeared_file=nm_dentry_inode(outer_negative);
  port_query_dentry(outer_sub,"sub",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_sub,0));struct inode* sub_inode=nm_dentry_inode(outer_sub);assert(nm_is_directory_inode(sub_inode)&&!nm_dentry_revalidate((void*)outer_sub,0));
  port_query_dentry(outer_nested,"nested",outer_sub);assert(!nm_directory_lookup(sub_inode,(void*)outer_nested,0)&&nm_is_file_inode(nm_dentry_inode(outer_nested)));struct inode* nested_file=nm_dentry_inode(outer_nested);
  port_query_dentry(outer_child,"link",outer_root);int gets=data_gets,put_before=data_puts;assert(PTR_ERR(nm_directory_lookup(root_inode,(void*)outer_child,0))==-EOPNOTSUPP&&data_gets==gets+1&&data_puts==put_before+1);
  path_denied=-EACCES;port_query_dentry(outer_child,"base.apk",outer_root);assert(PTR_ERR(nm_directory_lookup(root_inode,(void*)outer_child,0))==-EACCES);path_denied=0;
  assert(!nm_uid_add(1000));queried=path_queries;port_query_dentry(outer_child,"base.apk",outer_root);assert(!nm_directory_lookup(root_inode,(void*)outer_child,0)&&!nm_dentry_inode(outer_child)&&path_queries==queried);assert(!nm_uid_del(1000));flush_rcu();
  // fallback 的分配失败均释放已取得的源 path；未发布 inode 时不留下额外引用。
  for(int n=1;n<=3;n++){port_query_dentry(outer_child,"sub",outer_root);gets=data_gets;put_before=data_puts;fail_alloc=n;assert(PTR_ERR(nm_directory_lookup(root_inode,(void*)outer_child,0))==-ENOMEM&&data_gets==gets+1&&data_puts==put_before+1);fail_alloc=0;drain();flush_rcu();}
  new_fail=1;port_query_dentry(outer_child,"base.apk",outer_root);gets=data_gets;put_before=data_puts;assert(PTR_ERR(nm_directory_lookup(root_inode,(void*)outer_child,0))==-ENOMEM&&data_gets==gets+1&&data_puts==put_before+1);new_fail=0;
  port_splice_error=1;port_query_dentry(outer_child,"base.apk",outer_root);assert(PTR_ERR(nm_directory_lookup(root_inode,(void*)outer_child,0))==-ELOOP);port_splice_error=0;
  assert(!nm_release(root_inode,(void*)outer_file)&&native_refs==0&&native_opens==native_closes);
  // 同一源权限策略也用于 fallback 普通文件；允许后由既有 read_iter 转交源 file。
  ((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_inode=first_file;
  ((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_op=nm_inode_engine.file_ops;
  read_denied=-EACCES;opened=native_opens;assert(nm_open(first_file,(void*)outer_file)==-EACCES&&native_opens==opened);read_denied=0;
  assert(!nm_open(first_file,(void*)outer_file)&&permission_inode==(void*)source_file_inode);
  struct nm_kiocb_head request={.ki_filp=(void*)outer_file,.ki_pos=9};
  assert(nm_read_iter((void*)&request,(void*)0xbeef)==17&&request.ki_filp==(void*)outer_file&&request.ki_pos==26);
  assert(!nm_release(first_file,(void*)outer_file)&&!native_refs&&native_opens==native_closes);
  clear_rules(&updates);assert(!nm_dentry_revalidate((void*)outer_root,0));
  port_iput(overlay_inode);port_iput(first_file);port_iput(replacement_file);port_iput(appeared_file);port_iput(nested_file);port_iput(sub_inode);port_iput(root_inode);port_iput(root_inode);
  assert(data_gets==data_puts&&anchor_gets==anchor_puts);
  nm_proxy_evict_inode(parent);flush_rcu();fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));
  int before=frees;nm_backing_open_permission=NULL;nm_discard_directory_view();assert(frees==before+5&&!nm_owned_dentry_ops&&!nm_virtual_directory_fops&&!nm_inode_engine.inode_ops&&!nm_inode_engine.lookup_backing);
  assert(!rcu_depth&&!spin_depth&&!hash_depth&&!q_count&&!native_refs&&permission_calls>=2);
  puts("backed inode cache, source permission, recursive lookup, cache refresh and path retirement: PASS");return 0;
}
'''
    c=args.output/'backing-inode.c';c.write_text(source)
    result=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-I'+str(root/'nomount'),'-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'backing-inode')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode()
    run=subprocess.run([str(args.output/'backing-inode')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    files=('nomount/nm_backing_inode.c','nomount/nm_inode.c','nomount/nm_offsets.c','nomount/nm_file.c','nomount/nm_virtual_directory.c','nomount/nm_directory.c','nomount/nm_topology.c','nomount/nm_directory_entry.c')
    receipt={'scope':'Developer host call contracts; not target ACL, VFS locks, concurrency or device proof','sources':{p:sha(root/p) for p in files},'tool_sha256':sha(Path(__file__)),'backing_oracle_sha256':sha(root/'nomount/tools/test_backing_directory.py'),'backing_receipt_sha256':sha(args.output/'backing-contract/receipt.json'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':main()
