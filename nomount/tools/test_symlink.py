#!/usr/bin/env python3
"""在冻结双 ABI 业务夹具中更新受影响生产函数，保留原断言，追加普通链接正反例。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
# 上一批实际执行并交接的生成夹具；这是 Oracle 输入完整性检查。
INPUTS = {'int': 'ebd15cf85ec7e093945b3c4dd54b7d7aaeaa68edfb20a30b6ba66f9f662a54b9',
          'bool': '5713b9f13c9b781e7bed50b791c925b0f8fb54bfd7091a0cf6d26e6cd44def67'}
FIXTURE = r'''
struct delayed_call {void (*fn)(void*);void* arg;};
static int link_api, link_missing, link_native_error, link_calls, link_cleanups, link_magic_calls;
static const char* link_text="../relative";
static void link_cleanup(void* arg){assert(arg==backing);link_cleanups++;}
static const char* link_simple(struct dentry* d,struct inode* i,struct delayed_call* done){
 assert(d==(void*)dentry_storage&&i==backing&&done);return link_text;
}
static const char* link_page(struct dentry* d,struct inode* i,struct delayed_call* done){
 assert(d==(void*)dentry_storage&&i==backing&&done);done->fn=link_cleanup;done->arg=i;return link_text;
}
static const char* link_simple_jump(struct dentry* d,struct inode* i,struct delayed_call* done){return link_simple(d,i,done);}
static const char* link_page_jump(struct dentry* d,struct inode* i,struct delayed_call* done){return link_page(d,i,done);}
static const char* link_magic(struct dentry* d,struct inode* i,struct delayed_call* done){link_magic_calls++;return NULL;}
static const char* link_vfs_get(struct dentry* d,struct delayed_call* done){
 assert(d==(void*)dentry_storage&&done);link_calls++;
 if(link_native_error)return ERR_PTR(link_native_error);
 const struct nm_inode_link_ops* ops=nm_inode_ops(backing);return ops->get_link(d,backing,done);
}
static int link_child_lookup(struct dentry* base,struct vfsmount* mnt,const char* name,unsigned int flags,struct nm_path* out){
 assert(base==(void*)tree_dentry[0]&&(void*)mnt==(void*)1&&!strcmp(name,"link")&&!flags);
 *out=backing_path;binding_owned_gets++;return 0;
}
static unsigned long symlink_fixture_lookup(const char* name){
 if(link_api){
  if(!strcmp(name,"vfs_get_link"))return link_missing==1?0:(uintptr_t)link_vfs_get;
  if(!strcmp(name,"vfs_readlink"))return link_missing==2?0:1;
  if(link_missing!=3){
   if(!strcmp(name,"simple_get_link"))return (uintptr_t)link_simple;
   if(!strcmp(name,"page_get_link"))return (uintptr_t)link_page;
   if(!strcmp(name,"simple_get_link.cfi_jt"))return (uintptr_t)link_simple_jump;
   if(!strcmp(name,"page_get_link.cfi_jt"))return (uintptr_t)link_page_jump;
  }
 }
 return inode_fixture_lookup(name);
}
static void check_symlinks(void){
 link_api=1;security_fixture_reset();security_target();
 kf_nm_new_inode=host_new;kf_nm_d_splice_alias=host_splice;kf_nm_vfs_getattr_nosec=host_attr;nm_vfs_getattr_pair=NULL;
 assert(nm_inode_engine.symlink_ops);
 assert(nm_operation_callback(nm_inode_engine.symlink_ops,offsetof(struct nm_inode_link_ops,get_link))==nm_symlink_get_link);
 assert(nm_operation_callback(nm_inode_engine.symlink_ops,struct_offset.iop_getattr)==nm_file_getattr_callback());
 assert(!nm_operation_callback(nm_inode_engine.symlink_ops,0));
 void* extra=(void*)123;
 for(link_missing=1;link_missing<=3;link_missing++){
  assert(!nm_new_symlink_operations(&extra)&&!extra);
 }
 link_missing=0;assert(!nm_new_symlink_operations(&extra)&&extra);nm_discard_operations(extra);
 int saved_slot=struct_offset.iop_getattr,saved_size=struct_offset.inode_ops_size;
 const int bad_slots[]={-8,0,8,512};
 for(unsigned i=0;i<4;i++){struct_offset.iop_getattr=bad_slots[i];assert(nm_new_symlink_operations(&extra)==-EINVAL&&!extra);}
 struct_offset.iop_getattr=saved_slot;struct_offset.inode_ops_size=-8;assert(nm_new_symlink_operations(&extra)==-EINVAL&&!extra);struct_offset.inode_ops_size=saved_size;

 _Alignas(8) unsigned char source_ops[512]={0}, outer_dentry[256]={0};
 nm_inode_objects(backing)->i_op=source_ops;
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0120777;security_set_sid(backing,37);
 nm_set_operation_callback(source_ops,offsetof(struct nm_inode_link_ops,get_link),link_simple);
 assert(nm_plain_symlink_source(backing));
 assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,&(struct nomount_rule){.r_path=backing_path},42))==-EOPNOTSUPP);
 struct nm_path path=backing_path;
 struct nomount_rule* rule=nm_take_backing_child_rule(&path,1000);
 assert(!IS_ERR(rule)&&!path.dentry&&rule->r_path.dentry==backing_path.dentry&&rule->refs==1);
 int gets=binding_owned_gets,put_count=binding_owned_puts;
 assert(!nm_materialize_symlink(parent,(void*)1234,rule,42)&&created);
 struct inode* link=created;((struct nm_dentry_head*)outer_dentry)->d_inode=link;
 assert(nm_is_virtual_inode(link)&&nm_is_symlink_inode(link)&&!nm_is_file_inode(link));
 assert(nm_inode_mapping(link)==nm_inode_data(link)&&nm_inode_mapping(link)!=nm_inode_mapping(backing));
 assert(nm_inode_mode(link)==0120777&&!(((struct nm_inode_owner_prefix*)link)->i_opflags&4));
 assert(!*(const void**)((char*)link+struct_offset.inode_file_ops));
 assert(nm_inode_secid(link)==37&&binding_owned_gets==gets+1);
 nm_rule_put(rule);assert(binding_owned_puts==put_count+1);
 struct delayed_call done={0};int calls=link_calls,allocs=alloc_calls;
 assert(PTR_ERR(nm_symlink_get_link(NULL,(void*)1,(void*)1))==-ECHILD&&link_calls==calls);
 assert(PTR_ERR(nm_symlink_get_link((void*)outer_dentry,backing,&done))==-EIO&&link_calls==calls);
 assert(PTR_ERR(nm_symlink_get_link((void*)outer_dentry,link,NULL))==-EIO&&link_calls==calls);
 assert(!strcmp(nm_symlink_get_link((void*)outer_dentry,link,&done),"../relative")&&!done.fn);
 link_text="/absolute/target";assert(!strcmp(nm_symlink_get_link((void*)outer_dentry,link,&done),link_text));
 link_text="";assert(!strcmp(nm_symlink_get_link((void*)outer_dentry,link,&done),""));link_text="../relative";
 void* callbacks[]={link_simple,link_simple_jump,link_page,link_page_jump};
 for(unsigned i=0;i<4;i++){
  nm_set_operation_callback(source_ops,offsetof(struct nm_inode_link_ops,get_link),callbacks[i]);done=(struct delayed_call){0};
  assert(nm_symlink_get_link((void*)outer_dentry,link,&done)==link_text);
  if(i>=2){assert(done.fn&&done.arg==backing);done.fn(done.arg);}
  else assert(!done.fn);
 }
 assert(link_cleanups==2&&alloc_calls==allocs);
 link_native_error=-EACCES;done=(struct delayed_call){0};assert(PTR_ERR(nm_symlink_get_link((void*)outer_dentry,link,&done))==-EACCES&&!done.fn);link_native_error=0;
 nm_set_operation_callback(source_ops,offsetof(struct nm_inode_link_ops,get_link),link_magic);calls=link_calls;
 assert(PTR_ERR(nm_symlink_get_link((void*)outer_dentry,link,&done))==-EOPNOTSUPP&&!link_magic_calls&&link_calls==calls);
 path=backing_path;assert(PTR_ERR(nm_take_backing_child_rule(&path,1000))==-EOPNOTSUPP&&path.dentry);
 assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&(struct nomount_rule){.r_path=backing_path},42))==-EOPNOTSUPP);
 nm_set_operation_callback(source_ops,offsetof(struct nm_inode_link_ops,get_link),NULL);assert(!nm_plain_symlink_source(backing));
 nm_inode_objects(backing)->i_op=NULL;assert(!nm_plain_symlink_source(backing));nm_inode_objects(backing)->i_op=source_ops;
 nm_set_operation_callback(source_ops,offsetof(struct nm_inode_link_ops,get_link),link_simple);
 unsigned char stat[256];struct nm_path outer_path={.dentry=(void*)outer_dentry};assert(!nm_file_getattr(&outer_path,(void*)stat,77,88));
 assert(((struct nm_kstat_prefix*)stat)->ino==42&&((struct nm_kstat_prefix*)stat)->dev==sb.s_dev);
 host_iput(link);drain();assert(binding_owned_puts==put_count+2&&!created);
 struct nomount_rule candidate={.r_path=backing_path,.refs=1};
 gets=binding_owned_gets;put_count=binding_owned_puts;
 fail_alloc=1;assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&candidate,42))==-ENOMEM);fail_alloc=0;
 new_fail=1;assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&candidate,42))==-ENOMEM);new_fail=0;
 assert(binding_owned_gets==gets&&binding_owned_puts==put_count);
 security_notify_error=-EACCES;assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&candidate,42))==-EACCES&&!created);security_notify_error=0;
 assert(binding_owned_gets==gets+1&&binding_owned_puts==put_count+1);
 splice_fail=1;assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&candidate,42))==-ELOOP&&!created);splice_fail=0;drain();
 assert(binding_owned_gets==gets+2&&binding_owned_puts==put_count+2&&candidate.refs==1);
 void* saved=nm_inode_engine.symlink_ops;nm_inode_engine.symlink_ops=NULL;
 path=backing_path;assert(PTR_ERR(nm_take_backing_child_rule(&path,1000))==-EOPNOTSUPP&&path.dentry);
 assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&candidate,42))==-EOPNOTSUPP);nm_inode_engine.symlink_ops=saved;

 _Alignas(8) unsigned char directory[768]={0};struct nm_inode_info dir_info={.r_path={(void*)1,(void*)tree_dentry[0]}};
 nm_inode_objects(directory)->i_op=nm_inode_engine.directory_ops;nm_inode_objects(directory)->i_sb=(void*)&sb;nm_set_inode_private(directory,&dir_info);
 ((struct nm_dentry_head*)tree_dentry[0])->d_inode=(void*)tree_inode[0];((struct nm_inode_owner_prefix*)tree_inode[0])->i_mode=0040755;nm_inode_objects(tree_inode[0])->i_op=native_iops;
 kf_nm_vfs_path_lookup=link_child_lookup;kf_nm_d_splice_alias=port_splice;port_query_dentry(outer_root,"link",root_dentry);
 gets=binding_owned_gets;put_count=binding_owned_puts;
 assert(!nm_lookup_backing_directory((void*)directory,(void*)outer_root,0)&&nm_is_symlink_inode(nm_dentry_inode(outer_root)));
 assert(binding_owned_gets==gets+2&&binding_owned_puts==put_count+1);
 assert(!strcmp(nm_symlink_get_link((void*)outer_root,nm_dentry_inode(outer_root),&done),"../relative"));
 assert(!nm_dentry_revalidate((void*)outer_root,0));
 host_iput(created);drain();((struct nm_dentry_head*)outer_root)->d_inode=NULL;
 assert(binding_owned_puts==put_count+2);kf_nm_d_splice_alias=host_splice;
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0020600;assert(!nm_plain_symlink_source(backing));
 path=backing_path;assert(PTR_ERR(nm_take_backing_child_rule(&path,1000))==-EOPNOTSUPP&&path.dentry);
 nm_discard_directory_view();assert(!nm_inode_engine.symlink_ops&&!nm_inode_engine.inode_ops);
 int before=frees;fail_alloc=3;assert(nm_prepare_inode_engine()==-ENOMEM&&!nm_inode_engine.inode_ops&&frees==before+2);fail_alloc=0;
 assert(!nm_prepare_inode_engine()&&nm_inode_engine.symlink_ops);nm_discard_directory_view();
 assert(security_gets==security_releases&&!link_magic_calls&&!pending_rcu);
 puts("ordinary symlinks: capability gates, callback identities, RCU rejection, strings, cleanup, attributes, independent bindings and failure reclamation PASS");
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    results=[]
    for abi,digest in INPUTS.items():
        original=(a.oracle_output/abi/'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest()==digest
        source=original
        block=re.search(r'#ifndef __NM_STRUCTS_H\b.*?#endif',source,re.S);assert block
        header=(ROOT/'nomount/nm_structs.h').read_text();source=source[:block.start()]+header[header.index('#ifndef '):]+source[block.end():]
        offsets=(ROOT/'nomount/nm_offsets.c').read_text()
        source=source.replace(function(source,'nm_operation_size'),function(source,'nm_operation_size')+'\nstatic bool nm_owned_operation_fallback;\n'+function(offsets,'nm_owned_operation_size'),1)
        current=(ROOT/'nomount/nm_inode.c').read_text()
        block=re.search(r'struct nm_inode_engine \{.*?\n\};',source,re.S);assert block
        engine=re.search(r'struct nm_inode_engine \{.*?\n\};',current,re.S).group()
        source=source[:block.start()]+engine+source[block.end():]
        source=source.replace('static struct nm_inode_engine nm_inode_engine;', '''static struct nm_inode_engine nm_inode_engine;
static unsigned long symlink_fixture_lookup(const char*);
static const char* kfunc_def(nm_vfs_get_link)(struct dentry*,struct delayed_call*);
static uintptr_t nm_plain_link_callbacks[4];''',1)
        helpers='\n'.join(function(current,n) for n in ('nm_is_symlink_inode','nm_plain_symlink_source','nm_symlink_get_link'))
        source=source.replace(function(source,'nm_is_virtual_inode'),helpers+'\n'+function(current,'nm_is_virtual_inode'),1)
        for n in ('nm_file_getattr','nm_prepare_inode_engine'):
            source=source.replace(function(source,n),function(current,n),1)
        helpers='\n'.join(function(current,n) for n in ('nm_new_symlink_operations','nm_materialize_backed_inode','nm_materialize_file','nm_materialize_symlink'))
        helpers=helpers.replace('kallsyms_lookup_name_by_suffix(', 'symlink_fixture_lookup(')
        source=source.replace(function(source,'nm_materialize_file'),helpers,1)
        for file,names in {'nm_backing_inode.c':['nm_take_backing_child_rule','nm_lookup_backing_directory'],
                           'nm_directory_entry.c':['nm_discard_directory_view']}.items():
            for n in names:source=source.replace(function(source,n),function((ROOT/'nomount'/file).read_text(),n),1)
        before=re.findall(r'\bassert\s*\([^;]+\);',original)
        assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
        source=source.replace('int main(void){assert(!previous_security_main());','static int previous_link_main(void){assert(!previous_security_main());',1)
        source+=FIXTURE+'\nint main(void){assert(!previous_link_main());check_symlinks();return 0;}\n'
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.oracle_output/'v22-base/cli.c'),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        results.append({'abi':abi,'prior_assertions_preserved':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',FIXTURE))+1,'result':'PASS'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'affected production functions with host VFS/LSM/path stubs; not native pathwalk/CFI/concurrency proof','results':results},indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
