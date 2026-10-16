#!/usr/bin/env python3
"""迁移已冻结引用Oracle，逐项列出契约变更并验证inode独立绑定。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from test_directory_abis import function

BASE = '0ebd44d5a6378ad1260b9cd3a1ac51e1e9e43265'
ORACLES = {'int': '681a320ac5551b61bc22b02ed0824ac8143cfcf5f5d0c8e8d7331d1eb0223000', 'bool': '585a8287a2cd4b3f8c10095e4c82e1838f2d3c3b6b5957134bd22a749019c3d1'}
CHANGED = {
 'nm_rules.c':['nm_prepare_rule_functions'],
 'nm_file.c':['nm_open'],
 'nm_inode.c':['nm_file_getattr','nm_proxy_evict_inode','nm_materialize_file'],
 'nm_directory.c':['nm_dentry_validate','nm_directory_lookup'],
 'nm_virtual_directory.c':['nm_cached_directory_test','nm_materialize_virtual_directory','nm_virtual_directory_getattr_context','nm_virtual_directory_llseek','nm_virtual_directory_iterate'],
 'nm_backing_inode.c':['nm_lookup_backing_directory'],
 'nm_backing_subtree.c':['nm_inherit_backing_directory','nm_check_backing_directory_search'],
}

def sha(raw):return hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
    old=lambda f:subprocess.check_output(['git','show',BASE+':nomount/'+f],cwd=root).decode()
    new=lambda f:(root/'nomount'/f).read_text()
    results=[]
    for abi,digest in ORACLES.items():
        original=(a.oracle_output/abi/'contracts.c').read_text();assert sha(original.encode())==digest
        source=original.replace(old('nm_rules.h'),new('nm_rules.h'))
        assert original.count(old('nm_rules.h'))==1
        for filename,names in CHANGED.items():
            for name in names:
                before=function(source,name);after=function(new(filename),name)
                if name=='nm_proxy_evict_inode':after=after.replace('nm_rcu_call(', 'inode_fixture_rcu_call(')
                assert source.count(before)==1,name
                source=source.replace(before,after)
        helpers='\n'.join(function(new('nm_inode.c'),n) for n in ['nm_bind_inode_path','nm_put_inode_binding','nm_inode_matches_binding'])
        source=source.replace('static struct nm_inode_engine nm_inode_engine;','static struct nm_inode_engine nm_inode_engine;\n'+helpers,1)
        source=source.replace('static void (*kf_nm_path_put)(const struct nm_path*) = host_path_put;', 'static void binding_fixture_get(const struct nm_path*);\nstatic void (*kf_nm_path_get)(const struct nm_path*) = binding_fixture_get;\nstatic void (*kf_nm_path_put)(const struct nm_path*) = host_path_put;',1)
        source=source.replace('if(!strcmp(name,"path_put"))return (uintptr_t)host_path_put;', 'if(!strcmp(name,"path_get"))return (uintptr_t)binding_fixture_get;\n  if(!strcmp(name,"path_put"))return (uintptr_t)host_path_put;',1)
        # 不同来源替换夹具取得不同path，保留原失效断言。
        source=source.replace("static int fixture_path(const char* name,unsigned int flags,struct nm_path* path) {assert(name[0]=='/'&&flags==1);*path=backing_path;return 0;}",'static _Alignas(8) unsigned char binding_new_dentry[256];\nstatic int fixture_path(const char* name,unsigned int flags,struct nm_path* path) {assert(name[0]==\'/\'&&flags==1);*path=backing_path;if(!strcmp(name,"/new")){((struct nm_dentry_head*)binding_new_dentry)->d_inode=backing;path->dentry=(void*)binding_new_dentry;}return 0;}',1)
        # 原有夹具对私有info字段的访问迁移；生产函数已完整从当前文件取得。
        source=source.replace('info->rule->r_path','info->r_path').replace('first_info->rule->r_path','first_info->r_path').replace('))->rule->r_path', '))->r_path')
        source=source.replace('info&&info->rule&&info->dir_node','info&&info->initialized&&info->dir_node')
        source=source.replace('((struct nm_inode_info*)data)->rule','((struct nm_inode_info*)data)->dir_node')
        source=source.replace('struct nm_inode_info candidate={.rule=rule,.dir_node=child_node}', 'struct nm_inode_info candidate={.r_path=rule->r_path,.flags=rule->flags,.dir_node=child_node}')
        source=source.replace('info.rule=&rule;rule.r_path=path;', 'info.r_path=path;').replace('info.rule=NULL;', 'info.r_path=(struct nm_path){0};')
        source=source.replace('first_info->rule->published&&first_info->rule->refs==1&&first_info->r_path.dentry==source_file_dentry', 'first_info->initialized&&first_info->flags==0&&first_info->r_path.dentry==source_file_dentry')
        # inode不再增加管理规则引用；旧refs=2断言迁移为refs=1。
        source=source.replace('rule->refs==2','rule->refs==1').replace('root_rule->refs==2','root_rule->refs==1')
        source=source.replace('static int fail_alloc, alloc_calls, frees, path_puts, in_rcu;', 'static int fail_alloc, alloc_calls, frees, path_puts, in_rcu;\nstatic const void* binding_watched_rule;static int binding_freed_rules;')
        source=source.replace('assert(p); frees++; free((void*)p);', 'assert(p);if(p==binding_watched_rule){binding_freed_rules++;binding_watched_rule=NULL;} frees++; free((void*)p);')
        source=source.replace('nm_rule_put(rule);assert(rule->refs==1 && !path_puts);host_iput(created);assert(path_puts==1 && pending_rcu && truncates==1 && clears==1);', 'binding_watched_rule=rule;int freed_before=binding_freed_rules;nm_rule_put(rule);assert(binding_freed_rules==freed_before+1 && path_puts==1);host_iput(created);assert(path_puts==2 && pending_rcu && truncates==1 && clears==1);')
        source=source.replace('assert(!nm_remove_child(&root_node->children,leaf));assert(!nm_remove_leaf_rule(leaf,0,&updates));', 'assert(!nm_remove_child(&root_node->children,leaf));binding_watched_rule=rule;int retired_before=binding_freed_rules;assert(!nm_remove_leaf_rule(leaf,0,&updates));')
        source=source.replace('assert(rule->refs==1&&!nm_dentry_revalidate((void*)virtual_dentry,0));','assert(binding_freed_rules==retired_before+1&&!nm_dentry_revalidate((void*)virtual_dentry,0));')
        # 显式path_get增加夹具的来源引用计数；总获取/释放平衡断言保留。
        source+=r'''
static int binding_path_gets;
static void binding_fixture_get(const struct nm_path* path){
 assert(path&&path->dentry&&!in_rcu);binding_path_gets++;
 if(kf_nm_path_put==port_path_put){assert(path->mnt==(void*)0x123);data_gets++;}
 else if(kf_nm_path_put==tree_put){assert(path->mnt==(void*)0x123);tree_gets++;}
}
'''
        source=source.replace('#define NM_KPM_VERSION "0.4.3"','#define NM_KPM_VERSION "0.5.0"')
        assertions=re.findall(r'\bassert\s*\([^;]+\);',original)
        current=re.findall(r'\bassert\s*\([^;]+\);',source)
        assert len(current)==len(assertions)+3, (len(current),len(assertions))
        # 新辅助函数末尾的3条断言排除后，原有用例逐项对应；任何变化都进迁移清单。
        migration=[dict(index=i,old=before,new=after,reason='inode binding owns independent path/node; private-field/hash and rule-refcount contract migration') for i,(before,after) in enumerate(zip(assertions,current[:len(assertions)])) if before!=after]
        source=source.replace('int main(void){assert(!previous_memory_main());', 'static int previous_binding_main(void){assert(!previous_memory_main());',1)
        source+=r'''
static int binding_owned_gets,binding_owned_puts,binding_opens,binding_closes,binding_permissions;
static int binding_permission(const struct nm_path* path){assert(path->dentry==(void*)dentry_storage);binding_permissions++;return 0;}
static struct file* binding_open(const struct nm_path* path,int flags,const struct cred* cred){assert(path->dentry==(void*)dentry_storage&&!flags&&cred==(void*)0xabc);binding_opens++;return (void*)native_regular_file;}
static void binding_fput(struct file* file){assert(file==(void*)native_regular_file);binding_closes++;}
static void binding_owned_get(const struct nm_path* path){assert(path->dentry==(void*)dentry_storage&&!in_rcu);binding_owned_gets++;}
static void binding_owned_put(const struct nm_path* path){assert(path->dentry==(void*)dentry_storage&&!in_rcu);binding_owned_puts++;}
static void check_bindings(void){
 target();directory_target();missing="path_get";assert(nm_prepare_rule_functions()==-ENOENT);missing=NULL;assert(!nm_prepare_rule_functions());fail_alloc=0;new_fail=splice_fail=0;kf_nm_kmalloc=memory_slab_miss;kf_nm_vzalloc=host_alloc;kf_nm_kvfree=memory_vmap_free;kf_nm_is_vmalloc_addr=memory_vmap;kf_nm_vfree_atomic=memory_vmap_free;kf_nm_vfree=fixture_vfree;
 nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;kf_nm_path_get=binding_owned_get;kf_nm_path_put=binding_owned_put;
 assert(!nm_prepare_inode_engine());assert(!nm_prepare_directory_engine());assert(!nm_prepare_virtual_directory_engine());
 nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;assert(!nm_install_super_proxy((void*)&sb));
 ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;nm_inode_objects(backing)->i_mapping=(void*)9876;
 struct nomount_rule* rule=calloc(1,sizeof(*rule));rule->r_path=backing_path;rule->refs=1;
 kf_nm_d_splice_alias=host_splice;assert(!nm_materialize_file(parent,(void*)1234,rule,42)&&rule->refs==1&&binding_owned_gets==1);
 struct inode* file_inode=created;assert(nm_inode_private(file_inode)&&((struct nm_inode_info*)nm_inode_private(file_inode))->r_path.dentry==backing_path.dentry);
 binding_watched_rule=rule;int freed=binding_freed_rules;nm_rule_put(rule);assert(binding_freed_rules==freed+1&&binding_owned_puts==1);
 nm_rcu_read_lock();assert(nm_inode_matches_binding(file_inode,&backing_path,NULL,0));nm_rcu_read_unlock();
 struct nm_path wrong=backing_path;wrong.mnt=(void*)0x765;nm_rcu_read_lock();assert(!nm_inode_matches_binding(file_inode,&wrong,NULL,0)&&!nm_inode_matches_binding(file_inode,&backing_path,NULL,NM_FLAG_IS_DIR));nm_rcu_read_unlock();
 kf_nm_dentry_open=binding_open;kf_nm_fput=binding_fput;nm_backing_open_permission=binding_permission;
 memset(outer_file,0,sizeof(outer_file));((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_inode=file_inode;*(void**)(outer_file+struct_offset.file_cred)=(void*)0xabc;
 assert(!nm_open(file_inode,(void*)outer_file)&&binding_permissions==1&&binding_opens==1);
 ((struct nm_file_inode_ops*)(native_regular_file+struct_offset.file_inode_ops))->f_op=native_fops;((struct nm_file_io_ops*)native_fops)->read_iter=port_read;
 struct nm_kiocb_head request={.ki_filp=(void*)outer_file};assert(nm_read_iter((void*)&request,(void*)0xbeef)==17&&request.ki_filp==(void*)outer_file&&request.ki_pos==17);
 assert(!nm_release(file_inode,(void*)outer_file)&&binding_closes==1&&!nm_file_private(outer_file));
 eviction_target=file_inode;host_iput(file_inode);drain();assert(binding_owned_puts==2&&binding_owned_gets==1);
 struct nm_directory_node* node=nm_new_directory_node();assert(node);((struct nm_inode_owner_prefix*)backing)->i_mode=0040755;
 nm_inode_engine.lookup_backing=nm_lookup_backing_directory;kf_nm_iget5_locked=port_iget;kf_nm_unlock_new_inode=port_unlock;kf_nm_set_nlink=port_nlink;kf_nm_d_splice_alias=port_splice;
 struct nomount_rule* a=calloc(1,sizeof(*a));a->r_path=backing_path;a->flags=NM_FLAG_IS_DIR;a->refs=1;
 port_query_dentry(outer_root,"bound",root_dentry);assert(!nm_materialize_virtual_directory(parent,(void*)outer_root,a,node,43));struct inode* first=nm_dentry_inode(outer_root);assert(first&&a->refs==1&&node->refs==2);
 struct nomount_rule* b=calloc(1,sizeof(*b));b->r_path=backing_path;b->flags=NM_FLAG_IS_DIR;b->refs=1;
 int gets=binding_owned_gets,put_count=binding_owned_puts;port_query_dentry(outer_again,"bound",root_dentry);assert(!nm_materialize_virtual_directory(parent,(void*)outer_again,b,node,43)&&nm_dentry_inode(outer_again)==first&&b->refs==1&&node->refs==2&&binding_owned_gets==gets+1&&binding_owned_puts==put_count+1);
 struct nm_inode_info candidate={.r_path=backing_path,.flags=NM_FLAG_IS_DIR,.dir_node=node};assert(nm_cached_directory_test(first,&candidate));
 struct nm_inode_owner_prefix* source=(void*)backing;u32 saved_uid=source->i_uid,saved_gid=source->i_gid;u16 saved_mode=source->i_mode;
 candidate.r_path.mnt=(void*)0x765;assert(!nm_cached_directory_test(first,&candidate));candidate.r_path=backing_path;candidate.flags=NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR;assert(!nm_cached_directory_test(first,&candidate));candidate.flags=NM_FLAG_IS_DIR;candidate.dir_node=NULL;assert(!nm_cached_directory_test(first,&candidate));candidate.dir_node=node;
 source->i_uid++;assert(!nm_cached_directory_test(first,&candidate));source->i_uid=saved_uid;source->i_gid++;assert(!nm_cached_directory_test(first,&candidate));source->i_gid=saved_gid;source->i_mode^=1;assert(!nm_cached_directory_test(first,&candidate));
 port_query_dentry(outer_child,"bound",root_dentry);assert(!nm_materialize_virtual_directory(parent,(void*)outer_child,b,node,43)&&nm_dentry_inode(outer_child)!=first);struct inode* changed=nm_dentry_inode(outer_child);source->i_mode=saved_mode;
 struct nm_inode_info* existing=nm_inode_private(first);__atomic_store_n(&existing->initialized,false,__ATOMIC_RELEASE);source->i_uid++;assert(nm_cached_directory_test(first,&candidate));__atomic_store_n(&existing->initialized,true,__ATOMIC_RELEASE);assert(!nm_cached_directory_test(first,&candidate));source->i_uid=saved_uid;
 nm_rule_put(a);nm_rule_put(b);assert(((struct nm_inode_info*)nm_inode_private(first))->r_path.dentry==backing_path.dentry&&node->refs==3);
 port_iput(first);port_iput(first);port_iput(changed);assert(node->refs==1);nm_directory_node_put(node);flush_rcu();
 assert(binding_owned_puts==binding_owned_gets+3);assert(!rcu_depth&&!spin_depth&&!hash_depth&&!q_count);
 puts("independent inode binding: rule freed while inode alive, same-source cache reuse, owner changes and initialization, path/node cleanup: PASS");
}
int main(void){assert(!previous_binding_main());check_bindings();return 0;}
'''
        out=a.output/abi;out.mkdir();c=out/'contracts.c';c.write_text(source)
        built=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(root/'nomount'),'-fsanitize=address,undefined','-g',str(c),'-o',str(out/'contracts')],capture_output=True,text=True);(out/'compile.log').write_text(built.stdout+built.stderr);built.check_returncode()
        run=subprocess.run([str(out/'contracts')],capture_output=True,text=True);(out/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
        results.append(dict(abi=abi,oracle_sha256=digest,original_assertions=len(assertions),unchanged_assertions=len(assertions)-len(migration),assertion_migration=migration,generated_sha256=sha(source.encode()),stdout=run.stdout))
    (a.output/'receipt.json').write_text(json.dumps(dict(scope='Developer host contract migration, requires Auditor review; not runtime acceptance',results=results),indent=2)+'\n')
    print('int/bool full Oracle migration and independent inode binding: PASS')

if __name__=='__main__':main()
