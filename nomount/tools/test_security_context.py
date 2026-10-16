#!/usr/bin/env python3
"""保留冻结inode Oracle，追加原生安全标签及失败生命周期契约。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from test_directory_abis import function

BASE = '773385757fcaaa6588e7946862e6784842c1901c'
ORACLES = {'int': '41f7f250e1754bac0a613ff36432b6c0b07d28fa947f7452754563e56cff2c89',
           'bool': '2b8c3e569cf8a7e99aba4da018b350041583dbacfc66ab28a343cc18e8636ae6'}
CHANGED = {'nm_inode.c': ['nm_inode_matches_binding', 'nm_prepare_inode_functions', 'nm_materialize_file'],
           'nm_directory.c': ['nm_dentry_validate'],
           'nm_virtual_directory.c': ['nm_cached_directory_test', 'nm_materialize_virtual_directory']}

PROTOTYPES = r'''
static int security_fixture_get(struct inode*,void**,u32*);
static int security_fixture_notify(struct inode*,void*,u32);
static void security_fixture_release(char*,u32);
static void security_fixture_sid(struct inode*,u32*);
static void security_fixture_iput(struct inode*);
'''

FIXTURE = r'''
struct security_fixture_label {struct inode* inode;u32 sid;};
static struct security_fixture_label security_labels[1024];
static int security_get_error,security_notify_error,security_noop,security_empty,security_relabel;
static int security_gets,security_releases,security_notifies,security_hold_waiter,security_iputs;
static struct inode* security_waiter;
static u32 security_sid_value(struct inode* inode){
 for(unsigned i=0;i<1024;i++)if(security_labels[i].inode==inode)return security_labels[i].sid;
 return 1;
}
static void security_set_sid(struct inode* inode,u32 sid){
 for(unsigned i=0;i<1024;i++)if(security_labels[i].inode==inode||!security_labels[i].inode){security_labels[i]=(struct security_fixture_label){inode,sid};return;}
 assert(0);
}
static int security_fixture_get(struct inode* inode,void** data,u32* length){
 assert(inode&&!in_rcu&&!rcu_depth&&!hash_depth&&!spin_depth&&!manager_depth);
 if(security_get_error)return security_get_error;
 *data=malloc(sizeof(u32));assert(*data);*(u32*)*data=security_sid_value(inode);*length=security_empty?0:sizeof(u32);security_gets++;
 if(security_relabel)security_set_sid(inode,security_sid_value(inode)+1);
 return 0;
}
static void security_fixture_release(char* data,u32 length){
 assert(data&&!in_rcu&&!rcu_depth&&!hash_depth&&!spin_depth);security_releases++;free(data);
}
static void security_fixture_sid(struct inode* inode,u32* sid){assert(inode&&sid);*sid=security_sid_value(inode);}
static int security_fixture_notify(struct inode* inode,void* data,u32 length){
 assert(!in_rcu&&!rcu_depth&&!hash_depth&&!spin_depth&&data&&length==sizeof(u32));
 assert(nm_inode_mode(inode)&0170000);security_notifies++;
 if(security_hold_waiter){
  struct nm_inode_info* info=nm_inode_private(inode);assert(info&&!info->initialized);
  assert(nm_cached_directory_test(inode,info));cache[port_slot(inode)].refs++;security_waiter=inode;
 }
 if(security_notify_error)return security_notify_error;
 if(!security_noop)security_set_sid(inode,*(u32*)data);
 return 0;
}
static void security_fixture_iput(struct inode* inode){
 security_iputs++;
 for(int i=0;i<32;i++)if(cache[i].inode==inode){port_iput(inode);return;}
 if(inode==cached_directory){virtual_iput(inode);return;}
 eviction_target=inode;host_iput(inode);drain();
}
static struct inode* security_waiter_iget(struct super_block* sb,unsigned long hash,int(*test)(struct inode*,void*),int(*set)(struct inode*,void*),void* data){
 assert(security_waiter&&((struct nm_inode_info*)nm_inode_private(security_waiter))->initialized);
 struct inode* inode=security_waiter;security_waiter=NULL;return inode;
}
static void security_fixture_reset(void){
 memset(security_labels,0,sizeof(security_labels));security_get_error=security_notify_error=security_noop=security_empty=security_relabel=security_hold_waiter=0;
 assert(!security_waiter);
}
static void security_target(void){
 target();directory_target();fail_alloc=new_fail=splice_fail=iget_error=port_splice_error=port_alias_mode=0;
 nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;
 kf_nm_kmalloc=memory_slab_miss;kf_nm_vzalloc=host_alloc;kf_nm_kvfree=memory_vmap_free;kf_nm_is_vmalloc_addr=memory_vmap;kf_nm_vfree_atomic=memory_vmap_free;
 kf_nm_path_get=binding_owned_get;kf_nm_path_put=binding_owned_put;
 assert(!nm_prepare_inode_engine());assert(!nm_prepare_directory_engine());assert(!nm_prepare_virtual_directory_engine());
 nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;assert(!nm_install_super_proxy((void*)&sb));
 ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;nm_inode_objects(backing)->i_mapping=(void*)9876;
 kf_nm_new_inode=port_new;kf_nm_iget5_locked=port_iget;kf_nm_unlock_new_inode=port_unlock;kf_nm_set_nlink=port_nlink;kf_nm_d_splice_alias=port_splice;
 nm_inode_engine.lookup_backing=nm_lookup_backing_directory;
}
static void security_query(void* d){port_query_dentry(d,"label",root_dentry);}
static void check_security_context(void){
 assert(security_gets==security_releases);security_fixture_reset();security_target();
 const char* names[]={"security_inode_getsecctx","security_inode_notifysecctx","security_release_secctx","security_inode_getsecid","iput"};
 for(unsigned i=0;i<5;i++){missing=names[i];assert(nm_prepare_inode_functions()==-ENOENT);missing=NULL;assert(!nm_prepare_inode_functions());}
 kf_nm_new_inode=port_new;kf_nm_d_splice_alias=port_splice;
 struct nomount_rule file_rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,37);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&file_rule,42));
 struct inode* file=nm_dentry_inode(outer_root);assert(file&&nm_inode_secid(file)==37&&((struct nm_inode_info*)nm_inode_private(file))->secid==37);
 nm_inode_mmap_ready(file);assert(!(((struct nm_inode_owner_prefix*)file)->i_flags&512)&&nm_inode_secid(file)==37);
 nm_rcu_read_lock();assert(nm_inode_matches_binding(file,&backing_path,NULL,0,nm_inode_secid(backing)));nm_rcu_read_unlock();
 security_set_sid(backing,38);nm_rcu_read_lock();assert(!nm_inode_matches_binding(file,&backing_path,NULL,0,nm_inode_secid(backing)));nm_rcu_read_unlock();
 security_fixture_iput(file);assert(security_gets==security_releases);
 int gets=binding_owned_gets,put_count=binding_owned_puts,allocs=alloc_calls;
 security_get_error=-ENOMEM;security_query(outer_root);assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-ENOMEM&&!nm_dentry_inode(outer_root)&&alloc_calls==allocs&&binding_owned_gets==gets);security_get_error=0;
 security_empty=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-EOPNOTSUPP&&security_gets==security_releases);security_empty=0;
 security_set_sid(backing,0);assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-EOPNOTSUPP&&security_gets==security_releases);security_set_sid(backing,38);
 fail_alloc=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-ENOMEM&&binding_owned_gets==gets&&security_gets==security_releases);fail_alloc=0;
 new_fail=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-ENOMEM&&binding_owned_gets==gets&&security_gets==security_releases);new_fail=0;
 security_notify_error=-EINVAL;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-EINVAL&&!nm_dentry_inode(outer_root)&&binding_owned_gets==gets+1&&binding_owned_puts==put_count+1&&security_gets==security_releases);security_notify_error=0;
 security_noop=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-EACCES&&!nm_dentry_inode(outer_root)&&security_gets==security_releases);security_noop=0;
 security_relabel=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)outer_root,&file_rule,42))==-EACCES&&!nm_dentry_inode(outer_root)&&security_gets==security_releases);security_relabel=0;
 struct nm_directory_node* node=nm_new_directory_node();assert(node);struct nomount_rule directory_rule={.r_path=backing_path,.flags=NM_FLAG_IS_DIR,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0040755;security_set_sid(backing,51);security_query(outer_root);
 assert(!nm_materialize_virtual_directory(parent,(void*)outer_root,&directory_rule,node,43));struct inode* first=nm_dentry_inode(outer_root);assert(nm_inode_secid(first)==51&&node->refs==2);
 int notified=security_notifies;security_query(outer_again);assert(!nm_materialize_virtual_directory(parent,(void*)outer_again,&directory_rule,node,43)&&nm_dentry_inode(outer_again)==first&&security_notifies==notified&&security_gets==security_releases);
 security_set_sid(backing,52);security_query(outer_child);assert(!nm_materialize_virtual_directory(parent,(void*)outer_child,&directory_rule,node,43));struct inode* changed=nm_dentry_inode(outer_child);assert(changed!=first&&nm_inode_secid(changed)==52);
 security_fixture_iput(first);security_fixture_iput(first);security_fixture_iput(changed);assert(node->refs==1);
 security_notify_error=-EACCES;security_hold_waiter=1;security_query(outer_root);int unlocked=cache_unlocks;
 assert(PTR_ERR(nm_materialize_virtual_directory(parent,(void*)outer_root,&directory_rule,node,43))==-EACCES&&!nm_dentry_inode(outer_root)&&cache_unlocks==unlocked+1&&security_waiter&&node->refs==2);
 struct nm_inode_info candidate={.r_path=backing_path,.flags=NM_FLAG_IS_DIR,.dir_node=node,.secid=52};assert(!nm_cached_directory_test(security_waiter,&candidate));
 security_hold_waiter=0;kf_nm_iget5_locked=security_waiter_iget;security_query(outer_again);
 assert(PTR_ERR(nm_materialize_virtual_directory(parent,(void*)outer_again,&directory_rule,node,43))==-EACCES&&!nm_dentry_inode(outer_again)&&!security_waiter&&node->refs==1&&security_gets==security_releases);
 kf_nm_iget5_locked=port_iget;security_notify_error=0;iget_error=-ENOMEM;
 assert(PTR_ERR(nm_materialize_virtual_directory(parent,(void*)outer_again,&directory_rule,node,43))==-ENOMEM&&node->refs==1&&security_gets==security_releases);iget_error=0;
 struct nomount_rule pure={.flags=NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,.refs=1};security_set_sid(parent,61);security_query(outer_root);
 assert(!nm_materialize_virtual_directory(parent,(void*)outer_root,&pure,node,44));first=nm_dentry_inode(outer_root);assert(nm_inode_secid(first)==61&&!((struct nm_inode_info*)nm_inode_private(first))->r_path.dentry);
 security_set_sid(parent,62);security_query(outer_again);assert(!nm_materialize_virtual_directory(parent,(void*)outer_again,&pure,node,44));changed=nm_dentry_inode(outer_again);assert(changed!=first&&nm_inode_secid(changed)==62);
 security_fixture_iput(first);security_fixture_iput(changed);assert(node->refs==1);nm_directory_node_put(node);flush_rcu();
 assert(security_gets==security_releases&&!rcu_depth&&!spin_depth&&!hash_depth&&!q_count&&!security_waiter);
 for(int i=0;i<32;i++)assert(!cache[i].inode);
 puts("native security context: SID/class transfer, mmap retention, source/parent relabel, cache reuse, allocation/notify failures and I_NEW waiter cleanup: PASS");
}
int main(void){assert(!previous_security_main());check_security_context();return 0;}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    a.output.mkdir(parents=True, exist_ok=False)
    old = lambda f: subprocess.check_output(['git', 'show', BASE + ':nomount/' + f], cwd=root).decode()
    new = lambda f: (root / 'nomount' / f).read_text()
    results = []
    for abi, digest in ORACLES.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        source = original.replace(old('nm_rules.h'), new('nm_rules.h'))
        assert original.count(old('nm_rules.h')) == 1
        for filename, names in CHANGED.items():
            for name in names:
                before = function(source, name)
                after = function(new(filename), name)
                if name == 'nm_prepare_inode_functions':
                    after = after.replace('kallsyms_lookup_name_by_suffix(', 'inode_fixture_lookup(')
                assert source.count(before) == 1, name
                source = source.replace(before, after)
        security = new('nm_security.c').replace('kallsyms_lookup_name_by_suffix(', 'inode_fixture_lookup(')
        source = source.replace('static struct nm_inode_engine nm_inode_engine;', PROTOTYPES + security + '\nstatic struct nm_inode_engine nm_inode_engine;', 1)
        source = source.replace('static struct inode* kfunc_def(nm_new_inode)(struct super_block*);', 'static void kfunc_def(nm_iput)(struct inode*);\nstatic struct inode* kfunc_def(nm_new_inode)(struct super_block*);', 1)
        lookup = '''  if (!strcmp(name,"security_inode_getsecctx")) return (uintptr_t)security_fixture_get;
  if (!strcmp(name,"security_inode_notifysecctx")) return (uintptr_t)security_fixture_notify;
  if (!strcmp(name,"security_release_secctx")) return (uintptr_t)security_fixture_release;
  if (!strcmp(name,"security_inode_getsecid")) return (uintptr_t)security_fixture_sid;
  if (!strcmp(name,"iput")) return (uintptr_t)security_fixture_iput;
'''
        source = source.replace('  if (!strcmp(name,"new_inode")) return (uintptr_t)host_new;', lookup + '  if (!strcmp(name,"new_inode")) return (uintptr_t)host_new;', 1)
        # 旧缓存夹具补新增的SID候选输入；旧断言的函数调用增加已知来源SID。
        source = source.replace('.dir_node=child_node};assert(nm_cached_directory_test', '.dir_node=child_node,.secid=1};assert(nm_cached_directory_test')
        source = source.replace('.dir_node=node};assert(nm_cached_directory_test', '.dir_node=node,.secid=1};assert(nm_cached_directory_test')
        for args in ('file_inode,&backing_path,NULL,0', 'file_inode,&wrong,NULL,0', 'file_inode,&backing_path,NULL,NM_FLAG_IS_DIR'):
            source = source.replace('nm_inode_matches_binding(' + args + ')', 'nm_inode_matches_binding(' + args + ',1)')
        assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
        current = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert len(assertions) == len(current) == 735
        migration = [dict(index=i, old=x, new=y, reason='binding match adds the fixture source SID argument; other conditions preserved') for i, (x, y) in enumerate(zip(assertions, current)) if x != y]
        assert len(migration) == 2
        source = source.replace('int main(void){assert(!previous_binding_main());check_bindings();return 0;}', 'static int previous_security_main(void){assert(!previous_binding_main());check_bindings();return 0;}', 1) + FIXTURE
        out = a.output / abi
        out.mkdir()
        c = out / 'contracts.c'
        c.write_text(source)
        built = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(out / 'contracts')], capture_output=True, text=True)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        built.check_returncode()
        run = subprocess.run([str(out / 'contracts')], capture_output=True, text=True)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        run.check_returncode()
        results.append(dict(abi=abi, oracle_sha256=digest, original_assertions=len(assertions), unchanged_assertions=len(assertions)-len(migration), assertion_migration=migration, total_assertions=len(re.findall(r'\bassert\s*\([^;]+\);', source)), generated_sha256=hashlib.sha256(source.encode()).hexdigest(), stdout=run.stdout))
    (a.output / 'receipt.json').write_text(json.dumps(dict(scope='Developer full Oracle migration plus native-LSM stubs; requires independent review and target SELinux-domain testing', results=results), indent=2) + '\n')
    print('int/bool complete inode Oracle and native security-context contracts: PASS')


if __name__ == '__main__':
    main()
