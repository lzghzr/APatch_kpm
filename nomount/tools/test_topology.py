#!/usr/bin/env python3
"""执行路径建树、规则替换、裁剪及分配失败；宿主路径夹具不证明原生命名空间并发。"""
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
    assert all(symbols.get(name) in ('t','T') for name in ('d_hash_and_lookup','shrink_dcache_parent'))
    command = [sys.executable,str(root/'nomount/tools/test_virtual_directory.py')]
    for name in ('symbols','reference','inode_reference','ops_reference','file_reference'):
        command += ['--'+name.replace('_','-'),str(getattr(args,name))]
    command += ['--output',str(args.output/'virtual-contract')]
    subprocess.run(command, check=True)
    base = (args.output/'virtual-contract/virtual-directory.c').read_text()
    base = base.replace('int main(void)', 'int virtual_contract_main(void)')
    base = base.replace('nm_rcu_synchronize', 'topology_prior_synchronize')
    source = base + r'''
static unsigned long topology_lookup(const char*);
static int manager_depth, barriers;
static void nm_rcu_synchronize(void) {assert(!manager_depth&&!rcu_depth&&!spin_depth);barriers++;topology_prior_synchronize();}
'''+(root/'nomount/nm_topology.c').read_text().replace('kallsyms_lookup_name_by_suffix','topology_lookup')+r'''
static _Alignas(8) unsigned char cached_child[256],live_directory[256],live_file[512],child_query[256];
static _Alignas(8) unsigned char other_inode_storage[768],other_native_dentry[256];
static struct inode* other_inode=(void*)other_inode_storage;
static int native_gets,native_puts,backing_gets,backing_puts,hash_gets,hash_puts,hash_error,hash_hit,shrinks;
static int topo_gets,topo_puts,topo_drops;
static int path_error,late_calls;
static int topo_path(const char* name,unsigned int flags,struct nm_path* path) {
  assert(flags==1&&!rcu_depth&&!spin_depth);
  if(!strcmp(name,"/backing")){*path=backing_path;backing_gets++;return 0;}
  if(!strcmp(name,"/system/app/Appeared")) {
    if(!late_calls++)return -ENOENT;
    *path=(struct nm_path){.mnt=(void*)1,.dentry=root_dentry};native_gets++;return 0;
  }
  if(!strcmp(name,"/system/app/Native")){*path=(struct nm_path){.mnt=(void*)1,.dentry=other_native_dentry};native_gets++;return 0;}
  if(!strcmp(name,"/system/app")||!strcmp(name,"/")||!strcmp(name,"/system/app/Loop")) {
    *path=(struct nm_path){.mnt=(void*)1,.dentry=root_dentry};native_gets++;return 0;
  }
  if(!strcmp(name,"/system/plain")){*path=backing_path;backing_gets++;return 0;}
  if(!strcmp(name,"/system/blocked"))return -EACCES;
  return path_error?path_error:-ENOENT;
}
static void topo_path_put(const struct nm_path* path) {
  assert(!in_rcu&&!rcu_depth&&!spin_depth);
  if(path->dentry==root_dentry||path->dentry==other_native_dentry)native_puts++;
  else {assert(path->dentry==backing_path.dentry);backing_puts++;}
}
static struct dentry* topo_hash(struct dentry* parent_dentry,struct nm_qstr* name) {
  assert((parent_dentry==(void*)root_dentry||parent_dentry==(void*)other_native_dentry)&&!rcu_depth&&!spin_depth&&manager_depth&&name->len&&name->len<=255);
  if(hash_error)return ERR_PTR(hash_error);
  if(hash_hit){hash_gets++;return (void*)cached_child;}return NULL;
}
static void topo_shrink(struct dentry* d) {assert((d==(void*)root_dentry||d==(void*)other_native_dentry)&&manager_depth&&!rcu_depth&&!spin_depth);shrinks++;}
static void topo_dput(struct dentry* d) {assert(!in_rcu&&!rcu_depth&&!spin_depth);if(d==(void*)cached_child)hash_puts++;else topo_puts++;}
static struct dentry* topo_parent(struct dentry* d) {assert(!rcu_depth&&!spin_depth);topo_gets++;return ((struct nm_dentry_head*)d)->d_parent;}
static void topo_drop(struct dentry* d) {assert(d&&!spin_depth);topo_drops++;}
static unsigned long topology_lookup(const char* name) {
  if(missing&&!strcmp(missing,name))return 0;
  if(!strcmp(name,"d_hash_and_lookup"))return (uintptr_t)topo_hash;
  if(!strcmp(name,"shrink_dcache_parent"))return (uintptr_t)topo_shrink;
  return 0;
}
static int add_rule(const char* path,u32 uid,u32 flags,struct nm_topology_updates* updates) {
  struct nomount_rule* rule=nm_alloc_rule("/backing",8,flags,uid);assert(!IS_ERR(rule));
  manager_depth=1;int rc=nm_topology_add_locked(path,strlen(path),rule,updates);manager_depth=0;
  if(rc)nm_rule_put(rule);return rc;
}
static int remove_rule(const char* path,u32 uid,struct nm_topology_updates* updates) {
  manager_depth=1;int rc=nm_topology_remove_locked(path,strlen(path),uid,updates);manager_depth=0;return rc;
}
static void clear_rules(struct nm_topology_updates* updates) {
  manager_depth=1;assert(!nm_topology_clear_locked(updates));manager_depth=0;
  nm_finish_topology_updates(updates);drain();flush_rcu();assert(!nm_topology_leaves&&!nm_topology_anchors);
}
static void topo_evict(struct inode* inode) {assert(inode==parent||inode==other_inode);}
static int records(void) {int n=0;for(struct nm_topology_leaf* e=nm_topology_leaves;e;e=e->next)n++;return n;}
static void bind_topology(void) {
  kf_nm_kern_path=topo_path;kf_nm_path_put=topo_path_put;kf_nm_d_hash_and_lookup=topo_hash;kf_nm_shrink_dcache_parent=topo_shrink;
  kf_nm_dget_parent=topo_parent;kf_nm_dput=topo_dput;kf_nm_d_drop=topo_drop;kf_nm_d_splice_alias=virtual_splice;
}
int main(void) {
  assert(!virtual_contract_main());nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;
  assert(nm_prepare_topology_functions()==-ENODEV);target();directory_target();
  assert(!nm_prepare_inode_engine());assert(!nm_prepare_directory_engine());assert(!nm_prepare_virtual_directory_engine());
  missing="d_hash_and_lookup";assert(nm_prepare_topology_functions()==-ENOENT);missing=NULL;assert(!nm_prepare_topology_functions());bind_topology();
  memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;
  nm_inode_objects(parent)->i_op=native_iops;*(const void**)((uintptr_t)parent+struct_offset.inode_file_ops)=native_fops;
  ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;((struct nm_dentry_head*)root_dentry)->d_inode=parent;
  ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;
  nm_inode_objects(other_inode)->i_sb=(void*)&sb;nm_inode_objects(other_inode)->i_op=native_iops;
  *(const void**)((uintptr_t)other_inode+struct_offset.inode_file_ops)=native_fops;((struct nm_inode_owner_prefix*)other_inode)->i_mode=0040755;
  ((struct nm_dentry_head*)other_native_dentry)->d_inode=other_inode;
  nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,topo_evict);
  set_uid(1000);thread.flags=0;struct nm_topology_updates updates={0};
  assert(nm_topology_path_valid("/",1)==-EINVAL&&nm_topology_path_valid("/a//b",5)==-EINVAL&&nm_topology_path_valid("/a/../b",7)==-EINVAL);
  char long_name[258];memset(long_name,'a',sizeof(long_name));long_name[0]='/';assert(nm_topology_path_valid(long_name,257)==-ENAMETOOLONG);
  // 每次从未接管的 native parent 开始，检验最高边界分配先于操作表发布。
  int initial_failures=0;
  for(int n=1;n<=28;n++) {
    struct nomount_rule* r=nm_alloc_rule("/backing",8,0,0);assert(!IS_ERR(r));hash_hit=1;
    fail_alloc=n;manager_depth=1;int rc=nm_topology_add_locked("/system/app/Fresh/x",strlen("/system/app/Fresh/x"),r,&updates);manager_depth=0;fail_alloc=0;hash_hit=0;
    if(rc){assert(rc==-ENOMEM&&!records()&&!nm_topology_anchors&&nm_inode_ops(parent)==native_iops&&r->refs==1&&!r->published);nm_rule_put(r);initial_failures++;}
    else clear_rules(&updates);
    if(nm_directory_proxy(nm_inode_ops(parent)))nm_proxy_evict_inode(parent);flush_rcu();assert(nm_inode_ops(parent)==native_iops&&hash_gets==hash_puts);
  }
  assert(initial_failures>10);
  assert(!add_rule("/system/app/A/res/base.apk",1000,0,&updates)&&records()==3);
  struct nm_topology_leaf* a=nm_topology_find("/system/app/A",13);assert(a&&a->automatic&&a->leaf->this_dir);
  struct nm_topology_leaf* file=nm_topology_find("/system/app/A/res/base.apk",26);assert(file&&!file->automatic);
  struct nm_directory_node* installed=nm_inode_directory_node(parent);assert(installed&&installed==nm_topology_anchors->node);
  assert(nm_find_child(nm_rules_load(installed->children),"A",1)==a->leaf);
  assert(!add_rule("/system/app/A/res/second.apk",0,0,&updates)&&records()==4);
  struct nm_rule_array* old=nm_rules_load(file->leaf->rules);struct nomount_rule* previous=old->rules[0];nm_rule_get(previous);
  assert(!add_rule("/system/app/A/res/base.apk",1000,NM_FLAG_WHITEOUT,&updates)&&records()==4);
  assert(updates.rules.rules==previous&&nm_select_rule(file->leaf,1000)->flags&NM_FLAG_WHITEOUT);
  int before=barriers;nm_finish_topology_updates(&updates);assert(barriers==before+1&&previous->refs==1);nm_rule_put(previous);flush_rcu();
  assert(!remove_rule("/system/app/A/res/base.apk",1000,&updates));nm_finish_topology_updates(&updates);flush_rcu();assert(records()==3);
  assert(!remove_rule("/system/app/A/res/second.apk",0,&updates));assert(!records()&&!nm_topology_anchors&&updates.leaves);
  nm_finish_topology_updates(&updates);flush_rcu();assert(!nm_rules_load(installed->children));
  // path_put 不使 native inode 退出缓存；再次添加必须复用已安装的节点。
  assert(!add_rule("/system/app/B/base.apk",0,0,&updates)&&nm_topology_anchors->node==installed);
  assert(!add_rule("/system/app/Other.apk",0,0,&updates));
  struct nomount_child_array* view=nm_rules_load(installed->children);fail_alloc=1;
  assert(remove_rule("/system/app/Other.apk",0,&updates)==-ENOMEM&&nm_rules_load(installed->children)==view&&records()==3);
  assert(!updates.leaves&&!updates.anchors&&!updates.rules.rules);clear_rules(&updates);
  hash_error=-EIO;assert(add_rule("/system/app/Rejected.apk",0,0,&updates)==-EIO&&!records());hash_error=0;flush_rcu();
  assert(add_rule("/system/plain/a",0,0,&updates)==-ENOTDIR&&!records());
  assert(add_rule("/system/blocked/a",0,0,&updates)==-EACCES&&!records());path_error=-ELOOP;
  assert(add_rule("/system/app/Missing/a",0,0,&updates)==-ELOOP&&!records());path_error=0;flush_rcu();
  assert(!add_rule("/system/app/Kept.apk",0,0,&updates));view=nm_rules_load(installed->children);
  // prefix 缺失后命名空间改变，自动父节点仍使用私有新节点，不再次采用原生视图。
  assert(!add_rule("/system/app/Appeared/child",0,0,&updates)&&late_calls==1);
  struct nm_topology_leaf* appeared=nm_topology_find("/system/app/Appeared",20);
  assert(appeared&&appeared->leaf->this_dir!=installed&&!nm_find_child(nm_rules_load(installed->children),"child",5));
  assert(!remove_rule("/system/app/Appeared/child",0,&updates));nm_finish_topology_updates(&updates);flush_rcu();view=nm_rules_load(installed->children);
  struct nomount_rule* directory=nm_alloc_rule(NULL,0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);assert(!IS_ERR(directory));
  manager_depth=1;assert(nm_topology_add_locked("/system/app/Loop",16,directory,&updates)==-ELOOP);manager_depth=0;
  assert(!directory->published&&directory->refs==1&&nm_rules_load(installed->children)==view&&!installed->owner);nm_rule_put(directory);
  clear_rules(&updates);
  // 新增完整缺失链的逐分配失败；失败没有可达新叶节点，原生空 proxy 可再次复用。
  int failures=0,successes=0;
  for(int n=1;n<=48;n++) {
    struct nomount_rule* rule=nm_alloc_rule("/backing",8,0,1000);assert(!IS_ERR(rule));
    fail_alloc=n;manager_depth=1;int rc=nm_topology_add_locked("/system/app/Oom/deep/file",25,rule,&updates);manager_depth=0;fail_alloc=0;
    if(rc){assert(rc==-ENOMEM&&!records()&&!nm_topology_anchors&&rule->refs==1&&!rule->published);nm_rule_put(rule);failures++;}
    else{assert(records()==3&&nm_topology_anchors->node==installed);successes++;clear_rules(&updates);}
    flush_rcu();
  }
  assert(failures>10&&successes>0);
  // 打开中的虚拟父目录在整个子树撤销后仍可枚举空视图。
  assert(!add_rule("/system/app/Live/base.apk",1000,0,&updates));
  struct nm_topology_leaf* live=nm_topology_find("/system/app/Live",16);assert(live);
  reset_dentry(live_directory,"Live",NULL);assert(!nm_directory_lookup(parent,(void*)live_directory,0));struct inode* live_inode=cached_directory;
  assert(live_inode&&nm_is_directory_inode(live_inode));struct nm_directory_node* live_node=((struct nm_inode_info*)nm_inode_private(live_inode))->dir_node;
  assert(!remove_rule("/system/app/Live/base.apk",1000,&updates));nm_finish_topology_updates(&updates);flush_rcu();assert(!records()&&!nm_rules_load(live_node->children));
  ((struct nm_file_inode_ops*)(live_file+struct_offset.file_inode_ops))->f_inode=live_inode;
  ((struct nm_file_inode_ops*)(live_file+struct_offset.file_inode_ops))->f_op=nm_virtual_directory_fops;
  ((struct nm_path*)nm_file_path(live_file))->dentry=live_directory;
  struct nm_dir_context context={.actor=fixture_actor};reset_emit();assert(!nm_virtual_directory_iterate((void*)live_file,&context)&&has_name(".")&&has_name("..")&&!has_name("base.apk"));
  reset_dentry(child_query,"base.apk",NULL);((struct nm_dentry_head*)child_query)->d_parent=(void*)live_directory;
  assert(!nm_directory_lookup(live_inode,(void*)child_query,0)&&!nm_dentry_inode(child_query));virtual_iput(live_inode);drain();flush_rcu();
  // 目录仍有子项时，撤销遮住它的普通文件规则会保留可进入的虚拟目录。
  assert(!add_rule("/system/app/Keep/child",1000,0,&updates));assert(!add_rule("/system/app/Keep",0,0,&updates));
  assert(!remove_rule("/system/app/Keep",0,&updates));nm_finish_topology_updates(&updates);
  struct nm_topology_leaf* keep=nm_topology_find("/system/app/Keep",16);assert(keep&&nm_select_rule(keep->leaf,0)->flags&NM_FLAG_VIRTUAL_DIR);clear_rules(&updates);
  // 普通文件升级为虚拟目录：节点与新规则均在最终发布前备齐。
  assert(!add_rule("/system/app/Upgrade",0,0,&updates));struct nm_topology_leaf* upgrade=nm_topology_find("/system/app/Upgrade",19);
  old=nm_rules_load(upgrade->leaf->rules);
  for(int n=1;n<=2;n++) {
    directory=nm_alloc_rule(NULL,0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);assert(!IS_ERR(directory));fail_alloc=n;
    manager_depth=1;assert(nm_topology_add_locked("/system/app/Upgrade",19,directory,&updates)==-ENOMEM);manager_depth=0;
    assert(nm_rules_load(upgrade->leaf->rules)==old&&!upgrade->leaf->this_dir&&!directory->published);nm_rule_put(directory);flush_rcu();
  }
  directory=nm_alloc_rule(NULL,0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);hash_error=-EIO;manager_depth=1;
  assert(nm_topology_add_locked("/system/app/Upgrade",19,directory,&updates)==-EIO);manager_depth=0;hash_error=0;
  assert(nm_rules_load(upgrade->leaf->rules)==old&&!upgrade->leaf->this_dir&&!directory->published);nm_rule_put(directory);flush_rcu();
  assert(!add_rule("/system/app/Upgrade",0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,&updates)&&upgrade->leaf->this_dir);
  nm_finish_topology_updates(&updates);clear_rules(&updates);
  // 将有既存子项的原生目录纳入规则后，空目录仍保留 native anchor，便于后续新增。
  assert(!add_rule("/system/app/Native/child",0,0,&updates));
  struct nm_directory_node* native_node=nm_inode_directory_node(other_inode);assert(native_node&&nm_topology_anchor(native_node));
  assert(!add_rule("/system/app/Native",1000,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,&updates));
  struct nm_topology_leaf* adopted=nm_topology_find("/system/app/Native",18);assert(adopted&&adopted->leaf->this_dir==native_node);
  assert(!remove_rule("/system/app/Native/child",0,&updates));nm_finish_topology_updates(&updates);flush_rcu();
  assert(native_node->owner==adopted&&!nm_rules_load(native_node->children)&&nm_topology_anchor(native_node));
  assert(!add_rule("/system/app/Native/again",1000,0,&updates)&&nm_inode_directory_node(other_inode)==native_node);clear_rules(&updates);
  nm_proxy_evict_inode(other_inode);flush_rcu();assert(nm_inode_ops(other_inode)==native_iops);
  // 多 UID 删除不能退役另一个 UID 的规则；失败替换保持原数组。
  assert(!add_rule("/system/app/Uid",1000,0,&updates));assert(!add_rule("/system/app/Uid",2000,0,&updates));
  struct nm_topology_leaf* uid=nm_topology_find("/system/app/Uid",15);old=nm_rules_load(uid->leaf->rules);fail_alloc=1;
  assert(remove_rule("/system/app/Uid",1000,&updates)==-ENOMEM&&nm_rules_load(uid->leaf->rules)==old);
  assert(!remove_rule("/system/app/Uid",1000,&updates));nm_finish_topology_updates(&updates);assert(!nm_select_rule(uid->leaf,1000)&&nm_select_rule(uid->leaf,2000));
  hash_hit=1;assert(!add_rule("/system/app/Uid",2000,NM_FLAG_WHITEOUT,&updates)&&hash_gets==hash_puts);hash_hit=0;nm_finish_topology_updates(&updates);clear_rules(&updates);
  nm_proxy_evict_inode(parent);flush_rcu();assert(nm_inode_ops(parent)==native_iops);
  fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));
  fixture_vfree(nm_inode_engine.inode_ops);fixture_vfree(nm_inode_engine.file_ops);fixture_vfree(nm_inode_engine.directory_ops);
  fixture_vfree(nm_virtual_directory_fops);fixture_vfree(nm_owned_dentry_ops);
  assert(native_gets==native_puts&&backing_gets==backing_puts&&hash_gets==hash_puts&&topo_gets==topo_puts);
  assert(!rcu_depth&&!spin_depth&&!manager_depth&&!q_count&&!pending_rcu&&shrinks>0&&topo_drops>0);
  printf("topology publication, %d fresh-parent and %d cached-parent allocation failures, pruning and live-inode retirement: PASS\n",initial_failures,failures);return 0;
}
'''
    c=args.output/'topology.c';c.write_text(source)
    result=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-I'+str(root/'nomount'),
                           '-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'topology')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode()
    run=subprocess.run([str(args.output/'topology')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    files=('nomount/nm_topology.c','nomount/nm_directory_nodes.c','nomount/nm_rules.c','nomount/nm_rules.h',
           'nomount/nm_directory.c','nomount/nm_virtual_directory.c','nomount/nm_inode.c','nomount/nm_offsets.c')
    receipt={'scope':'Developer host call contracts and allocation failures; not native namespace or concurrency proof',
             'sources':{name:sha(root/name) for name in files},'tool_sha256':sha(Path(__file__)),
             'virtual_oracle_sha256':sha(root/'nomount/tools/test_virtual_directory.py'),
             'virtual_receipt_sha256':sha(args.output/'virtual-contract/receipt.json'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':main()
