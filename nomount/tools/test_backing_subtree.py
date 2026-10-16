#!/usr/bin/env python3
"""执行 backing 子目录管理与源搜索权限；复用已生成的 backing inode Oracle。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    oracle = json.loads((args.oracle_output / 'receipt.json').read_text())
    assert oracle['tool_sha256'] == sha(root / 'nomount/tools/test_backing_inode.py')
    assert all(sha(root / p) == h for p, h in oracle['sources'].items())
    args.output.mkdir(parents=True, exist_ok=False)
    base = (args.oracle_output / 'backing-inode.c').read_text()
    assert base.count('int main(void)') == 1
    source = base.replace('int main(void)', 'int backing_inode_contract_main(void)')
    source += (root / 'nomount/nm_backing_subtree.c').read_text()
    source += r'''
static _Alignas(8) unsigned char tree_inode[8][768],tree_dentry[8][256],view_dentry[24][256];
static int tree_gets,tree_puts,tree_anchor_gets,tree_anchor_puts,tree_queries,tree_execs,tree_reads;
static int tree_denied=-1,tree_missing,tree_wrong_type,tree_query_error;
static int tree_index(const void* d) {for(int i=0;i<8;i++)if(d==tree_dentry[i])return i;assert(0);return -1;}
static int tree_path(const char* path,unsigned int flags,struct nm_path* out) {
  assert(flags==1&&!rcu_depth&&!spin_depth);
  int index=!strcmp(path,"/A")?0:!strcmp(path,"/B")?3:!strcmp(path,"/file")?6:!strcmp(path,"/file2")?7:-1;
  if(index>=0){*out=(struct nm_path){(void*)0x123,tree_dentry[index]};tree_gets++;return 0;}
  if(!strcmp(path,"/system/app")){*out=(struct nm_path){(void*)1,root_dentry};tree_anchor_gets++;return 0;}
  // 管理子树不得解析管理者的 UID 视图；新规则只在读侧继承来源。
  assert(strncmp(path,"/system/app/Package/",20));return -ENOENT;
}
static void tree_put(const struct nm_path* path) {
  assert(!rcu_depth&&!spin_depth&&!in_rcu);
  if(path->dentry==root_dentry){assert(path->mnt==(void*)1);tree_anchor_puts++;return;}
  assert(path->mnt==(void*)0x123);tree_index(path->dentry);tree_puts++;
}
static int tree_query(struct dentry* base,struct vfsmount* mnt,const char* name,unsigned int flags,struct nm_path* out) {
  assert((void*)mnt==(void*)0x123&&!flags&&!rcu_depth&&!spin_depth&&!manager_depth);
  int parent_index=tree_index(base),index=-1;tree_queries++;
  if(tree_query_error)return tree_query_error;
  if(!strcmp(name,"sub")&&(parent_index==0||parent_index==3))index=parent_index+1;
  if(!strcmp(name,"deep")&&(parent_index==1||parent_index==4))index=parent_index+1;
  if(!strcmp(name,"original"))index=6;
  if(index<0||tree_missing)return -ENOENT;
  if(tree_wrong_type)index=6;
  *out=(struct nm_path){(void*)0x123,tree_dentry[index]};tree_gets++;return 0;
}
static int tree_permission(struct vfsmount* mnt,struct inode* inode,int mask) {
  assert((void*)mnt==(void*)0x123&&!rcu_depth&&!spin_depth&&!manager_depth);
  if(mask==1){tree_execs++;return inode==(void*)tree_inode[tree_denied<0?7:tree_denied]&&tree_denied>=0?-EACCES:0;}
  assert(mask==(0x20|0x04));tree_reads++;return 0;
}
static int tree_add(const char* path,struct nomount_rule* rule,struct nm_topology_updates* updates) {
  manager_depth=1;int rc=nm_topology_add_locked(path,strlen(path),rule,updates);manager_depth=0;return rc;
}
static struct inode* tree_lookup(int slot,const char* name,int parent_slot,struct inode* parent_inode) {
  port_query_dentry(view_dentry[slot],name,parent_slot<0?(void*)root_dentry:(void*)view_dentry[parent_slot]);
  assert(!nm_directory_lookup(parent_inode,(void*)view_dentry[slot],0));return nm_dentry_inode(view_dentry[slot]);
}
static void tree_release(int slot) {
  struct inode* inode=nm_dentry_inode(view_dentry[slot]);if(inode)port_iput(inode);
  ((struct nm_dentry_head*)view_dentry[slot])->d_inode=NULL;
}
static void tree_check_source(struct inode* inode,int source_index,struct nm_directory_node* node) {
  struct nm_inode_info* info=nm_inode_private(inode);assert(info&&info->rule->r_path.dentry==tree_dentry[source_index]&&info->dir_node==node);
}
int main(void) {
  assert(!backing_inode_contract_main());assert(nm_prepare_backing_subtrees()==-ENODEV);
  target();directory_target();set_uid(1000);thread.flags=0;
  assert(!nm_prepare_inode_engine()&&!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
  assert(!nm_prepare_backing_inode_engine()&&!nm_prepare_topology_functions());
  kf_nm_inode_permission2=tree_permission;assert(!nm_prepare_backing_subtrees());assert(nm_prepare_backing_subtrees()==-EALREADY);
  memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;nm_inode_objects(parent)->i_op=native_iops;
  *(const void**)((char*)parent+struct_offset.inode_file_ops)=native_fops;((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;
  ((struct nm_dentry_head*)root_dentry)->d_inode=parent;sb.s_op=original_sops;sb.s_dev=456;
  nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
  for(int i=0;i<8;i++){
    nm_inode_objects(tree_inode[i])->i_sb=(void*)&sb;nm_inode_objects(tree_inode[i])->i_op=native_iops;
    nm_inode_objects(tree_inode[i])->i_mapping=nm_inode_data(tree_inode[i]);
    ((struct nm_inode_owner_prefix*)tree_inode[i])->i_mode=i<6?0040755:0100644;
    *(u64*)(tree_inode[i]+struct_offset.inode_size)=4096+i;*(u32*)(tree_inode[i]+struct_offset.inode_nlink)=i<6?3:1;
    ((struct nm_dentry_head*)tree_dentry[i])->d_inode=(void*)tree_inode[i];
  }
  kf_nm_kern_path=tree_path;kf_nm_path_put=tree_put;kf_nm_vfs_path_lookup=tree_query;
  kf_nm_new_inode=port_new;kf_nm_iget5_locked=port_iget;kf_nm_unlock_new_inode=port_unlock;kf_nm_set_nlink=port_nlink;
  kf_nm_d_splice_alias=port_splice;kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;kf_nm_d_drop=virtual_drop;
  struct nm_topology_updates updates={0};
  assert(!tree_add("/system/app/Package",port_rule("/A",1000),&updates));
  assert(!tree_add("/system/app/Package",port_rule("/B",2000),&updates));nm_finish_topology_updates(&updates);
  struct inode* root_a=tree_lookup(0,"Package",-1,parent);assert(root_a);
  struct inode* old_sub=tree_lookup(1,"sub",0,root_a);assert(old_sub);struct nm_directory_node* old_node=nm_inode_directory_node(old_sub);
  const char* injection="/system/app/Package/sub/deep/inject";
  assert(!tree_add(injection,port_rule("/file",0),&updates));
  struct nm_topology_leaf* sub_entry=nm_topology_find("/system/app/Package/sub",strlen("/system/app/Package/sub"));
  struct nm_topology_leaf* deep_entry=nm_topology_find("/system/app/Package/sub/deep",strlen("/system/app/Package/sub/deep"));
  assert(sub_entry&&deep_entry&&sub_entry->automatic&&deep_entry->automatic&&records()==4);
  assert(nm_select_rule(sub_entry->leaf,1000)->inherit_backing&&sub_entry->leaf->this_dir!=old_node&&!old_node->children);
  struct inode* sub_a=tree_lookup(2,"sub",0,root_a);tree_check_source(sub_a,1,sub_entry->leaf->this_dir);
  struct inode* deep_a=tree_lookup(3,"deep",2,sub_a);tree_check_source(deep_a,2,deep_entry->leaf->this_dir);
  struct inode* injected=tree_lookup(4,"inject",3,deep_a);assert(nm_is_file_inode(injected)&&nm_dentry_revalidate((void*)view_dentry[4],0)==1);
  assert(tree_lookup(5,"original",3,deep_a));tree_release(5);
  set_uid(2000);struct inode* root_b=tree_lookup(6,"Package",-1,parent);
  struct inode* sub_b=tree_lookup(7,"sub",6,root_b);tree_check_source(sub_b,4,sub_entry->leaf->this_dir);
  struct inode* deep_b=tree_lookup(8,"deep",7,sub_b);tree_check_source(deep_b,5,deep_entry->leaf->this_dir);
  assert(tree_lookup(9,"inject",8,deep_b));tree_release(9);set_uid(1000);
  // 原生 ACL 可以允许读取、拒绝搜索；显式规则和有效缓存同样受搜索权限约束。
  tree_denied=2;int queries=tree_queries;port_query_dentry(view_dentry[10],"inject",view_dentry[3]);
  assert(PTR_ERR(nm_directory_lookup(deep_a,(void*)view_dentry[10],0))==-EACCES&&tree_queries==queries);
  assert(nm_dentry_revalidate((void*)view_dentry[4],0)==-EACCES&&tree_queries==queries);
  assert(!nm_backing_open_permission(&((struct nm_inode_info*)nm_inode_private(deep_a))->rule->r_path)&&tree_reads==1);
  assert(nm_dentry_revalidate((void*)view_dentry[4],0x40)==-ECHILD);tree_denied=-1;
  assert(!nm_uid_add(1000));queries=tree_queries;assert(!tree_lookup(10,"inject",3,deep_a)&&tree_queries==queries);
  assert(!nm_dentry_revalidate((void*)view_dentry[4],0));assert(!nm_uid_del(1000));flush_rcu();
  // 源暂缺时保持纯目录，源恢复后不能沿用该 inode 的有效缓存。
  tree_missing=1;struct inode* pure=tree_lookup(11,"sub",0,root_a);assert(pure&&!((struct nm_inode_info*)nm_inode_private(pure))->rule->r_path.dentry);
  tree_missing=0;assert(!nm_dentry_revalidate((void*)view_dentry[11],0));tree_release(11);
  int gets=tree_gets,put_count=tree_puts;tree_wrong_type=1;port_query_dentry(view_dentry[11],"sub",view_dentry[0]);
  assert(PTR_ERR(nm_directory_lookup(root_a,(void*)view_dentry[11],0))==-ENOTDIR&&tree_gets==gets+1&&tree_puts==put_count+1);tree_wrong_type=0;
  tree_query_error=-EACCES;assert(PTR_ERR(nm_directory_lookup(root_a,(void*)view_dentry[11],0))==-EACCES);tree_query_error=0;
  for(int n=1;n<=2;n++){gets=tree_gets;put_count=tree_puts;fail_alloc=n;assert(PTR_ERR(nm_directory_lookup(root_a,(void*)view_dentry[11],0))==-ENOMEM);fail_alloc=0;assert(tree_gets==gets+1&&tree_puts==put_count+1);drain();flush_rcu();}
  assert(!tree_add(injection,port_rule("/file2",0),&updates));nm_finish_topology_updates(&updates);
  assert(!nm_dentry_revalidate((void*)view_dentry[4],0));assert(tree_lookup(12,"inject",3,deep_a));
  assert(((struct nm_inode_info*)nm_inode_private(injected))->rule->r_path.dentry==tree_dentry[6]);
  assert(((struct nm_inode_info*)nm_inode_private(nm_dentry_inode(view_dentry[12])))->rule->r_path.dentry==tree_dentry[7]);
  // 已发布管理树不能因为构建新父链失败而变化；覆盖每个分配点直到完整成功。
  int failures=0,successes=0;struct nm_directory_node* root_node=nm_inode_directory_node(root_a);
  for(int n=1;n<=40;n++){
    struct nomount_rule* rule=port_rule("/file",0);struct nomount_child_array* children=root_node->children;
    fail_alloc=n;int rc=tree_add("/system/app/Package/fresh/more/file",rule,&updates);fail_alloc=0;
    if(rc){assert(rc==-ENOMEM&&rule->refs==1&&!rule->published&&records()==4&&root_node->children==children);nm_rule_put(rule);failures++;}
    else {assert(records()==7);successes++;assert(!remove_rule("/system/app/Package/fresh/more/file",0,&updates));}
    nm_finish_topology_updates(&updates);drain();flush_rcu();assert(records()==4);
  }
  assert(failures>10&&successes>0);
  // 删除最后子项裁剪自动父链，已打开的旧目录持有空节点及源路径直到引用释放。
  assert(!remove_rule(injection,0,&updates));nm_finish_topology_updates(&updates);
  assert(records()==1&&!nm_topology_find("/system/app/Package/sub",strlen("/system/app/Package/sub"))); // 下方不再访问已退役 entry。
  assert(!nm_inode_directory_node(sub_a)->children&&!nm_inode_directory_node(deep_a)->children&&!old_node->children);
  // 有子规则的显式目录撤销后，保留管理节点并恢复对应父目录中的 backing 来源。
  const char* retained_child="/system/app/Package/sub/inject";
  assert(!tree_add(retained_child,port_rule("/file",0),&updates));
  assert(!tree_add("/system/app/Package/sub",port_rule("/B",0),&updates));nm_finish_topology_updates(&updates);
  struct nm_topology_leaf* retained=nm_topology_find("/system/app/Package/sub",strlen("/system/app/Package/sub"));
  assert(retained&&!retained->automatic);struct inode* explicit_sub=tree_lookup(13,"sub",0,root_a);
  tree_check_source(explicit_sub,3,retained->leaf->this_dir);
  assert(!remove_rule("/system/app/Package/sub",0,&updates));nm_finish_topology_updates(&updates);
  assert(nm_select_rule(retained->leaf,1000)->inherit_backing&&!nm_dentry_revalidate((void*)view_dentry[13],0));
  struct inode* restored=tree_lookup(14,"sub",0,root_a);tree_check_source(restored,1,retained->leaf->this_dir);
  assert(tree_lookup(15,"inject",14,restored));tree_release(15);
  assert(!remove_rule(retained_child,0,&updates));nm_finish_topology_updates(&updates);assert(records()==2);
  assert(!remove_rule("/system/app/Package/sub",0,&updates));nm_finish_topology_updates(&updates);assert(records()==1);
  clear_rules(&updates);for(int i=0;i<24;i++)tree_release(i);
  assert(tree_gets==tree_puts&&tree_anchor_gets==tree_anchor_puts&&tree_execs>10&&!q_count&&!rcu_depth&&!manager_depth);
  nm_proxy_evict_inode(parent);flush_rcu();fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));
  nm_backing_open_permission=NULL;nm_discard_directory_view();
  printf("managed backing subtrees, UID sources, search ACL, refresh, %d allocation failures and retirement: PASS\n",failures);return 0;
}
'''
    c = args.output / 'backing-subtree.c'
    c.write_text(source)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function',
               '-I' + str(root / 'nomount'), '-fsanitize=address,undefined', '-g',
               str(c), '-o', str(args.output / 'backing-subtree')]
    compile_result = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compile_result.stdout + compile_result.stderr)
    compile_result.check_returncode()
    run = subprocess.run([str(args.output / 'backing-subtree')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    files = ['kpm_utils.h'] + [str(p.relative_to(root)) for p in sorted((root / 'nomount').glob('nm*.[ch]'))]
    receipt = {'scope': 'Developer host contracts; not native ACL, concurrent VFS or device proof',
               'sources': {p: sha(root / p) for p in files}, 'tool_sha256': sha(Path(__file__)),
               'oracle_receipt_sha256': sha(args.oracle_output / 'receipt.json'),
               'oracle_source_sha256': sha(args.oracle_output / 'backing-inode.c'),
               'generated_source_sha256': sha(c), 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout.strip().splitlines()[-1])


if __name__ == '__main__':
    main()
