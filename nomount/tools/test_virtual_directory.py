#!/usr/bin/env python3
"""执行纯虚拟目录的 inode 复用、子项查找、枚举和回收；不证明原生并发。"""
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
    for name in ('symbols', 'reference', 'inode-reference', 'ops-reference', 'file-reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    symbols = {name: kind for _, kind, name in json.loads(args.symbols.read_text())}
    dependencies = ('iget5_locked', 'unlock_new_inode', 'generic_fillattr', 'set_nlink', 'generic_file_llseek')
    assert all(symbols.get(name) in ('t', 'T') for name in dependencies)
    command = [sys.executable, str(root/'nomount/tools/test_directory.py')]
    for name in ('symbols', 'reference', 'inode_reference', 'ops_reference', 'file_reference'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    command += ['--output', str(args.output/'directory-contract')]
    subprocess.run(command, check=True)
    base = (args.output/'directory-contract/directory.c').read_text()
    base = base.replace('int main(void)', 'int directory_contract_main(void)')
    source = base + (root/'nomount/nm_virtual_directory.c').read_text() + r'''
static struct inode* cached_directory;
static int directory_refs, iget_error, iget_calls, set_calls, unlock_calls, hash_depth, stat_calls;
static int virtual_splice_error, virtual_alias, virtual_drops, virtual_puts, virtual_gets;
static _Alignas(8) unsigned char virtual_dentry[256],nested_dentry[256],virtual_file[512],other_alias[256];
static struct inode* virtual_iget(struct super_block* super,unsigned long hash,
                                 int (*test)(struct inode*,void*),int (*set)(struct inode*,void*),void* data) {
  assert(super==(void*)&sb && hash==(unsigned long)((struct nm_inode_info*)data)->rule && !rcu_depth && !hash_depth);
  iget_calls++;if(iget_error)return iget_error==-ENOMEM?NULL:ERR_PTR(iget_error);
  if(cached_directory){hash_depth=1;int matched=test(cached_directory,data);hash_depth=0;if(matched){directory_refs++;return cached_directory;}}
  assert(!cached_directory);cached_directory=host_new(super);assert(cached_directory);
  hash_depth=1;assert(!set(cached_directory,data));hash_depth=0;set_calls++;directory_refs=1;return cached_directory;
}
static void virtual_unlock(struct inode* inode) {
  assert(inode==cached_directory && !hash_depth && nm_is_directory_inode(inode));
  assert(nm_inode_mode(inode)==0040755 && nm_inode_nlink(inode)==2 && nm_inode_mapping(inode)==nm_inode_data(inode));
  assert(nm_inode_size(inode)==4096 && nm_inode_file_ops(inode)==nm_virtual_directory_fops);unlock_calls++;
}
static void virtual_nlink(struct inode* inode,unsigned int links) {assert(links==2);*(u32*)((uintptr_t)inode+struct_offset.inode_nlink)=links;}
static void virtual_stat(struct inode* inode,struct kstat* stat) {
  assert(inode==cached_directory);stat_calls++;struct nm_kstat_prefix* s=(void*)stat;
  s->ino=nm_inode_number(inode);s->dev=sb.s_dev;s->mode=nm_inode_mode(inode);s->size=nm_inode_size(inode);s->nlink=nm_inode_nlink(inode);
}
static void virtual_iput(struct inode* inode) {
  assert(inode==cached_directory && directory_refs>0);
  if(--directory_refs)return;
  assert(nm_proxy_drop_inode(inode)==1);eviction_target=inode;nm_proxy_evict_inode(inode);
  assert(!nm_inode_private(inode)&&nm_inode_mapping(inode)==nm_inode_data(inode));
  free(inode);cached_directory=NULL;created=NULL;
}
static struct dentry* virtual_splice(struct inode* inode,struct dentry* d) {
  assert(!rcu_depth&&!hash_depth&&!spin_depth);
  if(virtual_splice_error){assert(inode==cached_directory);virtual_iput(inode);return ERR_PTR(-ELOOP);}
  if(inode==cached_directory&&virtual_alias){virtual_iput(inode);return (void*)other_alias;}
  ((struct nm_dentry_head*)d)->d_inode=inode;return NULL;
}
static struct dentry* virtual_parent(struct dentry* d) {assert(!rcu_depth&&!spin_depth);virtual_gets++;return ((struct nm_dentry_head*)d)->d_parent;}
static void virtual_put(struct dentry* d) {assert(d&&!rcu_depth&&!spin_depth);virtual_puts++;}
static void virtual_drop(struct dentry* d) {assert(d&&!spin_depth);virtual_drops++;}
static int64_t virtual_seek(struct file* f,int64_t pos,int whence) {assert(whence==0);return fixture_setpos(f,pos,0x7fffffffffffffffLL);}
static void bind_virtual_functions(void) {
  kf_nm_iget5_locked=virtual_iget;kf_nm_unlock_new_inode=virtual_unlock;kf_nm_generic_fillattr=virtual_stat;
  kf_nm_set_nlink=virtual_nlink;kf_nm_generic_file_llseek=virtual_seek;
  kf_nm_d_splice_alias=virtual_splice;kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;kf_nm_d_drop=virtual_drop;
}
// 加载符号的准备路径仍执行生产代码；正式回调夹具随后覆盖这些已验证非空的地址。
static unsigned long virtual_function_lookup(const char* name) {
  if(missing&&!strcmp(missing,name))return 0;
  if(!strcmp(name,"iget5_locked"))return (uintptr_t)virtual_iget;
  if(!strcmp(name,"unlock_new_inode"))return (uintptr_t)virtual_unlock;
  if(!strcmp(name,"generic_fillattr"))return (uintptr_t)virtual_stat;
  if(!strcmp(name,"set_nlink"))return (uintptr_t)virtual_nlink;
  if(!strcmp(name,"generic_file_llseek"))return (uintptr_t)virtual_seek;
  return kallsyms_lookup_name_by_suffix(name);
}
int main(void) {
  assert(!directory_contract_main());nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;
  assert(nm_prepare_virtual_directory_engine()==-ENODEV);target();directory_target();
  assert(!nm_prepare_inode_engine());assert(!nm_prepare_directory_engine());
  int old_inode_offset=struct_offset.file_inode_ops;struct_offset.file_inode_ops=8;
  assert(nm_prepare_virtual_directory_engine()==-EINVAL);struct_offset.file_inode_ops=old_inode_offset;
  missing="iget5_locked";assert(nm_prepare_virtual_directory_engine()==-ENOENT);missing=NULL;
  fail_alloc=1;assert(nm_prepare_virtual_directory_engine()==-ENOMEM&&!nm_inode_engine.directory_ops);
  fail_alloc=2;int before=frees;assert(nm_prepare_virtual_directory_engine()==-ENOMEM&&!nm_inode_engine.directory_ops&&frees==before+1);
  assert(!nm_prepare_virtual_directory_engine());assert(nm_prepare_virtual_directory_engine()==-EALREADY);bind_virtual_functions();
  memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;sb.s_dev=456;
  ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;nm_inode_objects(parent)->i_op=native_iops;
  *(const void**)((uintptr_t)parent+struct_offset.inode_file_ops)=native_fops;
  nm_set_operation_callback(original_sops,struct_offset.sop_drop_inode,host_drop);nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
  ((struct nm_dentry_head*)root_dentry)->d_inode=parent;set_uid(1000);thread.flags=0;
  struct nm_directory_node* root_node=nm_new_directory_node();assert(!nm_install_directory(parent,root_node));
  struct nomount_leaf* leaf=nm_alloc_leaf("/added",6);assert(leaf);struct nm_directory_node* child_node=nm_new_directory_node();leaf->this_dir=child_node;
  struct nomount_rule* rule=nm_alloc_rule(NULL,0,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);assert(!IS_ERR(rule));
  struct nm_rule_updates updates={0};assert(!nm_set_leaf_rule(leaf,rule,&updates));assert(!nm_insert_child(&root_node->children,leaf));
  reset_dentry(virtual_dentry,"added",NULL);
  fail_alloc=1;assert(PTR_ERR(nm_directory_lookup(parent,(void*)virtual_dentry,0))==-ENOMEM&&rule->refs==1&&child_node->refs==1);
  iget_error=-ENOMEM;assert(PTR_ERR(nm_directory_lookup(parent,(void*)virtual_dentry,0))==-ENOMEM&&rule->refs==1&&child_node->refs==1);
  iget_error=-ESTALE;assert(PTR_ERR(nm_directory_lookup(parent,(void*)virtual_dentry,0))==-ESTALE&&rule->refs==1&&child_node->refs==1);iget_error=0;
  virtual_splice_error=1;assert(PTR_ERR(nm_directory_lookup(parent,(void*)virtual_dentry,0))==-ELOOP&&!cached_directory&&rule->refs==1&&child_node->refs==1);virtual_splice_error=0;drain();flush_rcu();
  int new_before=unlock_calls;
  assert(!nm_directory_lookup(parent,(void*)virtual_dentry,0));struct inode* first=cached_directory;
  assert(first&&rule->refs==2&&child_node->refs==2&&unlock_calls==new_before+1&&set_calls==new_before+1);
  assert(nm_inode_number(first)==leaf->v_ino&&!nm_directory_proxy(nm_inode_ops(first)));
  assert(nm_dentry_revalidate((void*)virtual_dentry,0)==1);
  nm_rules_publish(leaf->this_dir,root_node);assert(!nm_dentry_revalidate((void*)virtual_dentry,0));nm_rules_publish(leaf->this_dir,child_node);
  reset_dentry(nested_dentry,"added",NULL);assert(!nm_directory_lookup(parent,(void*)nested_dentry,0));
  assert(cached_directory==first&&directory_refs==2&&rule->refs==2&&child_node->refs==2&&set_calls==new_before+1&&unlock_calls==new_before+1);
  struct nm_inode_info candidate={.rule=rule,.dir_node=child_node};assert(nm_cached_directory_test(first,&candidate));
  candidate.dir_node=root_node;assert(!nm_cached_directory_test(first,&candidate));candidate.dir_node=child_node;
  void* actual=nm_inode_private(first);nm_set_inode_private(first,NULL);assert(!nm_cached_directory_test(first,&candidate));nm_set_inode_private(first,actual);
  ((struct nm_dentry_head*)nested_dentry)->d_parent=(void*)virtual_dentry;
  reset_dentry(nested_dentry,"missing",NULL);((struct nm_dentry_head*)nested_dentry)->d_parent=(void*)virtual_dentry;
  assert(!nm_directory_lookup(first,(void*)nested_dentry,0)&&!nm_dentry_inode(nested_dentry));
  assert(!nm_dentry_revalidate((void*)nested_dentry,0));
  struct nomount_rule* file_rule;struct nomount_leaf* file_leaf=leaf_rule("/added/extra",1000,0,&file_rule);
  ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;assert(!nm_insert_child(&child_node->children,file_leaf));
  reset_dentry(nested_dentry,"extra",NULL);((struct nm_dentry_head*)nested_dentry)->d_parent=(void*)virtual_dentry;
  assert(!nm_directory_lookup(first,(void*)nested_dentry,0)&&nm_is_file_inode(nm_dentry_inode(nested_dentry)));
  struct inode* file_inode=nm_dentry_inode(nested_dentry);eviction_target=file_inode;nm_proxy_evict_inode(file_inode);free(file_inode);drain();
  ((struct nm_file_inode_ops*)(virtual_file+struct_offset.file_inode_ops))->f_inode=first;
  ((struct nm_file_inode_ops*)(virtual_file+struct_offset.file_inode_ops))->f_op=nm_virtual_directory_fops;
  struct nm_path* path=(void*)nm_file_path(virtual_file);path->dentry=virtual_dentry;
  assert(!nm_open(first,(void*)virtual_file)&&!nm_file_private(virtual_file));
  *(u32*)(virtual_file+struct_offset.file_flags)=1;assert(nm_open(first,(void*)virtual_file)==-EROFS);*(u32*)(virtual_file+struct_offset.file_flags)=0;
  assert(nm_virtual_directory_read((void*)virtual_file,NULL,1,NULL)==-EISDIR);
  unsigned char stat[256]={0};struct nm_path stat_path={.dentry=virtual_dentry};assert(!nm_virtual_directory_getattr(&stat_path,(void*)stat,77,88));
  assert(stat_calls==1&&((struct nm_kstat_prefix*)stat)->ino==leaf->v_ino&&((struct nm_kstat_prefix*)stat)->nlink==2);
  kf_nm_vfs_setpos=fixture_setpos;struct nm_dir_context ctx={.actor=fixture_actor,.pos=0};reset_emit();full_after=0;
  assert(!nm_virtual_directory_iterate((void*)virtual_file,&ctx)&&ctx.pos==0&&!emitted_count);
  full_after=1;assert(!nm_virtual_directory_iterate((void*)virtual_file,&ctx)&&ctx.pos==1&&has_name("."));
  reset_emit();assert(!nm_virtual_directory_iterate((void*)virtual_file,&ctx)&&has_name("..")&&has_name("extra"));
  assert(emitted_numbers[0]==nm_inode_number(parent)&&nm_virtual_position(ctx.pos,false));
  assert(nm_virtual_directory_llseek((void*)virtual_file,ctx.pos,0)==ctx.pos&&nm_virtual_directory_llseek((void*)virtual_file,0,1)==ctx.pos);
  assert(!nm_virtual_directory_llseek((void*)virtual_file,0,0));
  ctx.pos=0;reset_emit();assert(!nm_uid_add(1000));assert(!nm_virtual_directory_iterate((void*)virtual_file,&ctx)&&has_name(".")&&has_name("..")&&!has_name("extra"));
  assert(!nm_dentry_revalidate((void*)virtual_dentry,0));assert(!nm_uid_del(1000));flush_rcu();
  thread.flags=1UL<<TIF_32BIT;ctx.pos=2;reset_emit();assert(!nm_virtual_directory_iterate((void*)virtual_file,&ctx)&&has_name("extra")&&nm_virtual_position(ctx.pos,true));thread.flags=0;
  before=directory_refs;virtual_splice_error=1;reset_dentry(nested_dentry,"added",NULL);
  assert(PTR_ERR(nm_directory_lookup(parent,(void*)nested_dentry,0))==-ELOOP&&directory_refs==before&&rule->refs==2&&child_node->refs==2);virtual_splice_error=0;
  virtual_alias=1;reset_dentry(other_alias,"added",nm_owned_dentry_ops);assert(nm_directory_lookup(parent,(void*)nested_dentry,0)==(void*)other_alias&&directory_refs==before);
  reset_dentry(other_alias,"added",NULL);assert(PTR_ERR(nm_directory_lookup(parent,(void*)nested_dentry,0))==-EOPNOTSUPP&&virtual_drops>0);virtual_alias=0;
  assert(!nm_remove_child(&child_node->children,file_leaf));flush_rcu();nm_free_leaf(file_leaf);
  assert(!nm_remove_child(&root_node->children,leaf));assert(!nm_remove_leaf_rule(leaf,0,&updates));nm_finish_rule_updates(&updates);
  assert(rule->refs==1&&!nm_dentry_revalidate((void*)virtual_dentry,0));
  virtual_iput(first);virtual_iput(first);assert(!cached_directory);drain();flush_rcu();assert(child_node->refs==1);
  nm_directory_node_put(child_node);nm_free_leaf(leaf);nm_proxy_evict_inode(parent);flush_rcu();nm_directory_node_put(root_node);flush_rcu();
  assert(virtual_gets==virtual_puts-1); // 被拒绝的 alias 单独消耗一份返回引用。
  fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));
  fixture_vfree(nm_inode_engine.inode_ops);fixture_vfree(nm_inode_engine.file_ops);fixture_vfree(nm_owned_dentry_ops);
  fixture_vfree(nm_inode_engine.directory_ops);fixture_vfree(nm_virtual_directory_fops);
  assert(!rcu_depth&&!spin_depth&&!hash_depth&&!q_count);
  puts("virtual-directory inode reuse, child lookup, dot entries, UID visibility and retirement: PASS");return 0;
}
'''
    # 仅新增夹具的符号分派；原有 Oracle 及其所有断言完整保留。
    declaration = 'static unsigned long virtual_function_lookup(const char*);\n'
    start = source.index('/* Virtual directory identity and callbacks')
    source = source[:start] + declaration + source[start:]
    end = source.index('static struct inode* cached_directory;')
    source = source[:start] + source[start:end].replace('kallsyms_lookup_name_by_suffix', 'virtual_function_lookup') + source[end:]
    c = args.output/'virtual-directory.c'
    c.write_text(source)
    binary = args.output/'virtual-directory'
    result = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function',
                             '-I'+str(root/'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(binary)],
                            text=True, capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr)
    result.check_returncode()
    run = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr)
    run.check_returncode()
    files = ('nomount/nm_virtual_directory.c', 'nomount/nm_inode.c', 'nomount/nm_directory.c', 'nomount/nm_directory_nodes.c',
             'nomount/nm_offsets.c', 'nomount/nm_structs.h', 'nomount/nm_rules.h', 'nomount/nm_rules.c')
    receipt = {'scope': 'Developer host native call contracts; not native inode cache or concurrency proof',
               'sources': {name: sha(root/name) for name in files}, 'tool_sha256': sha(Path(__file__)),
               'directory_oracle_sha256': sha(root/'nomount/tools/test_directory.py'),
               'directory_receipt_sha256': sha(args.output/'directory-contract/receipt.json'),
               'dependencies': dependencies, 'result': run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
