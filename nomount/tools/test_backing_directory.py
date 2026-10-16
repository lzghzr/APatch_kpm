#!/usr/bin/env python3
"""执行backing 路径查询和合并枚举；宿主接口夹具不证明原生命名空间或锁。"""
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
    assert all(symbols.get(name) in ('t','T') for name in ('vfs_path_lookup',))
    command = [sys.executable,str(root/'nomount/tools/test_topology.py')]
    for name in ('symbols','reference','inode_reference','ops_reference','file_reference'):
        command += ['--'+name.replace('_','-'),str(getattr(args,name))]
    command += ['--output',str(args.output/'topology-contract')]
    subprocess.run(command, check=True)
    base = (args.output/'topology-contract/topology.c').read_text()
    base = base.replace('int main(void)', 'int topology_contract_main(void)')
    native = (root/'nomount/nm_native.c').read_text()
    source = base + 'static int (*kf_nm_iterate_dir)(void*,struct nm_dir_context*);\n'
    source += native[native.index('static int nm_iterate_backing'):native.index('// 同一 inode')]
    source += 'static unsigned long backing_query_lookup(const char*);\n'
    source += (root/'nomount/nm_backing_directory.c').read_text().replace('kallsyms_lookup_name_by_suffix','backing_query_lookup') + r'''
static _Alignas(8) unsigned char bridge_file[512],bridge_backing_file[512],bridge_child[256],bridge_inode[768];
static int query_calls,query_error,query_gets,query_puts,bridge_iterates,bridge_iterator_error,bridge_setpos_error;
static int64_t bridge_seek_error;
static struct nm_path bridge_base={.mnt=(void*)0x111};
static int bridge_query(struct dentry* base,struct vfsmount* mount,const char* name,unsigned int flags,struct nm_path* out) {
  assert(base==bridge_base.dentry&&(void*)mount==bridge_base.mnt&&flags==0&&!rcu_depth&&!spin_depth&&!manager_depth);
  assert(name[0]&&!strchr(name,'/')&&strcmp(name,".")&&strcmp(name,".."));query_calls++;
  if(query_error)return query_error;
  *out=(struct nm_path){.mnt=(void*)0x222,.dentry=(void*)bridge_child};query_gets++;return 0;
}
static void bridge_put(const struct nm_path* path) {
  assert(path->mnt==(void*)0x222&&path->dentry==(void*)bridge_child&&!rcu_depth&&!spin_depth&&!in_rcu);query_puts++;
}
static unsigned long backing_query_lookup(const char* name) {
  assert(!strcmp(name,"vfs_path_lookup"));return missing?0:(uintptr_t)bridge_query;
}
static int64_t bridge_setpos(void* file,int64_t pos,int64_t max) {
  assert(file==bridge_backing_file||file==bridge_file);
  if(bridge_setpos_error)return bridge_setpos_error;
  return fixture_setpos(file,pos,max);
}
static int64_t bridge_seek(struct file* file,int64_t pos,int whence) {
  assert(file==(void*)bridge_backing_file&&whence==0);
  if(bridge_seek_error)return bridge_seek_error;
  return fixture_seek(file,pos,whence);
}
static int bridge_iterate(void* file,struct nm_dir_context* context) {
  assert(file==bridge_backing_file&&!rcu_depth&&!spin_depth&&!manager_depth);bridge_iterates++;
  assert(*nm_file_position(file)==context->pos);
  if(bridge_iterator_error)return bridge_iterator_error;
  const char* names[]={".","..","native","replace","white","extra"};
  for(int i=context->pos;i<6;i++) {
    context->pos=i;
    if(context->actor(context,names[i],strlen(names[i]),i,i+50,i<2?4:8))return 0;
    context->pos=i+1;
  }
  *nm_file_position(file)=context->pos;return 0;
}
int main(void) {
  assert(!topology_contract_main());nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;
  target();directory_target();thread.flags=0;set_uid(1000);fail_alloc=0;
  missing="vfs_path_lookup";assert(nm_prepare_backing_directory_functions()==-ENOENT);missing=NULL;
  assert(!nm_prepare_backing_directory_functions());
  memset(parent_storage,0,sizeof(parent_storage));memset(backing_storage,0,sizeof(backing_storage));
  nm_inode_objects(parent)->i_op=native_iops;nm_inode_objects(backing)->i_op=native_iops;
  ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;
  *(u64*)((uintptr_t)parent+struct_offset.inode_number)=101;
  ((struct nm_dentry_head*)root_dentry)->d_inode=parent;((struct nm_dentry_head*)dentry_storage)->d_inode=backing;
  kf_nm_kern_path=fixture_path;kf_nm_path_put=host_path_put;
  struct nomount_rule* a;struct nomount_rule* b;struct nomount_rule* c;
  struct nomount_leaf* replacement=leaf_rule("/replace",0,0,&a);
  struct nomount_leaf* extra=leaf_rule("/extra",1000,0,&b);
  struct nomount_leaf* whiteout=leaf_rule("/white",0,NM_FLAG_WHITEOUT,&c);
  struct nm_directory_node* node=nm_new_directory_node();assert(node);
  assert(!nm_insert_child(&node->children,replacement));assert(!nm_insert_child(&node->children,extra));assert(!nm_insert_child(&node->children,whiteout));
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0040755;bridge_base.dentry=(void*)dentry_storage;
  ((struct nm_dentry_head*)bridge_child)->d_inode=(void*)bridge_inode;
  nm_inode_objects((void*)bridge_inode)->i_op=native_iops;((struct nm_inode_owner_prefix*)bridge_inode)->i_mode=0100644;
  kf_nm_path_put=bridge_put;
  struct nm_qstr name={.name="base.apk",.len=8};struct nm_path out;
  assert(!nm_lookup_backing_child(parent,&bridge_base,&name,&out)&&out.mnt==(void*)0x222&&out.dentry==(void*)bridge_child);
  kf_nm_path_put(&out);assert(query_gets==query_puts);
  const char* invalid[]={"",".","..","a/b"};int before=query_calls;
  for(unsigned int i=0;i<sizeof(invalid)/sizeof(*invalid);i++){name.name=invalid[i];name.len=strlen(invalid[i]);out=bridge_base;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-EINVAL&&!out.dentry&&!out.mnt);}
  name=(struct nm_qstr){.name="a\0b",.len=3};assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-EINVAL);
  name.len=256;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-EINVAL&&query_calls==before);
  assert(nm_lookup_backing_child(parent,&bridge_base,&name,&bridge_base)==-EINVAL&&bridge_base.dentry==dentry_storage);
  char longest[255];memset(longest,'x',sizeof(longest));name=(struct nm_qstr){.name=longest,.len=255};
  assert(!nm_lookup_backing_child(parent,&bridge_base,&name,&out));kf_nm_path_put(&out);
  name=(struct nm_qstr){.name="entry",.len=5};
  const int errors[]={-ENOENT,-EACCES,-ELOOP,-ESTALE,-ENOMEM};
  for(unsigned int i=0;i<sizeof(errors)/sizeof(*errors);i++){query_error=errors[i];assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==errors[i]&&!out.dentry&&!out.mnt);}query_error=0;
  ((struct nm_dentry_head*)bridge_child)->d_inode=NULL;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-ENOENT&&query_gets==query_puts);
  ((struct nm_dentry_head*)bridge_child)->d_inode=parent;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-ELOOP&&query_gets==query_puts);
  ((struct nm_dentry_head*)bridge_child)->d_inode=(void*)bridge_inode;
  nm_inode_engine.inode_ops=native_iops;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-ELOOP);nm_inode_engine.inode_ops=NULL;
  ((struct nm_inode_lookup_ops*)native_iops)->lookup=nm_directory_lookup;
  assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-ELOOP);((struct nm_inode_lookup_ops*)native_iops)->lookup=fixture_lookup;
  assert(nm_lookup_backing_child(backing,&bridge_base,&name,&out)==-ELOOP);
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;assert(nm_lookup_backing_child(parent,&bridge_base,&name,&out)==-ENOTDIR);
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0040755;
  ((struct nm_file_inode_ops*)(bridge_file+struct_offset.file_inode_ops))->f_inode=(void*)bridge_inode;
  ((struct nm_inode_owner_prefix*)bridge_inode)->i_mode=0040755;*(u64*)(bridge_inode+struct_offset.inode_number)=202;
  ((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_inode=backing;
  ((struct nm_path*)nm_file_path(bridge_file))->dentry=(void*)bridge_child;((struct nm_dentry_head*)bridge_child)->d_parent=(void*)root_dentry;
  nm_set_file_private(bridge_file,bridge_backing_file);kf_nm_iterate_dir=bridge_iterate;kf_nm_vfs_setpos=bridge_setpos;kf_nm_vfs_llseek=bridge_seek;
  kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;
  struct nm_dir_context context={.actor=fixture_actor};reset_emit();
  assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node));
  assert(has_name(".")&&has_name("..")&&has_name("native")&&!has_name("replace")&&!has_name("white")&&!has_name("extra"));
  assert(emitted_numbers[0]==202&&emitted_numbers[1]==101&&context.pos==6);
  reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("replace")&&has_name("extra")&&!has_name("white"));
  assert(nm_virtual_position(context.pos,false));before=bridge_iterates;
  reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&bridge_iterates==before&&!emitted_count);
  context.pos=0;reset_emit();full_after=0;
  assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&!context.pos&&!emitted_count);
  reset_emit();full_after=1;assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&context.pos==1&&has_name(".")&&!has_name(".."));
  reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("..")&&!has_name("."));
  context.pos=3;reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("replace")&&has_name("extra")&&nm_virtual_position(context.pos,false));
  set_uid(2000);context.pos=0;reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("extra")&&!has_name("replace")&&!has_name("white"));
  reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("replace")&&!has_name("extra"));
  assert(!nm_uid_add(2000));context.pos=0;reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("native")&&has_name("replace")&&has_name("white")&&has_name("extra"));
  context.pos=nm_directory_position(0,false);reset_emit();assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&!emitted_count);nm_uid_clear();flush_rcu();set_uid(1000);
  thread.flags=1UL<<TIF_32BIT;context.pos=nm_directory_position(0,true);reset_emit();
  assert(!nm_backing_directory_iterate((void*)bridge_file,&context,node)&&has_name("extra")&&context.pos<=0xffffffffLL);
  struct nomount_child_array* array=nm_rules_load(node->children);u32 count=array->count;array->count=65536;context.pos=nm_directory_position(0,true);
  assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-EOVERFLOW);array->count=count;thread.flags=0;
  context.pos=-1;assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-EINVAL);context.pos=0;
  bridge_setpos_error=-EINVAL;assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-EINVAL);bridge_setpos_error=0;
  bridge_iterator_error=-EACCES;reset_emit();assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-EACCES&&!emitted_count);bridge_iterator_error=0;
  nm_set_file_private(bridge_file,NULL);assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-EINVAL);nm_set_file_private(bridge_file,bridge_backing_file);
  ((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_inode=(void*)bridge_inode;
  assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-ELOOP);((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_inode=backing;
  // 模拟 i_fop 先发布：backing file 已保存模块 iterate 表，inode 的 i_op 仍为原生表。
  nm_set_operation_callback(native_fops,struct_offset.fop_iterate_shared,nm_directory_iterate);
  ((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_op=native_fops;
  assert(((const struct nm_inode_lookup_ops*)nm_inode_ops(backing))->lookup==fixture_lookup);
  assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-ELOOP);
  assert(nm_backing_directory_llseek((void*)bridge_file,nm_directory_position(0,false),0)==-ELOOP);
  ((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_op=nm_virtual_directory_fops;
  assert(nm_backing_directory_iterate((void*)bridge_file,&context,node)==-ELOOP);
  assert(nm_backing_directory_llseek((void*)bridge_file,0,0)==-ELOOP);
  ((struct nm_file_inode_ops*)(bridge_backing_file+struct_offset.file_inode_ops))->f_op=NULL;
  int64_t cookie=nm_directory_position(1,false);assert(nm_backing_directory_llseek((void*)bridge_file,cookie,0)==cookie);
  assert(nm_backing_directory_llseek((void*)bridge_file,0,1)==cookie);
  assert(nm_backing_directory_llseek((void*)bridge_file,0,0)==0&&!(*nm_file_position(bridge_backing_file)));
  bridge_seek_error=-ESPIPE;assert(nm_backing_directory_llseek((void*)bridge_file,1,0)==-ESPIPE);bridge_seek_error=0;
  kf_nm_path_put=host_path_put;nm_free_leaf(replacement);nm_free_leaf(extra);nm_free_leaf(whiteout);nm_directory_node_put(node);flush_rcu();
  assert(query_gets==query_puts&&!rcu_depth&&!spin_depth&&!manager_depth&&!q_count);
  puts("backing path ownership, native errors, merged enumeration, dot identity, UID and seek: PASS");return 0;
}
'''
    c=args.output/'backing-directory.c';c.write_text(source)
    result=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-I'+str(root/'nomount'),
                           '-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'backing-directory')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode()
    run=subprocess.run([str(args.output/'backing-directory')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'Developer host native-call contracts; not target permissions, VFS locks or namespace proof',
             'sources':{name:sha(root/name) for name in ('nomount/nm_backing_directory.c','nomount/nm_native.c','nomount/nm_directory.c','nomount/nm_directory_nodes.c','nomount/nm_file.c')},
             'tool_sha256':sha(Path(__file__)),'topology_oracle_sha256':sha(root/'nomount/tools/test_topology.py'),
             'topology_receipt_sha256':sha(args.output/'topology-contract/receipt.json'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':main()
