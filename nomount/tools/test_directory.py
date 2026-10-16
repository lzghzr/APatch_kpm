#!/usr/bin/env python3
"""执行原生父目录的 lookup、枚举和缓存重验证；宿主夹具不证明 VFS 并发。"""
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
    # 原有 inode Oracle 完整运行并保留；扩展测试仅追加新的入口和夹具。
    subprocess.run([sys.executable, str(root/'nomount/tools/test_inode.py'), '--symbols', str(args.symbols),
                    '--reference', str(args.inode_reference), '--ops-reference', str(args.ops_reference),
                    '--file-reference', str(args.file_reference), '--output', str(args.output/'inode-contract')], check=True)
    base = (args.output/'inode-contract/inode.c').read_text()
    base = base.replace('int main(void)', 'int inode_contract_main(void)')
    base = base.replace('kallsyms_lookup_name_by_suffix', 'inode_fixture_lookup')
    base = base.replace('nm_rcu_call', 'inode_fixture_rcu_call')
    # 查找与规则层使用独立的排队 RCU 夹具，保留上面的旧 Oracle 原貌。
    source = base + (root/'nomount/nm_protocol.h').read_text() + r'''
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
static int64_t (*kf_nm_vfs_setpos)(void*,int64_t,int64_t);
static int rcu_depth, spin_depth, drops, dputs, native_lookups, native_revalidates, native_weak, native_releases;
static struct rcu_head* queued[128]; static void (*callbacks[128])(struct rcu_head*);static int q_count;
static void nm_rcu_call(struct rcu_head* h,void (*f)(struct rcu_head*)) {assert(q_count<128);queued[q_count]=h;callbacks[q_count++]=f;}
static void flush_rcu(void) {assert(!rcu_depth);while(q_count){struct rcu_head* h=queued[0];void (*f)(struct rcu_head*)=callbacks[0];memmove(queued,queued+1,--q_count*sizeof(*queued));memmove(callbacks,callbacks+1,q_count*sizeof(*callbacks));in_rcu=1;f(h);in_rcu=0;}}
static void nm_rcu_read_lock(void) {rcu_depth++;}
static void nm_rcu_read_unlock(void) {assert(rcu_depth>0);rcu_depth--;}
static void nm_rcu_synchronize(void) {assert(!rcu_depth);flush_rcu();}
static void fixture_vfree(const void* p) {if(p)host_free(p);}
struct fixture_cred_offset {int16_t fsuid_offset;} cred_offset;
struct fixture_task_offset {int16_t cred_offset;} task_struct_offset;
struct thread_info {unsigned long flags;};
static _Alignas(8) unsigned char task_buffer[128],cred_buffer[128];
static struct thread_info thread;
typedef struct {u32 val;} kuid_t;
static void* get_current(void) {return task_buffer;}
#define current get_current()
#define TIF_32BIT 22
static struct thread_info* current_thread_info(void) {return &thread;}
'''
    common = (root/'kpm_utils.h').read_text().split('#define __GET_CREDID',1)[1].split('// BTF',1)[0]
    source += '#define __GET_CREDID' + common
    source += (root/'nomount/nm_current.c').read_text().replace('#include <linux/thread_info.h>','')
    offset = (root/'nomount/nm_offsets.c').read_text()
    source += offset[offset.index('static int nm_prepare_directory_layout'):]
    native = (root/'nomount/nm_native.c').read_text()
    source += native[native.index('static int nm_iterate_original'):native.index('// preparse 收到')]
    # 两个引用函数已在旧 inode Oracle 中使用实际生产实现；其余规则代码完整包含。
    rules = (root/'nomount/nm_rules.c').read_text()
    rules = rules[:rules.index('static void nm_rule_get')] + rules[rules.index('// 管理层解锁后调用'):]
    source += rules + (root/'nomount/nm_directory_nodes.c').read_text() + (root/'nomount/nm_directory.c').read_text()
    reference = json.loads(args.reference.read_text())['values']
    ops = json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']
    source += '\nstatic void directory_target(void) {\n'
    source += f'struct_offset.dentry_ops={reference["dentry.d_op"]};struct_offset.dentry_lock={reference["dentry.d_lockref"]};\n'
    source += f'struct_offset.dentry_ops_size={reference["dentry_operations.size"]};struct_offset.dop_init={reference["dentry_operations.d_init"]};struct_offset.dop_release={reference["dentry_operations.d_release"]};\n'
    source += f'struct_offset.fop_iterate={ops["file_operations"]["iterate"]};struct_offset.fop_iterate_shared={ops["file_operations"]["iterate_shared"]};\n}}\n'
    source += r'''
static _Alignas(64) unsigned char native_iops[512],native_fops[512],native_dops[256];
static _Alignas(8) unsigned char root_dentry[256],lookup_dentry[256],alias_dentry[256],parent_file[512];
static struct dentry* alias=(void*)alias_dentry;
static int parent_gets,parent_puts;
static int use_alias, lookup_error, iterator_error, full_after, emitted_count;
static char emitted[32][256];static unsigned int emitted_types[32];static u64 emitted_numbers[32];
static int native_stage;
static void reset_dentry(void* data,const char* name,const void* ops) {
  memset(data,0,256);struct nm_dentry_head* d=data;d->d_parent=root_dentry;d->d_name.name=name;d->d_name.len=strlen(name);
  nm_dentry_objects(data)->d_op=ops;
}
static void set_uid(u32 uid) {*(u32*)(cred_buffer+cred_offset.fsuid_offset)=uid;}
static u32 fixture_hash(const void* salt,const char* name,unsigned int len) {(void)salt;u32 h=2166136261U;while(len--)h=(h^(u8)*name++)*16777619U;return h;}
static int fixture_path(const char* name,unsigned int flags,struct nm_path* path) {assert(name[0]=='/'&&flags==1);*path=backing_path;return 0;}
static void fixture_lock(void* lock) {assert(!spin_depth && lock);spin_depth=1;}
static void fixture_unlock(void* lock) {assert(spin_depth && lock);spin_depth=0;}
static void fixture_drop(struct dentry* d) {(void)d;assert(!spin_depth);drops++;}
static struct dentry* fixture_parent(struct dentry* d) {assert(!rcu_depth&&!spin_depth);parent_gets++;return ((struct nm_dentry_head*)d)->d_parent;}
static void fixture_dput(struct dentry* d) {assert(!in_rcu);if(d==(void*)root_dentry)parent_puts++;else{assert(d==alias);dputs++;}}
static struct dentry* fixture_splice(struct inode* inode,struct dentry* d) {
  assert(!rcu_depth&&!spin_depth);((struct nm_dentry_head*)d)->d_inode=inode;return NULL;
}
static struct dentry* fixture_lookup(struct inode* inode,struct dentry* d,unsigned int flags) {
  assert(inode==parent&&!rcu_depth&&!spin_depth);(void)flags;native_lookups++;
  if(lookup_error)return ERR_PTR(lookup_error);
  struct dentry* result=use_alias?alias:d;((struct nm_dentry_head*)result)->d_inode=parent;return use_alias?alias:NULL;
}
static int fixture_revalidate(struct dentry* d,unsigned int flags) {(void)d;(void)flags;native_revalidates++;return 7;}
static int fixture_weak(struct dentry* d,unsigned int flags) {(void)d;(void)flags;native_weak++;return 11;}
static void fixture_release(struct dentry* d) {(void)d;assert(!rcu_depth&&!spin_depth);native_releases++;}
static void fixture_call_release(struct dentry* d) {void (*release)(struct dentry*)=nm_operation_callback(nm_dentry_ops(d),struct_offset.dop_release);if(release)release(d);}
static int64_t fixture_setpos(void* file,int64_t pos,int64_t maximum) {assert(pos>=0&&pos<=maximum);*nm_file_position(file)=pos;return pos;}
static int64_t fixture_seek(struct file* file,int64_t pos,int whence) {assert(whence==0);*nm_file_position(file)=pos;return pos;}
static int fixture_actor(struct nm_dir_context* ctx,const char* name,int length,int64_t pos,u64 number,unsigned int type) {
  assert(!rcu_depth&&!spin_depth && emitted_count<32 && length>0 && length<256);(void)pos;
  if(full_after>=0&&emitted_count>=full_after)return -EINVAL;
  memcpy(emitted[emitted_count],name,length);emitted[emitted_count][length]=0;
  emitted_types[emitted_count]=type;emitted_numbers[emitted_count++]=number;(void)ctx;return 0;
}
static int fixture_iterate(void* file,struct nm_dir_context* ctx) {
  assert(file==(void*)parent_file&&!rcu_depth);if(iterator_error)return iterator_error;
  if(native_stage)return 0;
  const char* names[]={"native","replace","white"};
  for(int i=ctx->pos;i<3;i++) {ctx->pos=i;if(ctx->actor(ctx,names[i],strlen(names[i]),i,i+10,8))return 0;ctx->pos=i+1;}
  native_stage=1;return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if(missing&&!strcmp(missing,name))return 0;
  if(!strcmp(name,"_raw_spin_lock"))return (uintptr_t)fixture_lock;
  if(!strcmp(name,"_raw_spin_unlock"))return (uintptr_t)fixture_unlock;
  if(!strcmp(name,"d_drop"))return (uintptr_t)fixture_drop;
  if(!strcmp(name,"dget_parent"))return (uintptr_t)fixture_parent;
  if(!strcmp(name,"dput"))return (uintptr_t)fixture_dput;
  if(!strcmp(name,"kern_path"))return (uintptr_t)fixture_path;
  if(!strcmp(name,"path_put"))return (uintptr_t)host_path_put;
  if(!strcmp(name,"full_name_hash"))return (uintptr_t)fixture_hash;
  return inode_fixture_lookup(name);
}
static struct nomount_leaf* leaf_rule(const char* path,u32 uid,u32 flags,struct nomount_rule** rule) {
  struct nomount_leaf* leaf=nm_alloc_leaf(path,strlen(path));assert(leaf);
  *rule=nm_alloc_rule("/backing",8,flags,uid);assert(!IS_ERR(*rule));
  struct nm_rule_updates updates={0};assert(!nm_set_leaf_rule(leaf,*rule,&updates));return leaf;
}
static void reset_emit(void) {emitted_count=0;full_after=-1;memset(emitted,0,sizeof(emitted));}
static int has_name(const char* name) {for(int i=0;i<emitted_count;i++)if(!strcmp(emitted[i],name))return 1;return 0;}
int main(void) {
  assert(!inode_contract_main());nm_inode_engine=(struct nm_inode_engine){0};target();directory_target();
  kf_nm_vfree=fixture_vfree;task_struct_offset.cred_offset=40;cred_offset.fsuid_offset=52;*(void**)(task_buffer+40)=cred_buffer;
  *(u32*)(cred_buffer+4)=5678;set_uid(1000);assert(nm_current_fsuid()==1000);cred_offset.fsuid_offset=-1;assert(nm_prepare_current()==-ENOENT);cred_offset.fsuid_offset=52;
  assert(!nm_prepare_inode_engine());kf_nm_d_splice_alias=fixture_splice;
  missing="d_drop";assert(nm_prepare_directory_engine()==-ENOENT);missing=NULL;
  fail_alloc=1;assert(nm_prepare_directory_engine()==-ENOMEM&&!nm_owned_dentry_ops);assert(!nm_prepare_directory_engine());
  assert(!nm_prepare_rule_functions());
  memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;
  nm_set_operation_callback(original_sops,struct_offset.sop_drop_inode,host_drop);nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
  ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;nm_inode_objects(parent)->i_op=native_iops;
  *(const void**)((uintptr_t)parent+struct_offset.inode_file_ops)=native_fops;
  ((struct nm_inode_lookup_ops*)native_iops)->lookup=fixture_lookup;
  ((struct nm_file_io_ops*)native_fops)->llseek=fixture_seek;
  nm_set_operation_callback(native_fops,struct_offset.fop_iterate_shared,fixture_iterate);native_iops[255]=0x51;native_fops[295]=0x52;
  struct nm_directory_node* node=nm_new_directory_node();assert(node&&node->refs==1);
  fail_alloc=1;assert(nm_install_directory(parent,node)==-ENOMEM&&node->refs==1&&nm_inode_ops(parent)==native_iops);
  fail_alloc=2;assert(nm_install_directory(parent,node)==-ENOMEM&&node->refs==1&&nm_inode_ops(parent)==native_iops);
  assert(!nm_install_directory(parent,node)&&node->refs==2);
  assert(((const u8*)nm_inode_ops(parent))[255]==0x51&&((const u8*)nm_inode_file_ops(parent))[295]==0x52);
  ((struct nm_dentry_head*)root_dentry)->d_inode=parent;
  ((struct nm_file_inode_ops*)(parent_file+struct_offset.file_inode_ops))->f_inode=parent;
  ((struct nm_file_inode_ops*)(parent_file+struct_offset.file_inode_ops))->f_op=nm_inode_file_ops(parent);
  struct nomount_rule *replacement,*white,*extra;struct nomount_leaf* replace_leaf=leaf_rule("/replace",0,0,&replacement);
  struct nomount_leaf* white_leaf=leaf_rule("/white",0,NM_FLAG_WHITEOUT,&white);struct nomount_leaf* extra_leaf=leaf_rule("/extra",1000,0,&extra);
  assert(!nm_insert_child(&node->children,replace_leaf));assert(!nm_insert_child(&node->children,white_leaf));assert(!nm_insert_child(&node->children,extra_leaf));
  assert(!nm_install_directory(parent,node));
  reset_dentry(lookup_dentry,"replace",NULL);assert(!nm_directory_lookup(parent,(void*)lookup_dentry,0));assert(created&&nm_inode_number(created)==replace_leaf->v_ino);
  assert(nm_dentry_revalidate((void*)lookup_dentry,0)==1);int before=drops;assert(nm_dentry_revalidate((void*)lookup_dentry,0x40)==-ECHILD&&drops==before);
  assert(!nm_uid_add(1000));assert(!nm_dentry_revalidate((void*)lookup_dentry,0)&&drops==before+1);assert(!nm_uid_del(1000));flush_rcu();
  struct nm_rule_updates updates={0};struct nomount_rule* next=nm_alloc_rule("/new",4,0,0);assert(!IS_ERR(next));assert(!nm_set_leaf_rule(replace_leaf,next,&updates));nm_finish_rule_updates(&updates);
  assert(!nm_dentry_revalidate((void*)lookup_dentry,0));host_iput(created);drain();
  reset_dentry(lookup_dentry,"white",NULL);assert(!nm_directory_lookup(parent,(void*)lookup_dentry,0)&&!nm_dentry_inode(lookup_dentry));assert(nm_dentry_revalidate((void*)lookup_dentry,0)==1);
  ((struct nm_dentry_control_ops*)native_dops)->d_revalidate=fixture_revalidate;((struct nm_dentry_control_ops*)native_dops)->d_weak_revalidate=fixture_weak;nm_set_operation_callback(native_dops,struct_offset.dop_release,fixture_release);
  reset_dentry(lookup_dentry,"native",native_dops);assert(!nm_directory_lookup(parent,(void*)lookup_dentry,0));assert(nm_dentry_revalidate((void*)lookup_dentry,0)==7&&nm_dentry_weak_revalidate((void*)lookup_dentry,0)==11);
  fixture_call_release((void*)lookup_dentry);flush_rcu();assert(native_releases==1);
  const void* shared_ops=nm_dentry_ops(lookup_dentry);int prior_allocations=alloc_calls;
  reset_dentry(lookup_dentry,"native",native_dops);assert(!nm_directory_lookup(parent,(void*)lookup_dentry,0)&&nm_dentry_ops(lookup_dentry)==shared_ops&&alloc_calls==prior_allocations);fixture_call_release((void*)lookup_dentry);
  native_dops[191]^=1;reset_dentry(lookup_dentry,"native",native_dops);assert(!nm_directory_lookup(parent,(void*)lookup_dentry,0)&&nm_dentry_ops(lookup_dentry)!=shared_ops&&alloc_calls==prior_allocations+1);fixture_call_release((void*)lookup_dentry);native_dops[191]^=1;

  reset_dentry(lookup_dentry,"replace",native_dops);const void* original=nm_dentry_ops(lookup_dentry);assert(PTR_ERR(nm_directory_lookup(parent,(void*)lookup_dentry,0))==-EOPNOTSUPP&&nm_dentry_ops(lookup_dentry)==original);
  reset_dentry(lookup_dentry,"replace",NULL);nm_dentry_objects(lookup_dentry)->d_fsdata=(void*)1;assert(PTR_ERR(nm_directory_lookup(parent,(void*)lookup_dentry,0))==-EOPNOTSUPP);
  reset_dentry(lookup_dentry,"native",NULL);lookup_error=-EIO;assert(PTR_ERR(nm_directory_lookup(parent,(void*)lookup_dentry,0))==-EIO);lookup_error=0;
  reset_dentry(alias_dentry,"native",NULL);use_alias=1;fail_alloc=1;before=drops;assert(PTR_ERR(nm_directory_lookup(parent,(void*)lookup_dentry,0))==-ENOMEM&&drops==before+1&&dputs==1);use_alias=0;
  struct nm_dir_context ctx={.actor=fixture_actor,.pos=0};kf_nm_vfs_setpos=fixture_setpos;reset_emit();native_stage=0;
  assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("native")&&!has_name("replace")&&!has_name("white")&&!has_name("extra"));
  reset_emit();assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("replace")&&has_name("extra")&&!has_name("white"));assert(nm_virtual_position(ctx.pos,false));
  int64_t cookie=nm_directory_position(0,false);assert(nm_directory_llseek((void*)parent_file,cookie,0)==cookie&&nm_directory_llseek((void*)parent_file,0,1)==cookie);
  assert(!nm_directory_llseek((void*)parent_file,0,0));iterator_error=-EIO;ctx.pos=0;assert(nm_directory_iterate((void*)parent_file,&ctx)==-EIO);iterator_error=0;
  // 缓冲区满时保留当前项 cookie；恢复调用继续交付同一条目。
  reset_emit();full_after=0;ctx.pos=nm_directory_position(0,false);assert(!nm_directory_iterate((void*)parent_file,&ctx)&&ctx.pos==nm_directory_position(0,false));full_after=-1;
  assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("replace")&&has_name("extra"));
  thread.flags=1UL<<TIF_32BIT;assert(nm_current_compat());reset_emit();ctx.pos=nm_directory_position(0,true);assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("replace")&&ctx.pos<=0xffffffffLL);
  struct nomount_child_array* array=nm_rules_load(node->children);u32 count=array->count;array->count=65536;ctx.pos=nm_directory_position(0,true);assert(nm_directory_iterate((void*)parent_file,&ctx)==-EOVERFLOW);array->count=count;thread.flags=0;
  set_uid(2000);reset_emit();ctx.pos=nm_directory_position(0,false);assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("replace")&&!has_name("extra"));
  assert(!nm_uid_add(2000));reset_emit();ctx.pos=0;native_stage=0;assert(!nm_directory_iterate((void*)parent_file,&ctx)&&has_name("native")&&has_name("replace")&&has_name("white"));nm_uid_clear();flush_rcu();
  // 清空拓扑视图后 native evict 恢复原表；RCU 回调只释放私有对象。
  assert(!nm_remove_child(&node->children,replace_leaf));assert(!nm_remove_child(&node->children,white_leaf));assert(!nm_remove_child(&node->children,extra_leaf));flush_rcu();
  nm_proxy_evict_inode(parent);assert(nm_inode_ops(parent)==native_iops&&nm_inode_file_ops(parent)==native_fops);flush_rcu();assert(node->refs==1);
  nm_directory_node_put(node);flush_rcu();nm_free_leaf(replace_leaf);nm_free_leaf(white_leaf);nm_free_leaf(extra_leaf);
  fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));fixture_vfree(nm_inode_engine.inode_ops);fixture_vfree(nm_inode_engine.file_ops);fixture_vfree(nm_owned_dentry_ops);
  while(nm_dentry_proxies){struct nm_dentry_proxy* entry=nm_dentry_proxies;nm_dentry_proxies=entry->next;fixture_vfree(entry);}
  assert(!rcu_depth&&!spin_depth&&!q_count&&parent_gets==parent_puts);puts("native-parent lookup, UID cache validation, enumeration, cookies and proxy cleanup: PASS");return 0;
}
'''
    c = args.output/'directory.c'; c.write_text(source)
    binary = args.output/'directory'
    built = subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-I'+str(root/'nomount'),
                            '-fsanitize=address,undefined','-g',str(c),'-o',str(binary)],text=True,capture_output=True)
    (args.output/'compile.log').write_text(built.stdout+built.stderr);built.check_returncode()
    run = subprocess.run([str(binary)],text=True,capture_output=True);(args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    files=('nomount/nm_directory.c','nomount/nm_directory_nodes.c','nomount/nm_current.c','nomount/nm_rules.c',
           'nomount/nm_rules.h','nomount/nm_structs.h','nomount/nm_offsets.c','nomount/nm_inode.c','kpm_utils.h')
    receipt={'scope':'Developer native-interface host contracts; not kernel concurrency or filesystem proof',
             'sources':{name:sha(root/name) for name in files},'tool_sha256':sha(Path(__file__)),
             'inode_oracle_sha256':sha(root/'nomount/tools/test_inode.py'),'inode_receipt_sha256':sha(args.output/'inode-contract/receipt.json'),
             'reference_sha256':sha(args.reference),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__ == '__main__':
    main()
