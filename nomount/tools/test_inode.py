#!/usr/bin/env python3
"""执行普通文件物化、原生表复制及回收契约；不模拟 VFS 并发或文件系统私有对象。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('symbols', 'reference', 'ops-reference', 'file-reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    native = json.loads(args.reference.read_text())['values']
    ops = json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']
    file = json.loads(args.file_reference.read_text())['values']
    symbols = {name: kind for _, kind, name in json.loads(args.symbols.read_text())}
    deps = ('new_inode', 'd_splice_alias', 'truncate_inode_pages_final', 'clear_inode', 'vfs_getattr_nosec')
    assert all(symbols.get(name) in ('t', 'T') for name in deps)
    files = ('nomount/nm_structs.h', 'nomount/nm_rules.h', 'nomount/nm_offsets.c',
             'nomount/nm_operations.c', 'nomount/nm_file.c', 'nomount/nm_rules.c', 'nomount/nm_inode.c')
    source = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define CONFIG_KPM_BASELINES 1
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
struct rcu_head { struct rcu_head* next; void (*func)(struct rcu_head*); };
static int fail_alloc, alloc_calls, frees, path_puts, in_rcu;
static const void** race_slot;
static const void* race_value;
static void* host_alloc(unsigned long size) {
  if (race_slot) { *race_slot=race_value;race_slot=NULL; }
  alloc_calls++; if (fail_alloc && !--fail_alloc) return NULL; return calloc(1,size);
}
static void host_free(const void* p) { assert(p); frees++; free((void*)p); }
static void* (*kf_nm_vzalloc)(unsigned long) = host_alloc;
static void (*kf_nm_vfree)(const void*) = host_free;
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
static void nm_rcu_call(struct rcu_head*, void (*)(struct rcu_head*));
'''
    source += (root / files[0]).read_text() + (root / files[1]).read_text()
    source += (root / files[2]).read_text().split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
    source += '''static int nm_prepare_inode_layout(void) { struct struct_offset o = struct_offset; return nm_validate_inode_offsets(&o); }
static void host_path_put(const struct nm_path* path) { assert(path->dentry && !in_rcu); path_puts++; }
static void (*kf_nm_path_put)(const struct nm_path*) = host_path_put;
'''
    rules = (root / files[5]).read_text()
    source += rules[rules.index('static void nm_rule_get'):rules.index('// 管理层解锁后调用')]
    source += (root / files[3]).read_text() + (root / files[4]).read_text() + (root / files[6]).read_text()
    mapping = {'inode_superblock': 'inode.i_sb', 'inode_number': 'inode.i_ino', 'inode_nlink': 'inode.i_nlink',
               'inode_size': 'inode.i_size', 'inode_private': 'inode.i_private', 'inode_file_ops': 'inode.i_fop',
               'inode_data': 'inode.i_data', 'inode_data_size': 'address_space_size',
               'inode_hash': 'inode.i_hash', 'inode_blocks': 'inode.i_blocks'}
    source += '\nstatic void target(void) {\n' + '\n'.join(f'struct_offset.{k} = {native[v]};' for k, v in mapping.items())
    for kind, dest, member in [('inode_operations', 'iop_getattr', 'getattr'), ('super_operations', 'sop_drop_inode', 'drop_inode'),
                               ('super_operations', 'sop_evict_inode', 'evict_inode')]:
        source += f'\nstruct_offset.{dest} = {ops[kind][member]};'
    for kind, dest in [('file_operations', 'file_ops_size'), ('inode_operations', 'inode_ops_size'), ('super_operations', 'super_ops_size')]:
        source += f'\nstruct_offset.{dest} = {ops[kind]["size"]};'
    for dest, key in [('file_private', 'file.private_data'), ('file_position', 'file.f_pos'), ('file_flags', 'file.f_flags'),
                       ('file_cred', 'file.f_cred'), ('file_mapping', 'file.f_mapping'), ('fop_open', 'file_operations.open'),
                       ('fop_release', 'file_operations.release'), ('fop_mmap', 'file_operations.mmap'),
                       ('fop_splice_read', 'file_operations.splice_read')]:
        source += f'\nstruct_offset.{dest} = {file[key]};'
    source += '\nstruct_offset.file_inode_ops = 32; }\n'
    source += r'''
static _Alignas(8) unsigned char parent_storage[768], backing_storage[768], dentry_storage[128];
static _Alignas(64) unsigned char original_sops[512];
static struct nm_super_head sb;
static struct inode* parent = (void*)parent_storage;
static struct inode* backing = (void*)backing_storage;
static struct nm_path backing_path = {.mnt=(void*)1,.dentry=dentry_storage};
static struct inode* created;
static struct inode* eviction_target;
static struct rcu_head* pending_rcu;
static void (*pending_func)(struct rcu_head*);
static int new_fail, splice_fail, attr_error, original_drops, original_evicts, truncates, clears;
static const char* missing;
static void nm_rcu_call(struct rcu_head* h, void (*f)(struct rcu_head*)) { assert(!pending_rcu); pending_rcu=h;pending_func=f; }
static void drain(void) { if (pending_rcu) {in_rcu=1;pending_func(pending_rcu);pending_rcu=NULL;in_rcu=0;} }
static struct inode* host_new(struct super_block* super) {
  assert(super == (void*)&sb); if (new_fail) return NULL;
  created = calloc(1,768); assert(created);
  eviction_target=created;
  nm_inode_objects(created)->i_sb = super;
  nm_inode_objects(created)->i_mapping = nm_inode_data(created);
  *(u32*)((uintptr_t)created+struct_offset.inode_nlink)=1;
  return created;
}
static void host_truncate(void* mapping) {
  assert(eviction_target && mapping == nm_inode_data(eviction_target) && mapping != nm_inode_mapping(backing)); truncates++;
}
static void host_clear(struct inode* inode) {
  assert(inode == eviction_target);
  if (nm_is_file_inode(inode)) assert(!nm_inode_private(inode) && nm_inode_mapping(inode)==nm_inode_data(inode));
  clears++;
}
static void host_iput(struct inode* inode) {
  assert(inode == created); assert(nm_proxy_drop_inode(inode) == 1);
  nm_proxy_evict_inode(inode); free(created); created=NULL;
}
static struct dentry* host_splice(struct inode* inode, struct dentry* dentry) {
  assert(inode == created && dentry == (void*)1234);
  if (splice_fail) {host_iput(inode);return ERR_PTR(-ELOOP);} // 消耗 inode 引用的原生失败契约。
  return NULL;
}
static int host_attr(const struct nm_path* path, struct kstat* stat, u32 mask, unsigned int flags) {
  assert(path->dentry == backing_path.dentry && mask == 77 && flags == 88);
  if (attr_error) return attr_error;
  memset(stat,0xa5,256); ((struct nm_kstat_prefix*)stat)->ino=999; return 0;
}
static int host_drop(struct inode* inode) {assert(inode==parent);original_drops++;return 9;}
static void host_evict(struct inode* inode) {assert(inode==parent);original_evicts++;}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (missing && !strcmp(name,missing)) return 0;
  if (!strcmp(name,"new_inode")) return (uintptr_t)host_new;
  if (!strcmp(name,"d_splice_alias")) return (uintptr_t)host_splice;
  if (!strcmp(name,"truncate_inode_pages_final")) return (uintptr_t)host_truncate;
  if (!strcmp(name,"clear_inode")) return (uintptr_t)host_clear;
  if (!strcmp(name,"vfs_getattr_nosec")) return (uintptr_t)host_attr;
  return 0;
}
int main(void) {
  target(); assert(nm_validate_inode_offsets(&(struct struct_offset){0}) == -EINVAL);
  struct struct_offset valid=struct_offset;
  struct_offset.inode_data_size=4097;assert(nm_prepare_inode_engine()==-EINVAL);struct_offset=valid;
  struct_offset.inode_data=struct_offset.inode_private;assert(nm_prepare_inode_engine()==-EINVAL);struct_offset=valid;
  missing="clear_inode";assert(nm_prepare_inode_engine()==-ENOENT);missing=NULL;
  fail_alloc=1;assert(nm_prepare_inode_engine()==-ENOMEM && !nm_inode_engine.inode_ops);
  fail_alloc=2;int old_frees=frees;assert(nm_prepare_inode_engine()==-ENOMEM && !nm_inode_engine.inode_ops && frees==old_frees+1);
  assert(!nm_prepare_inode_engine());assert(nm_prepare_inode_engine()==-EALREADY);
  nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;sb.s_dev=456;
  nm_set_operation_callback(original_sops,struct_offset.sop_drop_inode,host_drop);
  nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
  original_sops[0]=0x55;original_sops[16]=0x66;original_sops[279]=0x77;
  ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;
  ((struct nm_inode_owner_prefix*)backing)->i_uid=1000;((struct nm_inode_owner_prefix*)backing)->i_gid=2000;
  nm_inode_objects(backing)->i_mapping=(void*)9876;
  struct nm_inode_size_times* backing_times=(void*)((uintptr_t)backing+struct_offset.inode_size);
  *backing_times=(struct nm_inode_size_times){.i_size=4567,.i_atime={1,2},.i_mtime={3,4},.i_ctime={5,6}};
  struct nomount_rule* rule=calloc(1,sizeof(*rule));rule->refs=1;rule->r_path=backing_path;
  assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,rule,42))==-ENODEV);
  fail_alloc=1;assert(nm_install_super_proxy((void*)&sb)==-ENOMEM && sb.s_op==original_sops);
  unsigned char alternate_sops[512]={0};race_slot=&sb.s_op;race_value=alternate_sops;
  old_frees=frees;assert(nm_install_super_proxy((void*)&sb)==-EAGAIN && sb.s_op==alternate_sops && frees==old_frees+1);
  sb.s_op=original_sops;
  assert(!nm_install_super_proxy((void*)&sb));const void* clone=sb.s_op;
  int before=alloc_calls;assert(!nm_install_super_proxy((void*)&sb) && alloc_calls==before);
  assert(clone!=original_sops && ((const u8*)clone)[0]==0x55 && ((const u8*)clone)[16]==0x66 && ((const u8*)clone)[279]==0x77);
  assert(nm_proxy_drop_inode(parent)==9 && original_drops==1);nm_proxy_evict_inode(parent);assert(original_evicts==1);
  // 原生无 drop 回调时的 fallback，不能把所有真实 inode 都强制丢弃。
  nm_set_operation_callback(original_sops,struct_offset.sop_drop_inode,NULL);
  *(u32*)((uintptr_t)parent+struct_offset.inode_nlink)=1;
  *((void**)((uintptr_t)parent+struct_offset.inode_hash)+1)=(void*)1;assert(!nm_proxy_drop_inode(parent));
  *((void**)((uintptr_t)parent+struct_offset.inode_hash)+1)=NULL;assert(nm_proxy_drop_inode(parent)==1);
  nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,NULL);eviction_target=parent;
  nm_proxy_evict_inode(parent);assert(truncates==1 && clears==1);
  truncates=clears=0;
  fail_alloc=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,rule,42))==-ENOMEM && rule->refs==1);
  new_fail=1;assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,rule,42))==-ENOMEM && rule->refs==1);new_fail=0;
  rule->flags=NM_FLAG_IS_DIR;assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,rule,42))==-EOPNOTSUPP);rule->flags=0;
  assert(!nm_materialize_file(parent,(void*)1234,rule,42) && rule->refs==2 && created);
  assert(nm_inode_number(created)==42 && nm_inode_superblock(created)==(void*)&sb && nm_inode_mapping(created)==(void*)9876);
  assert(nm_inode_mode(created)==0100644 && !memcmp((void*)((uintptr_t)created+struct_offset.inode_size),backing_times,sizeof(*backing_times)));
  _Alignas(8) unsigned char stat_buffer[256];struct nm_path outer={.dentry=dentry_storage};
  ((struct nm_dentry_head*)dentry_storage)->d_inode=created;
  assert(!nm_file_getattr(&outer,(void*)stat_buffer,77,88));assert(((struct nm_kstat_prefix*)stat_buffer)->ino==42 && ((struct nm_kstat_prefix*)stat_buffer)->dev==456 && stat_buffer[255]==0xa5);
  attr_error=-EIO;assert(nm_file_getattr(&outer,(void*)stat_buffer,77,88)==-EIO);attr_error=0;
  ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;
  // 管理侧撤销规则后 inode 仍持有最后引用；evict 中释放路径，RCU 回调只释放私有元数据。
  nm_rule_put(rule);assert(rule->refs==1 && !path_puts);host_iput(created);assert(path_puts==1 && pending_rcu && truncates==1 && clears==1);drain();
  rule=calloc(1,sizeof(*rule));rule->refs=1;rule->r_path=backing_path;splice_fail=1;
  assert(PTR_ERR(nm_materialize_file(parent,(void*)1234,rule,42))==-ELOOP && !created && rule->refs==1);drain();nm_rule_put(rule);
  // 只在宿主夹具结束时回收驻留表，生产代码不撤销已发布表。
  host_free((const void*)((uintptr_t)clone - offsetof(struct nm_super_proxy,table)));
  host_free(nm_inode_engine.inode_ops);host_free(nm_inode_engine.file_ops);
  puts("inode materialization, full super table preservation, error cleanup and backing lifetime: PASS");return 0;
}
'''
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    args.output.mkdir(parents=True, exist_ok=False)
    cfile=args.output/'inode.c';cfile.write_text(source)
    binary=args.output/'inode'
    built=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-I'+str(root/'nomount'),'-fsanitize=address,undefined','-g',str(cfile),'-o',str(binary)],text=True,capture_output=True)
    (args.output/'compile.log').write_text(built.stdout+built.stderr);built.check_returncode()
    run=subprocess.run([str(binary)],text=True,capture_output=True);(args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'Developer host native call contracts; not filesystem or concurrency proof','sources':{name:sha(root/name) for name in files},'tool_sha256':sha(Path(__file__)),
             'reference_sha256':sha(args.reference),'ops_reference_sha256':sha(args.ops_reference),'file_reference_sha256':sha(args.file_reference),'symbols_sha256':sha(args.symbols),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__ == '__main__':
    main()
