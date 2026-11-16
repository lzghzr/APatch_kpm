#!/usr/bin/env python3
"""v2.3 selective port: production mutation/superblock/opaque callbacks under ASan/UBSan."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(r'(?m)^static [^\n]*\b' + name + r'\([^;]*?\)\s*\{', source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


PRE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32; typedef uint64_t u64;
#define kfunc(x) kf_##x
struct nm_directory_node {int value;};
struct nm_inode_info {u32 flags;struct nm_directory_node*dir_node;};
struct inode {bool virtual;struct nm_inode_info*info;};
struct dentry {struct inode*inode;};
struct nm_path {void*mnt;struct dentry*dentry;};
struct file {struct inode*inode;struct nm_path path;int64_t pos;};
struct nm_dir_context {int64_t pos;};
struct super_block;
struct nm_filesystem_type_head {const char*name;};
struct nm_super_head {void*list_next,*list_prev;u32 s_dev;uint8_t s_blocksize_bits;unsigned long s_blocksize;
 int64_t s_maxbytes;void*s_type;const void*s_op,*s_dq_op,*s_qcop,*s_export_op;unsigned long s_flags,s_iflags,s_magic;};
struct nm_super_proxy {const void*original;unsigned char table[];};
struct struct_offset {unsigned super_ops_size;int sop_drop_inode,sop_evict_inode;};
static struct struct_offset struct_offset={32,0,8};
static struct {void*inode_ops;int(*iterate_backing)(struct file*,struct nm_dir_context*,struct nm_directory_node*);
 int64_t(*seek_backing)(struct file*,int64_t,int);} nm_inode_engine={(void*)1};
static struct inode*nm_dentry_inode(struct dentry*d){return d->inode;}
static bool nm_is_virtual_inode(struct inode*i){assert(i);return i->virtual;}
static bool nm_is_directory_inode(struct inode*i){return i&&i->virtual;}
static void*nm_inode_private(struct inode*i){return i->info;}
static struct inode*nm_file_inode(struct file*f){return f->inode;}
static struct nm_path*nm_file_path(struct file*f){return &f->path;}
static int64_t*nm_file_position(struct file*f){return &f->pos;}
static bool blocked;static u32 nm_current_fsuid(void){return 10001;}
static bool nomount_is_uid_blocked(u32 uid){assert(uid==10001);return blocked;}
static bool nm_current_compat(void){return false;}
static bool nm_virtual_position(int64_t pos,bool compat){return pos>=100;}
static unsigned emitted,backing_calls,seek_calls;
static int nm_emit_children(struct nm_directory_node*n,struct nm_dir_context*c,u32 uid,bool compat){assert(n);emitted++;c->pos=100;return 0;}
static int nm_dir_emit(struct nm_dir_context*c,const char*n,int len,int64_t off,u64 ino,unsigned type){return 0;}
static u64 nm_inode_number(struct inode*i){return 1;}
static struct dentry*kf_nm_dget_parent(struct dentry*d){return d;}
static void kf_nm_dput(struct dentry*d){}
static int64_t kf_nm_vfs_setpos(struct file*f,int64_t off,int64_t max){return f->pos=off;}
static int64_t kf_nm_generic_file_llseek(struct file*f,int64_t off,int whence){return f->pos=off;}
static int backing_iterate(struct file*f,struct nm_dir_context*c,struct nm_directory_node*n){
 backing_calls++;if(nm_virtual_position(c->pos,false)&&blocked)return 0;c->pos=7;return 0;}
static int64_t backing_seek(struct file*f,int64_t off,int whence){seek_calls++;return f->pos=off;}
#define NM_FLAG_VIRTUAL_DIR 2
#define NM_FLAG_OPAQUE 8
static bool nm_xattr_resident;
typedef int hook_err_t;
typedef struct {bool skip_origin;uint64_t ret,arg0,arg1,arg2,arg3,arg4;} hook_fargs5_t;
typedef hook_fargs5_t hook_fargs2_t;typedef hook_fargs5_t hook_fargs3_t;
static int btf_rc,missing,fail_hook,hook_calls;static bool btf_missing;
static int calculate_btf_mutation(bool*u){*u=btf_missing;return btf_rc;}
static void*kallsyms_lookup_name_by_suffix(const char*n){
 const char*names[]={"security_inode_unlink","security_inode_rmdir","security_inode_link","security_inode_rename"};
 for(int i=0;i<4;i++)if(!strcmp(n,names[i]))return missing==i+1?NULL:(void*)(uintptr_t)(i+1);assert(0);return NULL;}
static int hook_wrap(void*t,unsigned n,void*before,void*after,void*data){
 unsigned count[]={2,2,3,5};assert(n==count[(uintptr_t)t-1]&&before&&!after&&!data);hook_calls++;
 return (uintptr_t)t==(unsigned)fail_hook?1:0;}
static unsigned allocations,published;static void*last_alloc;
static const void* fixture_kernfs_sops;
static void* fixture_other_sops[4];
static unsigned long kallsyms_lookup_name(const char* name) {
 assert(!strcmp(name,"kernfs_sops"));return (uintptr_t)fixture_kernfs_sops;
}
#define nm_log_error(...) fprintf(stderr,__VA_ARGS__)

static int nm_validate_inode_offsets(struct struct_offset*o){return 0;}
static const void*nm_super_ops(struct super_block*s){return ((struct nm_super_head*)s)->s_op;}
static void*nm_super_proxy(const void*t){return NULL;}
static void*nm_zalloc(size_t n){allocations++;return last_alloc=calloc(1,n);}
static void nm_free(void*p){free(p);}
static void nm_proxy_drop_inode(void){}
static void nm_proxy_evict_inode(void){}
static void nm_set_operation_callback(void*t,int off,void*cb){memcpy((char*)t+off,&cb,sizeof(cb));}
static bool nm_publish_super_ops(struct super_block*s,const void**old,void*t){
 assert(nm_super_ops(s)==*old);published++;((struct nm_super_head*)s)->s_op=t;return true;}
'''
TEST = r'''
int main(void){
 struct inode real={0},virtual={.virtual=true};struct dentry native={&real},fake={&virtual},negative={0};
 hook_fargs5_t a={.arg0=(uintptr_t)&real,.arg1=(uintptr_t)&native,.arg2=(uintptr_t)&real,.arg3=(uintptr_t)&negative,.arg4=2};
 hook_fargs5_t copy=a;nm_mutation_rename(&a,NULL);assert(!memcmp(&a,&copy,sizeof(a)));
 // Exchange into a virtual target, native source into virtual parent, virtual source out.
 a.arg3=(uintptr_t)&fake;nm_mutation_rename(&a,NULL);assert(a.skip_origin&&(long)a.ret==-EPERM);
 a=copy;a.arg2=(uintptr_t)&virtual;nm_mutation_rename(&a,NULL);assert(a.skip_origin&&(long)a.ret==-EPERM);
 a=copy;a.arg1=(uintptr_t)&fake;nm_mutation_rename(&a,NULL);assert(a.skip_origin&&(long)a.ret==-EPERM);
 a=copy;a.skip_origin=true;a.ret=(uint64_t)(long)-EACCES;nm_mutation_rename(&a,NULL);assert((long)a.ret==-EACCES);
 a=copy;a.arg3=(uintptr_t)&fake;a.skip_origin=true;a.ret=(uint32_t)-EACCES;nm_mutation_rename(&a,NULL);assert(a.ret==(uint32_t)-EACCES);
 a=copy;nm_mutation_remove(&a,NULL);assert(!memcmp(&a,&copy,sizeof(a)));
 a.arg1=(uintptr_t)&fake;nm_mutation_remove(&a,NULL);assert(a.skip_origin&&(long)a.ret==-EPERM);
 a=(hook_fargs5_t){.arg0=(uintptr_t)&native,.arg1=(uintptr_t)&real,.arg2=(uintptr_t)&negative};copy=a;
 nm_mutation_link(&a,NULL);assert(!memcmp(&a,&copy,sizeof(a)));
 a.arg0=(uintptr_t)&fake;nm_mutation_link(&a,NULL);assert(a.skip_origin&&(long)a.ret==-EPERM);
 // Previously cached virtual name resolved to a native dentry: no name-based refusal.
 a=copy;nm_mutation_link(&a,NULL);assert(!memcmp(&a,&copy,sizeof(a)));
 assert(nm_activate_mutation_guards_locked()==-ENODEV&&!hook_calls);
 nm_xattr_resident=true;btf_rc=-EINVAL;assert(nm_activate_mutation_guards_locked()==-EINVAL&&!hook_calls);
 btf_rc=-ENODATA;btf_missing=false;assert(nm_activate_mutation_guards_locked()==-ENODATA&&!hook_calls);
 btf_missing=true;missing=4;assert(nm_activate_mutation_guards_locked()==-ENOENT&&!hook_calls);
 missing=0;fail_hook=3;assert(nm_activate_mutation_guards_locked()==-EINVAL&&hook_calls==3&&!nm_mutation_ready);
 assert(nm_mutation_installed[0]&&nm_mutation_installed[1]&&!nm_mutation_installed[2]);
 fail_hook=0;assert(!nm_activate_mutation_guards_locked()&&hook_calls==5&&nm_mutation_ready);
 assert(!nm_activate_mutation_guards_locked()&&hook_calls==5);
 puts("mutation: native passthrough, exchange, virtual parent, hardlink, errno, partial activation PASS");
 const char*names[]={"sysfs","cgroup","cgroup2","ext4","f2fs","tmpfs"};void*ops[4]={0};
 for(unsigned i=0;i<6;i++){
  struct nm_filesystem_type_head type={names[i]};struct nm_super_head sb={.s_type=&type,.s_op=ops};
  unsigned prior=allocations;
  // Model the native operation-table identity independently of the guard.
  fixture_kernfs_sops=i<3 ? (void*)ops : (void*)fixture_other_sops;
  int rc=nm_install_super_proxy((void*)&sb);
  if(i<3)assert(rc==-EOPNOTSUPP&&sb.s_op==ops&&allocations==prior);
  else{assert(!rc&&sb.s_op!=ops&&allocations==prior+1);free(last_alloc);}
 }
 assert(published==3);puts("kernfs: targeted refusal before allocation/publication; ext4/f2fs/tmpfs passthrough PASS");
 struct nm_directory_node node={0};struct nm_inode_info info={.flags=NM_FLAG_OPAQUE,.dir_node=&node};
 virtual.info=&info;struct file f={.inode=&virtual,.path={.dentry=&fake}};struct nm_dir_context ctx={0};
 nm_inode_engine.iterate_backing=backing_iterate;nm_inode_engine.seek_backing=backing_seek;
 assert(!nm_virtual_directory_iterate(&f,&ctx)&&emitted==1&&!backing_calls&&ctx.pos==100);
 blocked=true;assert(!nm_virtual_directory_iterate(&f,&ctx)&&ctx.pos==100&&emitted==1);
 assert(!nm_virtual_directory_llseek(&f,0,0)&&seek_calls==1);
 ctx.pos=0;assert(!nm_virtual_directory_iterate(&f,&ctx)&&ctx.pos==7&&emitted==1);
 info.flags=NM_FLAG_VIRTUAL_DIR;ctx.pos=0;unsigned prior=backing_calls;
 assert(!nm_virtual_directory_iterate(&f,&ctx)&&backing_calls==prior&&emitted==1);
 info.flags=0;blocked=false;ctx.pos=0;
 assert(!nm_virtual_directory_iterate(&f,&ctx)&&backing_calls==prior+1);
 puts("opaque: active view, excluded FD/rewind/virtual cookie, pure directory and merged view PASS");
 return 0;
}
'''


def compile_run(source, out, arguments=()):
    out.with_suffix('.c').write_text(source)
    for command, suffix in [(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                             '-fsanitize=address,undefined', '-g', str(out.with_suffix('.c')), '-o', str(out)], '.compile.log'),
                            ([str(out.resolve()), *map(str, arguments)], '.run.log')]:
        result = subprocess.run(command, text=True, capture_output=True)
        out.with_suffix(suffix).write_text(result.stdout + result.stderr)
        result.check_returncode()
        if suffix == '.run.log':
            print(result.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--btf-harness', type=Path, help='test_612_btf.py generated production-query harness')
    p.add_argument('--btf-data', type=Path)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = PRE + (ROOT / 'nomount/nm_mutation.c').read_text()
    for name in ('nm_check_super_identity', 'nm_install_super_proxy'):
        source += function('nomount/nm_inode.c', name)
    for name in ('nm_directory_uses_backing', 'nm_virtual_directory_llseek', 'nm_virtual_directory_iterate'):
        source += function('nomount/nm_virtual_directory.c', name)
    compile_run(source + TEST, args.output / 'callbacks')
    cli = args.output.resolve() / 'nm-stub'
    cli.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$OUT/commands"\n'
                   'test "$*" = "rule list" || exit 99\n'
                   'test "$MODE" != query_error || exit 7\nprintf "first\\nsecond\\n"\n')
    cli.chmod(0o755)
    for mode, expected in (('ready', 0), ('query_error', 7), ('log_error', 1)):
        out = args.output.resolve() / mode
        out.mkdir()
        command = '. "$1"; NM_BIN="$2"; log() { [ "$MODE" != log_error ]; }; nm_dump_rules fixture'
        result = subprocess.run(['sh', '-c', command, 'fixture', str(ROOT / 'nomount/module/common.sh'), str(cli)],
                                env=dict(os.environ, OUT=str(out), MODE=mode), text=True, capture_output=True)
        (out / 'run.log').write_text(result.stdout + result.stderr)
        assert result.returncode == expected
        assert (out / 'commands').read_text() == 'rule list\n'
    print('rule dump: successful query, query failure and log failure are read-only PASS')
    if args.btf_harness:
        assert args.btf_data
        source = args.btf_harness.read_text()
        marker = ' reject_changed_btf();puts("OFFSETS");'
        assert source.count(marker) == 1
        extra = r'''
 assert(!calculate_btf_mutation(&unavailable)&&!unavailable);
 const struct btf_type*fn=host_type(&object,host_find(&object,"security_inode_rename",12));assert(fn);
 struct btf_type*proto=(void*)host_type(&object,fn->size);assert(proto);
 struct btf_param*params=(void*)(proto+1);u32 saved=params[0].type;
 params[0].type=params[1].type; // same pointer width, wrong object identity.
 assert(calculate_btf_mutation(&unavailable)==-EOPNOTSUPP&&!unavailable);
 params[0].type=saved;
 u32 info=proto->info;proto->info--;assert(calculate_btf_mutation(&unavailable)==-EOPNOTSUPP);
 proto->info=info;assert(!calculate_btf_mutation(&unavailable));
 struct btf_member*m=selected_member("file_system_type","name");saved=m->offset;m->offset+=64;
 assert(calculate_btf_inode_offsets(&unavailable)==-EINVAL);m->offset=saved;
 assert(!calculate_btf_inode_offsets(&unavailable));
 puts("target BTF: mutation ABI/named objects and filesystem identity positive/negative PASS");
'''
        revised = source.replace(marker, extra + marker)
        # Every pre-existing assertion remains in the generated extension, in order.
        original_asserts = re.findall(r'\bassert\s*\([^;]+\);', source)
        cursor = 0
        for expression in original_asserts:
            cursor = revised.index(expression, cursor) + len(expression)
        compile_run(revised, args.output / 'btf', [args.btf_data.resolve()])


if __name__ == '__main__':
    main()
