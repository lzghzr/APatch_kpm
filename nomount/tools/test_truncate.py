#!/usr/bin/env python3
"""M2当前宿主入口：按b642950迁移4处旧期望，保留其余1379条并追加自然边界链。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run
import test_setattr
import test_file_write
import test_truncate_boundary

ROOT = Path(__file__).resolve().parents[2]
TEST = r'''
#include <sys/mman.h>
#include <sys/stat.h>
/* 本结构仅为宿主原生桩的载荷，生产只访问已确认的ia_valid头部。 */
struct tm_attr {struct nm_iattr_head head;int64_t size;struct file*file;};
static int tm_fd,tm_error,tm_after_error,tm_dac_error;
static unsigned tm_opens,tm_puts,tm_flags,tm_mask,tm_syncs;
static int64_t tm_open_size;
static bool tm_outer_ro;
static struct tm_attr*tm_expected_attr;
static _Alignas(16)unsigned char tm_storage[1024],tm_ops[512];
static struct file*tm_file=(void*)tm_storage;
static int tm_permission(struct vfsmount*m,struct inode*i,int mask){assert((void*)m==backing_path.mnt&&i==backing);tm_mask=mask;return tm_dac_error;}
static int tm_permission_plain(struct inode*i,int mask){return tm_permission((void*)backing_path.mnt,i,mask);}
static int tm_permission_context(void*c,struct inode*i,int mask){assert(c==sa_expected_context);return tm_permission((void*)backing_path.mnt,i,mask);}
static struct file*tm_source_open(const struct nm_path*p,int flags,const struct cred*c){
 assert(p->mnt==backing_path.mnt&&p->dentry==backing_path.dentry&&c==(void*)0x1234);tm_opens++;tm_flags=flags;
 struct stat st;assert(!fstat(tm_fd,&st));tm_open_size=st.st_size;
 if((flags&03U)&&sa_ro)return ERR_PTR(-EROFS);
 ((struct nm_file_flags_mode*)(mw_source_file+struct_offset.file_flags))->f_flags=flags&~01000U;
 return mw_backing;
}
static void tm_put(struct file*f){assert(f==mw_backing&&!nm_file_private(tm_file));tm_puts++;}
static int tm_notify(struct dentry*d,void*arg,struct inode**delegated){
 assert(d==(void*)backing_path.dentry&&arg==tm_expected_attr&&!delegated&&sa_locks>sa_unlocks);sa_notify_calls++;
 struct tm_attr*a=arg;assert(a->head.ia_valid&ATTR_SIZE);
 if(a->head.ia_valid&ATTR_FILE)assert(a->file==tm_file&&nm_file_private(a->file)==mw_backing);
 if(tm_error)return tm_error;
 if(ftruncate(tm_fd,a->size))return -errno;
 struct stat st;assert(!fstat(tm_fd,&st));
 ((struct nm_inode_size_times*)((uintptr_t)backing+struct_offset.inode_size))->i_size=st.st_size;
 return tm_after_error;
}
static int tm_notify_mapped(void*c,struct dentry*d,void*a,struct inode**delegated){assert(c==sa_expected_context);return tm_notify(d,a,delegated);}
static void tm_ready(int shape,struct nm_mount_context_head*m){
 sn_ready(shape,m);nm_notify_plain=tm_notify;nm_notify_context=tm_notify_mapped;
 nm_inode_permission_plain=tm_permission_plain;nm_inode_permission_userns=(void*)tm_permission_context;nm_inode_permission_idmap=(void*)tm_permission_context;kf_nm_inode_permission2=tm_permission;
 tm_error=tm_after_error=tm_dac_error=0;tm_mask=0;
}
static int tm_set(int shape,struct tm_attr*a){tm_expected_attr=a;return sn_call(shape,(void*)outer_root,a);}
/* VFS入口桩保留outer ro；生产不复制下面的调用链或原生检查。 */
static int tm_path_truncate(int shape,int64_t size){
 if(size<0)return -EINVAL;if(tm_outer_ro)return -EROFS;
 struct tm_attr a={{ATTR_SIZE},size,NULL};return tm_set(shape,&a);
}
static int tm_ftruncate(int shape,int64_t size){
 if(size<0)return -EINVAL;if(!(nm_file_flags(tm_file)&03U))return -EINVAL;
 struct tm_attr a={{ATTR_SIZE|ATTR_FILE|ATTR_MTIME|ATTR_CTIME},size,tm_file};return tm_set(shape,&a);
}
static int tm_open_path(int shape,unsigned flags){
 if(tm_outer_ro&&(flags&01003U))return -EROFS;
 ((struct nm_file_flags_mode*)(tm_storage+struct_offset.file_flags))->f_flags=flags;
 int rc=nm_open(nm_dentry_inode(outer_root),tm_file);if(rc)return rc;
 ((struct nm_file_flags_mode*)(tm_storage+struct_offset.file_flags))->f_flags&=~01000U;
 if(flags&01000U){
  struct tm_attr a={{ATTR_SIZE|ATTR_FILE|ATTR_OPEN|ATTR_MTIME|ATTR_CTIME},0,tm_file};rc=tm_set(shape,&a);
  if(rc)nm_release(nm_dentry_inode(outer_root),tm_file);
 }
 return rc;
}
static int tm_sync(struct file*f,long long start,long long end,int datasync){assert(f==mw_backing&&start==0&&end==0x7fffffffffffffffLL&&!datasync);tm_syncs++;return fsync(tm_fd)?-errno:0;}
static long tm_read(struct kiocb*r,struct iov_iter*it){struct nm_kiocb_head*q=(void*)r;assert(q->ki_filp==mw_backing);long n=pread(tm_fd,(void*)it->data,it->count,q->ki_pos);if(n>0)q->ki_pos+=n;return n<0?-errno:n;}
static void tm_seed(struct inode*outer,const char*s){assert(!ftruncate(tm_fd,0)&&pwrite(tm_fd,s,strlen(s),0)==strlen(s));
 *(int64_t*)((uintptr_t)backing+struct_offset.inode_size)=strlen(s);*(int64_t*)((uintptr_t)outer+struct_offset.inode_size)=strlen(s);}
static void check_truncate(void){
 security_fixture_reset();security_target();struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,907));
 security_query(outer_again);assert(!nm_materialize_file(parent,(void*)outer_again,&rule,908));
 struct inode*outer=nm_dentry_inode(outer_root),*alias=nm_dentry_inode(outer_again);struct nm_inode_info*info=nm_inode_private(outer);
 assert(outer&&alias&&outer!=alias&&info&&nm_inode_objects(outer)->i_mapping==nm_inode_objects(backing)->i_mapping);
 int64_t alias_snapshot=nm_inode_size(alias);
 struct nm_mount_context_head mount={.context.userns=(void*)0x8765};void*saved_mnt=backing_path.mnt;
 backing_path.mnt=&mount;info->r_path.mnt=&mount;
 char name[]="/tmp/nomount-m2-XXXXXX";tm_fd=mkstemp(name);assert(tm_fd>=0);
 *(const void**)(tm_storage+struct_offset.file_cred)=(void*)0x1234;
 ((struct nm_file_inode_ops*)(tm_storage+struct_offset.file_inode_ops))->f_inode=outer;
 ((struct nm_file_inode_ops*)(mw_source_file+struct_offset.file_inode_ops))->f_inode=backing;
 ((struct nm_file_inode_ops*)(mw_source_file+struct_offset.file_inode_ops))->f_op=tm_ops;
 ((struct nm_file_io_ops*)tm_ops)->read_iter=tm_read;
 kf_nm_dentry_open=tm_source_open;kf_nm_fput=tm_put;
 nm_backing_write_open_permission=nm_backing_write_permission;nm_backing_open_permission=nm_backing_read_permission;
 unsigned total_opens=tm_opens;
 for(int shape=0;shape<4;shape++){
  tm_ready(shape,&mount);tm_outer_ro=false;tm_seed(outer,"abcdefghij");
  unsigned char table[512]={0};assert(!nm_install_setattr(table));
  assert(nm_operation_callback(table,nm_setattr_layout.slot)==(struct_offset.getattr_context_kind?(void*)nm_setattr_mapped:(void*)nm_setattr));
  assert(!tm_path_truncate(shape,3)&&nm_inode_size(outer)==3&&nm_inode_size(backing)==3&&sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1);
  mw_contents(tm_fd,"abc");
  tm_ready(shape,&mount);assert(!tm_path_truncate(shape,10)&&nm_inode_size(outer)==10&&nm_inode_size(backing)==10);
  char zeros[10];assert(pread(tm_fd,zeros,10,0)==10&&!memcmp(zeros,"abc\0\0\0\0\0\0\0",10));
  tm_seed(outer,"abcdefghij");tm_ready(shape,&mount);
  assert(!tm_open_path(shape,02U)&&tm_mask==(0x20|2|4)&&nm_file_private(tm_file)==mw_backing);
  void*map=mmap(NULL,4096,PROT_READ,MAP_SHARED,tm_fd,0);assert(map!=MAP_FAILED);
  tm_ready(shape,&mount);assert(!tm_ftruncate(shape,4)&&nm_inode_size(outer)==4&&nm_inode_size(backing)==4&&!memcmp(map,"abcd",4));
  char readback[8]={0};struct nm_kiocb_head q={tm_file,0,NULL};struct iov_iter it={readback,8};
  assert(nm_read_iter((void*)&q,&it)==4&&!memcmp(readback,"abcd",4)&&q.ki_filp==tm_file);
  assert(nm_inode_size(alias)==alias_snapshot); /* 其它虚拟inode仍按已裁定的独立快照语义。 */
  assert(!munmap(map,4096));
  nm_set_fop(tm_ops,struct_offset.fop_release+offsetof(struct nm_file_sync_ops,fsync),tm_sync);unsigned syncs=tm_syncs;
  assert(!nm_fsync(tm_file,0,0x7fffffffffffffffLL,0)&&tm_syncs==syncs+1);
  assert(!nm_release(outer,tm_file)&&!nm_file_private(tm_file));
  tm_ready(shape,&mount);tm_seed(outer,"abcdefghij");
  assert(!tm_open_path(shape,01U|01000U)&&tm_flags==(01U|01000U)&&tm_open_size==10&&nm_inode_size(outer)==0&&nm_inode_size(backing)==0&&sa_notify_calls==1);
  mw_contents(tm_fd,"");assert(!nm_release(outer,tm_file));
  tm_ready(shape,&mount);tm_seed(outer,"abcdefghij");
  assert(!tm_open_path(shape,01000U)&&tm_mask==(0x20|2|4)&&tm_open_size==10&&nm_inode_size(outer)==0);assert(!nm_release(outer,tm_file));
  /* 源ro、outer ro、权限/原生错误均不能靠open成功假装截断成功。 */
  tm_seed(outer,"abcdefghij");tm_ready(shape,&mount);tm_outer_ro=true;unsigned opens=tm_opens;
  assert(tm_open_path(shape,01000U)==-EROFS&&tm_opens==opens&&!nm_file_private(tm_file));
  assert(tm_path_truncate(shape,0)==-EROFS&&!sa_notify_calls);tm_outer_ro=false;
  tm_ready(shape,&mount);sa_ro=true;assert(tm_path_truncate(shape,0)==-EROFS&&!sa_notify_calls&&sa_locks==1&&sa_unlocks==1);
  assert(tm_open_path(shape,01U|01000U)==-EROFS&&!nm_file_private(tm_file));
  assert(tm_open_path(shape,01000U)==-EROFS&&!nm_file_private(tm_file));mw_contents(tm_fd,"abcdefghij");
  assert(nm_inode_size(outer)==10&&nm_inode_size(backing)==10);
  tm_ready(shape,&mount);tm_dac_error=-EACCES;opens=tm_opens;
  assert(tm_open_path(shape,01000U)==-EACCES&&tm_opens==opens&&!sa_notify_calls);
  tm_ready(shape,&mount);tm_error=-ENOSPC;assert(tm_path_truncate(shape,0)==-ENOSPC&&nm_inode_size(outer)==10&&nm_inode_size(backing)==10);mw_contents(tm_fd,"abcdefghij");
  tm_ready(shape,&mount);tm_error=-EIO;unsigned puts=tm_puts;
  assert(tm_open_path(shape,01U|01000U)==-EIO&&!nm_file_private(tm_file)&&tm_puts==puts+1);mw_contents(tm_fd,"abcdefghij");
  /* 任意MODE|SIZE，包括内生MODE|KILL；UID/GID组合与原生布局拒绝也保持。 */
  const unsigned compounds[]={1U|8U,1U|8U|16U,2U|8U,4U|8U,1U|8U|ATTR_KILL_SUID,1U|8U|ATTR_KILL_SGID};
  for(unsigned j=0;j<sizeof(compounds)/sizeof(compounds[0]);j++){
   tm_ready(shape,&mount);struct tm_attr a={{compounds[j]},0,NULL};unsigned char source[768],virtual[768];memcpy(source,backing,768);memcpy(virtual,outer,768);
   assert(tm_set(shape,&a)==-EOPNOTSUPP&&!sa_locks&&!sa_unlocks&&!sa_notify_calls);
   assert(!memcmp(source,backing,768)&&!memcmp(virtual,outer,768));
  }
  tm_ready(shape,&mount);struct tm_attr a={{ATTR_SIZE},0,NULL};nm_setattr_layout.lock_offset=-8;
  assert(tm_set(shape,&a)==-EINVAL&&!sa_locks&&!sa_notify_calls);
  tm_ready(shape,&mount);info->r_path.dentry=NULL;assert(tm_set(shape,&a)==-EOPNOTSUPP&&!sa_locks);info->r_path.dentry=backing_path.dentry;
  tm_ready(shape,&mount);if(shape==1||shape==2){sa_expected_context=(void*)0x9999;assert(tm_set(shape,&a)==-EXDEV&&!sa_locks);}
  tm_ready(shape,&mount);nm_setattr_status=-EOPNOTSUPP;assert(tm_set(shape,&a)==-EOPNOTSUPP&&!sa_locks);
  tm_ready(shape,&mount);assert(tm_path_truncate(shape,-1)==-EINVAL&&!sa_locks&&!sa_notify_calls);
  tm_ready(shape,&mount);tm_after_error=-EIO;assert(tm_path_truncate(shape,2)==-EIO&&nm_inode_size(backing)==2&&nm_inode_size(outer)==10);mw_contents(tm_fd,"ab");
 }
 assert(tm_opens>total_opens&&!nm_file_private(tm_file));
 backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;port_iput(outer);port_iput(alias);
 assert(!close(tm_fd)&&!unlink(name)&&!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 nm_setattr_status=-EOPNOTSUPP;nm_backing_write_open_permission=NULL;nm_backing_open_permission=NULL;
 puts("M2 four ABI shapes: path/FD/O_TRUNC natural-boundary model, host truncate/read/mmap/fsync, compound/ro/error/layout/idmap refusal and native partial-error boundary exercised");
}
'''


def assertions(source):
    return re.findall(r'\bassert\s*\([^;]+\);', source)


def migrate(source):
    before = assertions(source)
    # 源位置与新TEST保持同一份，不另造一套迁移后的期望。
    for test, names in ((test_setattr, ('check_setattr',)),
                        (test_file_write, ('check_file_writes', 'mw_vfs_open')),
                        (test_truncate_boundary, ('m2_check_refusal',))):
        for name in names:
            old, new = function(source, name), function(test.TEST, name)
            assert source.count(old) == 1
            source = source.replace(old, new, 1)
    after = assertions(source)
    assert len(before) == len(after) == 1379
    changes = [{'assert_index': i+1, 'before': old, 'after': new}
               for i, (old, new) in enumerate(zip(before, after)) if old != new]
    assert len(changes) == 4, changes
    expected_old = (
        'assert(nm_setattr((void*)outer_root,&attr)==-EOPNOTSUPP&&!sa_locks&&!sa_notify_calls);',
        'assert(mw_vfs_open(01U|01000U)==-EROFS&&mw_opens==opens&&!mw_mask&&!nm_file_private(mw_file));',
        'assert(sn_call(shape,(void*)outer_root,&a)==-EOPNOTSUPP);',
        'assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);')
    assert tuple(c['before'] for c in changes) == expected_old
    return source, changes


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output',type=Path,required=True)
    p.add_argument('--cli-source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
    for abi in ('int','bool'):
        original=(a.oracle_output/abi/'contracts.c').read_text();assert len(assertions(original))==1379
        source,changes=migrate(original)
        for file,names in {'nm_file.c':('nm_open',),'nm_setattr.c':('nm_setattr_context',)}.items():
            for name in names:source=source.replace(function(source,name),function((ROOT/'nomount'/file).read_text(),name),1)
        assert len(assertions(source))==1379
        entry='int main(void){assert(!previous_gates_main());check_upstream_truncate_gates();return 0;}'
        assert source.count(entry)==1
        base_asserts=assertions(source)
        source=source.replace(entry,entry.replace('int main(','static int previous_truncate_main('),1)+TEST
        source+='\nint main(void){assert(!previous_truncate_main());check_truncate();return 0;}\n'
        assert assertions(source)[:1379]==base_asserts
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        rows.append({'abi':abi,'prior_assert_sites':1379,'unchanged_assert_sites':1375,'migrated_assert_sites':4,'added_assert_sites':len(assertions(source))-1379,'total_assert_sites':len(assertions(source)),'migrations':changes,'result':'executed; pending independent Auditor review'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer ASan/UBSan actual callbacks with VFS/DAC/security/FS stubs and real host ftruncate/pread/mmap/fsync; no target kernel/CFI/LSM/freeze or power-loss proof','authorization':'b642950','host':rows},ensure_ascii=False,indent=2)+'\n');print([{k:r[k] for k in ('abi','migrated_assert_sites','added_assert_sites','total_assert_sites')}for r in rows])


if __name__=='__main__':main()
