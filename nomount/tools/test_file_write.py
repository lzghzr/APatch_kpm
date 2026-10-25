#!/usr/bin/env python3
"""保留1278处宿主断言，追加生产M1回调、VFS入口模型与宿主fsync闭环。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = {'int': '8e2aca88cbe829bfd5d24d31499e82f1fd5a3b6ae859e92654edbd4aa0b18cf5', 'bool': 'f8a8a56b54103165089fe76d57774b49ea607eb6b46a19c2efe57e093d031616'}
TEST = r'''
struct iov_iter {const char* data;size_t count;};
static _Alignas(16)unsigned char mw_outer[1024],mw_source_file[1024],mw_inode[1024],mw_source_inode[1024],mw_dentry[256],mw_ops[512];
static struct nm_inode_info mw_info;
static struct file*mw_file=(void*)mw_outer;
static struct file*mw_backing=(void*)mw_source_file;
static int mw_fd,mw_outer_fd,mw_open_error,mw_io_error,mw_sync_error,mw_mask,mw_dac_error;
static unsigned mw_opens,mw_calls,mw_syncs,mw_puts,mw_vfs_callbacks;
static size_t mw_limit;
static bool mw_outer_ro;
static struct nm_path mw_path;
static int mw_permission(struct vfsmount*m,struct inode*i,int mask){
 assert((void*)m==mw_path.mnt&&(void*)i==mw_source_inode);mw_mask=mask;return mw_dac_error;
}
static struct file*mw_source_open(const struct nm_path*p,int flags,const struct cred*cred){
 assert(p->mnt==mw_path.mnt&&p->dentry==mw_dentry&&cred==(void*)0x1234);mw_opens++;
 if(mw_open_error)return ERR_PTR(mw_open_error);
 ((struct nm_file_flags_mode*)(mw_source_file+struct_offset.file_flags))->f_flags=flags;
 return mw_backing;
}
static void mw_put(struct file*f){assert(f==mw_backing&&!nm_file_private(mw_file));mw_puts++;}
/* 源文件系统模型：真实宿主pwrite/fsync；并非目标文件系统/SELinux。 */
static long mw_native_write(struct kiocb*r,struct iov_iter*it){
 struct nm_kiocb_head*q=(void*)r;assert(q->ki_filp==mw_backing&&!q->ki_complete);mw_calls++;
 if(mw_io_error)return mw_io_error;
 size_t n=it->count<mw_limit?it->count:mw_limit;
 if(nm_file_flags(mw_backing)&02000U)q->ki_pos=lseek(mw_fd,0,SEEK_END);
 ssize_t rc=pwrite(mw_fd,it->data,n,q->ki_pos);
 assert(rc>=0);q->ki_pos+=rc;it->data+=rc;it->count-=rc;return rc;
}
static long mw_native_read(struct kiocb*r,struct iov_iter*it){
 struct nm_kiocb_head*q=(void*)r;assert(q->ki_filp==mw_backing);long n=pread(mw_fd,(void*)it->data,it->count,q->ki_pos);if(n>0)q->ki_pos+=n;return n;
}
static int mw_native_sync(struct file*f,long long start,long long end,int datasync){
 assert(f==mw_backing&&start==0&&end==0x7fffffffffffffffLL&&(datasync==0||datasync==1));mw_syncs++;
 if(mw_sync_error)return mw_sync_error;return fsync(mw_fd)?-EIO:0;
}
static int mw_vfs_open(unsigned flags){
 /* 原生do_dentry_open的外层ro门：在模块callback之前。 */
 if(mw_outer_ro&&(flags&01003U))return -EROFS;
 ((struct nm_file_flags_mode*)(mw_outer+struct_offset.file_flags))->f_flags=flags;
 mw_vfs_callbacks++;return nm_open((void*)mw_inode,mw_file);
}
static void mw_contents(int fd,const char*expected){char b[64]={0};ssize_t n=pread(fd,b,sizeof(b),0);assert(n==(ssize_t)strlen(expected)&&!memcmp(b,expected,n));}
static void mw_seed(const char*s){assert(!ftruncate(mw_fd,0));assert(pwrite(mw_fd,s,strlen(s),0)==(ssize_t)strlen(s));}
static void check_m1_failure_cleanup(void){
 cold_reset();cold_mode=1;control_register_error=-EPERM;
 assert(cold_nomount_init(NULL,"post-fs-data",NULL)==-EPERM&&!nm_backing_write_open_permission&&!nm_inode_engine.file_ops&&!nm_registered_key_type);
 control_register_error=0;target();directory_target();
 assert(!nm_prepare_inode_engine()&&!((struct nm_file_io_ops*)nm_inode_engine.file_ops)->write_iter);
 ((struct nm_file_flags_mode*)(mw_outer+struct_offset.file_flags))->f_flags=1;
 assert(nm_open(NULL,mw_file)==-EROFS&&!nm_file_private(mw_file));
 nm_discard_directory_view();puts("late register failure -> independent read-only engine -> write open refused PASS");
}
static void check_file_writes(void){
 nm_discard_directory_view();target();directory_target();missing=NULL;fail_alloc=0;
 nm_backing_open_permission=NULL;nm_backing_write_open_permission=NULL;
 assert(!nm_prepare_inode_engine()&&!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
 assert(!((struct nm_file_io_ops*)nm_inode_engine.file_ops)->write_iter);
 assert(!nm_prepare_backing_inode_engine());
 assert(((struct nm_file_io_ops*)nm_inode_engine.file_ops)->write_iter==nm_write_iter&&nm_backing_write_open_permission==nm_backing_write_permission);
 char source_name[]="/tmp/nomount-m1-source-XXXXXX",outer_name[]="/tmp/nomount-m1-outer-XXXXXX";
 mw_fd=mkstemp(source_name);mw_outer_fd=mkstemp(outer_name);assert(mw_fd>=0&&mw_outer_fd>=0);
 mw_seed("abcdef");assert(write(mw_outer_fd,"outer",5)==5);mw_limit=64;
 mw_path=(struct nm_path){(void*)0x1234,mw_dentry};mw_info=(struct nm_inode_info){.r_path=mw_path,.initialized=true};
 ((struct nm_dentry_head*)mw_dentry)->d_inode=(void*)mw_source_inode;
 nm_set_inode_private(mw_inode,&mw_info);
 ((struct nm_file_inode_ops*)(mw_outer+struct_offset.file_inode_ops))->f_inode=(void*)mw_inode;
 ((struct nm_file_inode_ops*)(mw_source_file+struct_offset.file_inode_ops))->f_inode=(void*)mw_source_inode;
 ((struct nm_file_inode_ops*)(mw_source_file+struct_offset.file_inode_ops))->f_op=mw_ops;
 *(const void**)(mw_outer+struct_offset.file_cred)=(void*)0x1234;
 ((struct nm_file_io_ops*)mw_ops)->write_iter=mw_native_write;((struct nm_file_io_ops*)mw_ops)->read_iter=mw_native_read;
 nm_set_fop(mw_ops,struct_offset.fop_release+offsetof(struct nm_file_sync_ops,fsync),mw_native_sync);
 kf_nm_dentry_open=mw_source_open;kf_nm_fput=mw_put;struct_offset.permission_abi=0;kf_nm_inode_permission2=mw_permission;
 /* 1 外层只读：模块没有机会绕过；2 源只读：原生打开错误原样透传。 */
 mw_outer_ro=true;unsigned opens=mw_opens,callbacks=mw_vfs_callbacks;
 assert(mw_vfs_open(01U)==-EROFS&&mw_opens==opens&&mw_vfs_callbacks==callbacks&&!nm_file_private(mw_file));
 mw_contents(mw_fd,"abcdef");mw_contents(mw_outer_fd,"outer");mw_outer_ro=false;
 mw_open_error=-EROFS;
 assert(mw_vfs_open(01U)==-EROFS&&mw_opens==opens+1&&!nm_file_private(mw_file));
 mw_contents(mw_fd,"abcdef");mw_contents(mw_outer_fd,"outer");
 mw_open_error=-EACCES;assert(mw_vfs_open(02U)==-EACCES&&!nm_file_private(mw_file));
 mw_open_error=-ETXTBSY;assert(mw_vfs_open(01U)==-ETXTBSY&&!nm_file_private(mw_file));mw_open_error=0;
 /* 3 O_TRUNC进入源打开；本例源拒绝，后续setattr截断由M2完整链另测。 */
 opens=mw_opens;mw_mask=0;
 mw_open_error=-EACCES;assert(mw_vfs_open(01U|01000U)==-EACCES&&mw_opens==opens+1&&mw_mask==(0x20|2)&&!nm_file_private(mw_file));mw_open_error=0;opens=mw_opens;
 mw_contents(mw_fd,"abcdef");mw_contents(mw_outer_fd,"outer");
 mw_dac_error=-EPERM;assert(mw_vfs_open(01U)==-EPERM&&mw_mask==(0x20|2)&&mw_opens==opens);mw_dac_error=0;
 assert(!mw_vfs_open(02U)&&mw_mask==(0x20|2|4)&&nm_file_private(mw_file)==mw_backing);
 assert(!nm_release((void*)mw_inode,mw_file)&&mw_puts==1&&!nm_file_private(mw_file));
 assert(!mw_vfs_open(01U)&&mw_mask==(0x20|2)&&nm_file_private(mw_file)==mw_backing);
 /* 4 短写不补写；迭代器只消费已写字节，位置与原句柄恢复。 */
 mw_limit=2;struct iov_iter it={"ABCDE",5};struct nm_kiocb_head q={mw_file,1,NULL};unsigned writes=mw_calls;
 assert(nm_write_iter((void*)&q,&it)==2&&mw_calls==writes+1&&q.ki_filp==mw_file&&q.ki_pos==3&&it.count==3);
 mw_contents(mw_fd,"aABdef");mw_contents(mw_outer_fd,"outer");
 /* 零进展错误不改源；异步必须在源callback前拒绝。 */
 mw_io_error=-EIO;it=(struct iov_iter){"BAD",3};q.ki_pos=0;
 assert(nm_write_iter((void*)&q,&it)==-EIO&&q.ki_filp==mw_file&&q.ki_pos==0&&it.count==3);
 mw_contents(mw_fd,"aABdef");mw_contents(mw_outer_fd,"outer");mw_io_error=0;
 writes=mw_calls;q.ki_complete=(void*)1;
 assert(nm_write_iter((void*)&q,&it)==-EOPNOTSUPP&&mw_calls==writes&&q.ki_filp==mw_file&&it.count==3);q.ki_complete=NULL;
 ((struct nm_file_io_ops*)mw_ops)->write_iter=NULL;
 assert(nm_write_iter((void*)&q,&it)==-EINVAL&&mw_calls==writes&&q.ki_filp==mw_file);
 ((struct nm_file_io_ops*)mw_ops)->write_iter=mw_native_write;
 /* 5 O_APPEND由源原生回调决定位置，传来的旧位置不能覆盖EOF。 */
 assert(!nm_release((void*)mw_inode,mw_file));mw_seed("abc");mw_limit=64;
 assert(!mw_vfs_open(01U|02000U)&&nm_file_flags(mw_backing)==(01U|02000U));
 q=(struct nm_kiocb_head){mw_file,0,NULL};it=(struct iov_iter){"XY",2};
 assert(nm_write_iter((void*)&q,&it)==2&&q.ki_pos==5&&q.ki_filp==mw_file&&!it.count);
 mw_contents(mw_fd,"abcXY");mw_contents(mw_outer_fd,"outer");
 /* 6 同一源句柄完成write/read/fsync；实际宿主fsync后重开文件核对内容。 */
 char got[6]={0};struct iov_iter read_it={got,5};q.ki_pos=0;
 assert(nm_read_iter((void*)&q,&read_it)==5&&!memcmp(got,"abcXY",5)&&q.ki_filp==mw_file);
 assert(!nm_fsync(mw_file,0,0x7fffffffffffffffLL,0)&&mw_syncs==1);
 assert(!nm_fsync(mw_file,0,0x7fffffffffffffffLL,1)&&mw_syncs==2);
 int verify=open(source_name,O_RDONLY);assert(verify>=0);mw_contents(verify,"abcXY");assert(!close(verify));
 mw_sync_error=-EIO;assert(nm_fsync(mw_file,0,0x7fffffffffffffffLL,0)==-EIO&&mw_syncs==3);mw_sync_error=0;
 mw_contents(mw_fd,"abcXY"); /* fsync错误不能伪称已经回滚成功写入的数据。 */
 unsigned put_count=mw_puts;assert(!nm_release((void*)mw_inode,mw_file)&&mw_puts==put_count+1&&!nm_file_private(mw_file));
 nm_backing_write_open_permission=NULL;nm_backing_open_permission=NULL;nm_discard_directory_view();
 assert(!close(mw_fd)&&!close(mw_outer_fd)&&!unlink(source_name)&&!unlink(outer_name));
 puts("M1 six cases PASS: outer ro model, source errno, O_TRUNC, short write, append, host fsync/reopen; async refusal and source DAC PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args();a.output.mkdir(parents=True, exist_ok=False)
    rows=[]
    for abi in ('int','bool'):
        original=(a.oracle_output/abi/'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest()==DIGESTS[abi]
        # 输入是已提交的xattr畸形输入里程碑；固定回执中的断言数与原表达式序列。
        before=re.findall(r'\bassert\s*\([^;]+\);',original);assert len(before)==1278
        source='#include <unistd.h>\n#include <fcntl.h>\n'+original
        for file,names in {'nm_file.c':['nm_open'], 'nm_backing_inode.c':['nm_prepare_backing_inode_engine']}.items():
            for name in names:source=source.replace(function(source,name),function((ROOT/'nomount'/file).read_text(),name),1)
        source=source.replace('static int (*nm_backing_open_permission)(const struct nm_path*);','static int (*nm_backing_open_permission)(const struct nm_path*);\nstatic int (*nm_backing_write_open_permission)(const struct nm_path*, int);',1)
        source=source.replace('static int nm_mmap(',function((ROOT/'nomount/nm_file.c').read_text(),'nm_write_iter')+'\nstatic int nm_mmap(',1)
        source=source.replace('static int nm_backing_read_permission(',function((ROOT/'nomount/nm_backing_inode.c').read_text(),'nm_backing_write_permission')+'\nstatic int nm_backing_read_permission(',1)
        source=source.replace('static int nm_prepare_backing_inode_engine(', 'static int calculate_btf_file_write(bool*u){*u=true;return -ENODATA;}\nstatic int nm_prepare_backing_inode_engine(',1)
        cold=function((ROOT/'nomount/nm_backing_inode.c').read_text(),'nm_prepare_backing_inode_engine').replace('nm_prepare_backing_inode_engine(', 'cold_nm_prepare_backing_inode_engine(',1).replace('nm_prepare_backing_inode_functions(', 'cold_nm_prepare_backing_inode_functions(')
        cold=cold.replace('{','{\n cold_note("nm_prepare_backing_inode_engine");',1)
        source=source.replace(function(source,'cold_nm_prepare_backing_inode_engine'),cold,1)
        # 失败清理新增写准入指针，旧断言仍逐条保留。
        source=source.replace('    nm_backing_open_permission = NULL;','    nm_backing_open_permission = NULL;\n    nm_backing_write_open_permission = NULL;')
        assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
        entry='int main(void){nm_xattr_writes_ready=true;assert(!previous_write_main());check_xattr_write_activation();check_xattr_writes();check_xattr_write_static();return 0;}'
        assert source.count(entry)==1
        source=source.replace(entry,entry.replace('int main(', 'static int previous_m1_main('),1)+TEST+'\nint main(void){assert(!previous_m1_main());check_file_writes();check_m1_failure_cleanup();return 0;}\n'
        after=re.findall(r'\bassert\s*\([^;]+\);',source);assert after[:len(before)]==before
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        rows.append({'abi':abi,'prior_assert_sites':len(before),'added_assert_sites':len(after)-len(before),'total_assert_sites':len(after),'result':'PASS'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer Tier-3; VFS/DAC/FS model with real host pwrite/fsync/reopen, not device or power-loss proof','host':rows},indent=2)+'\n');print(rows)

if __name__=='__main__':main()
