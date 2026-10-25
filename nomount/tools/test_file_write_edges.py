#!/usr/bin/env python3
"""保留 M2-0 的 1344 处断言，追加 M1 零写/负游标/只读 fsync/同步重入自检。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
TEST = r'''
#include <pthread.h>
/* 原生回调模型：真正调用宿主 pwrite，errno 按内核负错误码约定转交。 */
static long me_write(struct kiocb*r,struct iov_iter*it){
 struct nm_kiocb_head*q=(void*)r;
 if(q->ki_filp!=mw_backing||q->ki_complete)return -EFAULT;
 if(!it->count)return 0;
 ssize_t n=pwrite(mw_fd,it->data,it->count,q->ki_pos);
 if(n<0)return -errno;
 q->ki_pos+=n;it->data+=n;it->count-=n;return n;
}
struct me_thread {unsigned index;int error;};
static void*me_worker(void*arg){
 struct me_thread*t=arg;char bytes[16];memset(bytes,'A'+t->index,sizeof(bytes));
 for(unsigned j=0;j<64;j++){
  int64_t pos=(t->index*64+j)*sizeof(bytes);
  struct nm_kiocb_head q={mw_file,pos,NULL};struct iov_iter it={bytes,sizeof(bytes)};
  long rc=nm_write_iter((void*)&q,&it);
  if(rc!=sizeof(bytes)||q.ki_filp!=mw_file||q.ki_pos!=pos+sizeof(bytes)||it.count)t->error=1;
 }
 return NULL;
}
static void check_m1_edges(void){
 nm_discard_directory_view();target();directory_target();missing=NULL;fail_alloc=0;
 nm_backing_open_permission=NULL;nm_backing_write_open_permission=NULL;
 assert(!nm_prepare_inode_engine()&&!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine()&&!nm_prepare_backing_inode_engine());
 char name[]="/tmp/nomount-m1-edges-XXXXXX";mw_fd=mkstemp(name);assert(mw_fd>=0);mw_seed("abcdef");
 mw_path=(struct nm_path){(void*)0x1234,mw_dentry};mw_info=(struct nm_inode_info){.r_path=mw_path,.initialized=true};
 ((struct nm_dentry_head*)mw_dentry)->d_inode=(void*)mw_source_inode;nm_set_inode_private(mw_inode,&mw_info);
 ((struct nm_file_inode_ops*)(mw_source_file+struct_offset.file_inode_ops))->f_op=mw_ops;
 *(const void**)(mw_outer+struct_offset.file_cred)=(void*)0x1234;
 ((struct nm_file_io_ops*)mw_ops)->write_iter=me_write;
 nm_set_fop(mw_ops,struct_offset.fop_release+offsetof(struct nm_file_sync_ops,fsync),mw_native_sync);
 kf_nm_dentry_open=mw_source_open;kf_nm_fput=mw_put;struct_offset.permission_abi=0;kf_nm_inode_permission2=mw_permission;
 mw_open_error=mw_dac_error=mw_sync_error=0;mw_outer_ro=false;
 assert(!mw_vfs_open(02U));
 struct nm_kiocb_head q={mw_file,3,NULL};struct iov_iter it={"",0};
 assert(!nm_write_iter((void*)&q,&it)&&q.ki_filp==mw_file&&q.ki_pos==3&&!it.count);
 mw_contents(mw_fd,"abcdef");
 q.ki_pos=-1;it=(struct iov_iter){"BAD",3};const char*start=it.data;
 assert(nm_write_iter((void*)&q,&it)==-EINVAL&&q.ki_filp==mw_file&&q.ki_pos==-1&&it.count==3&&it.data==start);
 mw_contents(mw_fd,"abcdef");
 /* 四线程共享同一只读的 outer/private_data 绑定，各自独立 kiocb、迭代器与不重叠偏移。 */
 pthread_t threads[4];struct me_thread contexts[4]={0};
 for(unsigned i=0;i<4;i++){contexts[i].index=i;assert(!pthread_create(&threads[i],NULL,me_worker,&contexts[i]));}
 for(unsigned i=0;i<4;i++){assert(!pthread_join(threads[i],NULL));assert(!contexts[i].error);}
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<64;j++){
  char got[16],expected[16];memset(expected,'A'+i,sizeof(expected));
  assert(pread(mw_fd,got,sizeof(got),(i*64+j)*sizeof(got))==sizeof(got)&&!memcmp(got,expected,sizeof(got)));
 }
 assert(nm_file_private(mw_file)==mw_backing);
 assert(!nm_release((void*)mw_inode,mw_file));
 /* 宿主源 FD 也实际重开为 O_RDONLY；不是仅修改模型中的 f_flags。 */
 assert(!close(mw_fd));mw_fd=open(name,O_RDONLY);assert(mw_fd>=0);
 assert(!mw_vfs_open(0U)&&nm_file_private(mw_file)==mw_backing&&!(nm_file_flags(mw_backing)&03U));
 unsigned syncs=mw_syncs;
 assert(!nm_fsync(mw_file,0,0x7fffffffffffffffLL,0)&&mw_syncs==syncs+1);
 assert(!nm_release((void*)mw_inode,mw_file));
 assert(!close(mw_fd)&&!unlink(name));
 nm_backing_write_open_permission=NULL;nm_backing_open_permission=NULL;nm_discard_directory_view();
 puts("M1 edges: zero write, negative position, host read-only fsync, 4 x 64 independent-request writes PASS; not kernel race or power-loss proof");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for abi in ('int', 'bool'):
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1344
        for name in ('nm_open', 'nm_write_iter', 'nm_fsync', 'nm_release'):
            assert function(original, name) == function((ROOT / 'nomount/nm_file.c').read_text(), name), name
        entry = 'int main(void){assert(!previous_m2_main());m2_check_open_contract();m2_check_refusal();m2_check_native_transform();return 0;}'
        assert original.count(entry) == 1
        source = original.replace(entry, entry.replace('int main(', 'static int previous_edges_main('), 1) + TEST
        source += '\nint main(void){assert(!previous_edges_main());check_m1_edges();return 0;}\n'
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert after[:len(before)] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn',
             '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined',
             str(out / 'contracts.c'), str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before),
                     'total_assert_sites': len(after), 'concurrent_threads': 4, 'requests_per_thread': 64, 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer Tier-3 actual callbacks with host IO/stubs; no kernel concurrency/LSM/freeze or power-loss proof', 'host': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
