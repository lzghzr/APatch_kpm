#!/usr/bin/env python3
"""编译固定原生截断控制流，反证仅在 do_truncate 换源的检查覆盖；不安装 hook。"""
import argparse
import json
from pathlib import Path
import re
from test_file_control import run


def extract(source, name):
    m = re.search(r'(?m)^(?:static )?(?:int|long)\s+' + name + r'\([^;]*?\)\s*\{', source)
    if not m:
        raise ValueError('function not found: ' + name)
    end, depth = m.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[m.start():end], [source[:m.start()].count('\n')+1, source[:end].count('\n')+1]


PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
typedef long long loff_t;
#define ATTR_SIZE 8U
#define ATTR_MTIME 32U
#define ATTR_CTIME 64U
#define ATTR_FORCE 512U
#define ATTR_FILE 8192U
#define ATTR_OPEN 32768U
#define O_LARGEFILE 0100000U
#define O_WRONLY 1
#define FMODE_WRITE 2
#define MAY_WRITE 2
#define MAX_NON_LFS 0x7fffffffLL
#define unlikely(x) (x)
#define IS_APPEND(i) ((i)->append)
#define IS_PRIVATE(i) ((i)->private_inode)
#define d_backing_inode(d) ((d)->d_inode)
struct super_block {unsigned writers;};
struct inode {unsigned i_mode;bool append,private_inode;struct super_block*i_sb;loff_t size;int locked;};
struct mnt_idmap {int unused;};
struct vfsmount {bool ro;int writers;struct mnt_idmap idmap;};
struct dentry {struct inode*d_inode;};
struct path {struct vfsmount*mnt;struct dentry*dentry;};
struct file {struct path f_path;unsigned f_flags,f_mode;};
struct fd {struct file*file;};
struct iattr {loff_t ia_size;unsigned ia_valid;struct file*ia_file;};
static struct super_block osb,ssb;
static struct inode oi,si;
static struct dentry od,sd;
static struct vfsmount om,sm;
static struct file of,sf;
static bool redirect;
static int source_security_error,source_lock_error,source_permission_error;
static unsigned source_security_calls,outer_security_calls,source_lock_checks,notifications,killpriv_calls;
static struct file*seen_file;static struct inode*seen_lock;static unsigned seen_flags;
static struct inode*file_inode(struct file*f){return f->f_path.dentry->d_inode;}
static struct fd fdget(unsigned fd){return(struct fd){fd==0?&of:fd==1?&sf:NULL};}
static void fdput(struct fd f){(void)f;}
static int mnt_want_write(struct vfsmount*m){if(m->ro)return -EROFS;m->writers++;return 0;}
static void mnt_drop_write(struct vfsmount*m){assert(m->writers>0);m->writers--;}
static int inode_permission2(struct vfsmount*m,struct inode*i,int mask){(void)m;(void)mask;return i==&si?source_permission_error:0;}
static int inode_permission(struct mnt_idmap*m,struct inode*i,int mask){(void)m;return inode_permission2(NULL,i,mask);}
static int get_write_access(struct inode*i){(void)i;return 0;}
static void put_write_access(struct inode*i){(void)i;}
static int break_lease(struct inode*i,int mode){(void)i;(void)mode;return 0;}
static int locks_verify_truncate(struct inode*i,struct file*f,loff_t n){(void)f;(void)n;if(i==&si){source_lock_checks++;return source_lock_error;}return 0;}
static int locks_verify_locked(struct file*f){return locks_verify_truncate(file_inode(f),f,0);}
static int path_lsm(const struct path*p){if(p->dentry==&sd){source_security_calls++;return source_security_error;}outer_security_calls++;return 0;}
#define call_int_hook(name,zero,path) path_lsm(path)
static int security_path_truncate(const struct path*);
/* v6.6 file-security 回调为可控检查桩，不声称执行其完整LSM实现。 */
static int security_file_truncate(struct file*f){return path_lsm(&f->f_path);}
static void sb_start_write(struct super_block*s){s->writers++;}
static void sb_end_write(struct super_block*s){assert(s->writers);s->writers--;}
static struct mnt_idmap*mnt_idmap(struct vfsmount*m){return &m->idmap;}
static struct mnt_idmap*file_mnt_idmap(struct file*f){return mnt_idmap(f->f_path.mnt);}
static void inode_lock(struct inode*i){assert(!i->locked);i->locked=1;seen_lock=i;}
static void inode_unlock(struct inode*i){assert(i->locked);i->locked=0;}
/* notify/缓存及killpriv效果未模拟；只记录原生helper构造的请求与锁对象。 */
static int notify_change2(struct vfsmount*m,struct dentry*d,struct iattr*a,struct inode**delegated){
 (void)m;(void)delegated;assert(d->d_inode->locked);notifications++;seen_flags=a->ia_valid;seen_file=(a->ia_valid&ATTR_FILE)?a->ia_file:NULL;d->d_inode->size=a->ia_size;return 0;
}
static int notify_change(struct mnt_idmap*m,struct dentry*d,struct iattr*a,struct inode**delegated){(void)m;return notify_change2(NULL,d,a,delegated);}
static void reset(void){
 osb=(struct super_block){0};ssb=(struct super_block){0};
 oi=(struct inode){.i_mode=S_IFREG|0644,.private_inode=true,.i_sb=&osb,.size=32};
 si=(struct inode){.i_mode=S_IFREG|0644,.i_sb=&ssb,.size=32};od=(struct dentry){&oi};sd=(struct dentry){&si};
 om=(struct vfsmount){0};sm=(struct vfsmount){0};
 of=(struct file){.f_path={&om,&od},.f_flags=O_LARGEFILE,.f_mode=FMODE_WRITE};
 sf=(struct file){.f_path={&sm,&sd},.f_flags=O_LARGEFILE,.f_mode=FMODE_WRITE};
 redirect=false;source_security_error=source_lock_error=source_permission_error=0;
 source_security_calls=outer_security_calls=source_lock_checks=notifications=killpriv_calls=0;seen_file=NULL;seen_lock=NULL;seen_flags=0;
}
static void balanced(void){assert(!oi.locked&&!si.locked&&!om.writers&&!sm.writers&&!osb.writers&&!ssb.writers);}
'''
SONY = r'''
static int dentry_needs_remove_privs(struct dentry*d){assert(d==&od||d==&sd);killpriv_calls++;return 0;}
static int do_truncate2(struct vfsmount*,struct dentry*,loff_t,unsigned,struct file*);
'''
MODERN = r'''
static int dentry_needs_remove_privs(struct mnt_idmap*m,struct dentry*d){assert(m&& (d==&od||d==&sd));killpriv_calls++;return 0;}
static int do_truncate(struct mnt_idmap*,struct dentry*,loff_t,unsigned,struct file*);
'''
TEST = r'''
int main(void){
 /* 完整native FD前端会拒绝源LSM；late改绑只换对象，不会补跑安全检查。 */
 reset();source_security_error=-EACCES;
 assert(do_sys_ftruncate(1,8,0)==-EACCES&&source_security_calls==1&&!notifications&&si.size==32);balanced();
 reset();source_security_error=-EACCES;redirect=true;
 assert(!do_sys_ftruncate(0,8,0)&&!source_security_calls&&notifications==1&&si.size==8&&oi.size==32);CHECK_PRIVATE
 assert(seen_file==&sf&&seen_lock==&si&&(seen_flags&(ATTR_SIZE|ATTR_FILE))==(ATTR_SIZE|ATTR_FILE)&&killpriv_calls==1);balanced();
 reset();si.append=true;
 assert(do_sys_ftruncate(1,8,0)==-EPERM&&!notifications&&si.size==32);balanced();
 reset();si.append=true;redirect=true;
 assert(!do_sys_ftruncate(0,8,0)&&notifications==1&&si.size==8);balanced();
 /* O_TRUNC调用边界：get_write_access、安全检查在低层helper之前。 */
 reset();source_security_error=-EACCES;
 assert(CALL_HANDLE_SOURCE==-EACCES&&!notifications&&si.size==32);balanced();
 reset();source_security_error=-EACCES;redirect=true;
 assert(!CALL_HANDLE_OUTER&&!source_security_calls&&notifications==1&&si.size==0&&seen_file==&sf);balanced();
 /* 早path改绑检查源权限，但不会自动保留outer ro门。 */
 reset();om.ro=true;
 assert(vfs_truncate(&of.f_path,8)==-EROFS&&!notifications);balanced();
 assert(!vfs_truncate(&sf.f_path,8)&&si.size==8&&oi.size==32);balanced();
 reset();source_permission_error=-EACCES;
 assert(vfs_truncate(&sf.f_path,8)==-EACCES&&!notifications&&si.size==32);balanced();
 reset();
 assert(CALL_NEGATIVE==-EINVAL&&!notifications&&!killpriv_calls);balanced();
 CHECK_OLD_LOCKS
 puts("native entry control flow: FD/O_TRUNC late-rebind counterexamples and path outer-ro counterexample PASS; not installed code or filesystem effects");return 0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sony-open', type=Path, required=True)
    p.add_argument('--sony-namei', type=Path, required=True)
    p.add_argument('--sony-security', type=Path, required=True)
    p.add_argument('--modern-open', type=Path, required=True)
    p.add_argument('--modern-namei', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for variant, open_path, namei_path, helper in (
        ('sony', a.sony_open, a.sony_namei, 'do_truncate2'),
        ('v6.6', a.modern_open, a.modern_namei, 'do_truncate')):
        opening, namei = open_path.read_text(), namei_path.read_text()
        native, references = [], {}
        for name in (helper, 'vfs_truncate', 'do_sys_ftruncate'):
            body, span = extract(opening, name)
            references[name] = span
            # 仅低层helper定义改名，供下面显式的“候选hook模型”调用。
            if name == helper:
                body = body.replace(name + '(', 'native_low(', 1)
            native.append(body)
        handle, references['handle_truncate'] = extract(namei, 'handle_truncate')
        if variant == 'sony':
            security, references['security_path_truncate'] = extract(a.sony_security.read_text(), 'security_path_truncate')
            wrapper = '''static int do_truncate2(struct vfsmount*m,struct dentry*d,loff_t n,unsigned flags,struct file*f){
 if(redirect&&d==&od){m=&sm;d=&sd;if(f)f=&sf;}return native_low(m,d,n,flags,f);}
'''
            test = TEST.replace('CALL_HANDLE_SOURCE', 'handle_truncate(&sf)').replace('CALL_HANDLE_OUTER', 'handle_truncate(&of)').replace('CALL_NEGATIVE', 'do_truncate2(&sm,&sd,-1,0,&sf)')
            test = test.replace('CHECK_PRIVATE', 'assert(!outer_security_calls);').replace('CHECK_OLD_LOCKS', '''reset();source_lock_error=-EAGAIN;
 assert(do_sys_ftruncate(1,8,0)==-EAGAIN&&source_lock_checks==1&&!notifications);balanced();
 reset();source_lock_error=-EAGAIN;redirect=true;
 assert(!do_sys_ftruncate(0,8,0)&&!source_lock_checks&&si.size==8);balanced();''')
            prefix = SONY
        else:
            security = 'static int security_path_truncate(const struct path*p){return path_lsm(p);}'
            wrapper = '''static int do_truncate(struct mnt_idmap*m,struct dentry*d,loff_t n,unsigned flags,struct file*f){
 if(redirect&&d==&od){m=mnt_idmap(&sm);d=&sd;if(f)f=&sf;}return native_low(m,d,n,flags,f);}
'''
            test = TEST.replace('CALL_HANDLE_SOURCE', 'handle_truncate(mnt_idmap(&sm),&sf)').replace('CALL_HANDLE_OUTER', 'handle_truncate(mnt_idmap(&om),&of)').replace('CALL_NEGATIVE', 'do_truncate(mnt_idmap(&sm),&sd,-1,0,&sf)').replace('CHECK_OLD_LOCKS', '').replace('CHECK_PRIVATE', '')
            prefix = MODERN
        source = PREFIX + prefix + security + '\n' + native[0] + '\n' + wrapper + '\n' + '\n'.join(native[1:]) + '\n' + handle + '\n' + test
        out = a.output / variant
        out.mkdir()
        (out / 'native.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(out / 'native.c'), '-o', str(out / 'native')], out / 'compile.log')
        run([str((out / 'native').resolve())], out / 'run.log')
        rows.append({'source': variant, 'native_function_line_ranges': references,
                     'assert_sites': len(re.findall(r'\bassert\s*\([^;]+\);', source)), 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer Tier-3 original native function bodies + host locks/security/notify stubs and intentionally incomplete rebind; proves control-flow omission, not production vulnerability or native truncate/cache correctness', 'sources': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
