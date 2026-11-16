#!/usr/bin/env python3
"""执行生产 list/固定绑定/open/read；POSIX 文件支持 rename/unlink/重建实验。"""
import argparse
import json
import struct
import sys
from pathlib import Path
import re
from test_nomount_v230 import ROOT, function, compile_run

PRE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <limits.h>
typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t u16;
struct rcu_head {void*next,*func;};
struct dentry;struct nm_inode_info;
struct nm_path {void*mnt;struct dentry*dentry;};
struct inode {unsigned mode;struct nm_inode_info*info;};
struct dentry {int fd;unsigned refs;struct inode inode;char last[PATH_MAX];};
#define ERR_PTR(x) ((void*)(intptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x)>=(uintptr_t)-4095)
#define kfunc(x) kf_##x
static void*nm_zalloc(size_t n){return calloc(1,n);}
static void nm_free(const void*p){free((void*)p);}
static struct inode*nm_dentry_inode(struct dentry*d){return &d->inode;}
static unsigned nm_inode_mode(const struct inode*i){return i->mode;}
static unsigned paths_opened,paths_closed;
static int kf_nm_kern_path(const char*s,unsigned flags,struct nm_path*p){
 assert(flags==1);int fd=open(s,O_RDONLY);if(fd<0)return -errno;
 struct dentry*d=calloc(1,sizeof(*d));assert(d);d->fd=fd;d->refs=1;
 struct stat st;assert(!fstat(fd,&st));d->inode.mode=st.st_mode;strcpy(d->last,s);
 *p=(struct nm_path){(void*)1,d};paths_opened++;return 0;
}
static void kf_nm_path_get(const struct nm_path*p){assert(p->dentry->refs);p->dentry->refs++;}
static void kf_nm_path_put(const struct nm_path*p){assert(p->dentry->refs);if(!--p->dentry->refs){close(p->dentry->fd);free(p->dentry);paths_closed++;}}
'''
BOUNDARY = r'''
struct nm_topology_leaf {struct nm_topology_leaf*next;struct nomount_leaf*leaf;void*parent;bool automatic;};
static struct nm_topology_leaf*nm_topology_leaves;
static pthread_mutex_t management=PTHREAD_MUTEX_INITIALIZER;
static bool locked,missing;static int injected_error;static const char*injected_path;
static unsigned renders;
static void nm_management_lock(void){assert(!pthread_mutex_lock(&management));assert(!locked);locked=true;}
static void nm_management_unlock(void){assert(locked);locked=false;assert(!pthread_mutex_unlock(&management));}
static char*host_d_path(const struct nm_path*p,char*buf,int len){
 assert(locked&&p->mnt&&p->dentry&&p->dentry->refs);renders++;
 if(injected_error)return ERR_PTR(injected_error);
 char current[4096+16]; // Linux path-size fixture; macOS PATH_MAX is smaller.
 if(injected_path){assert(strlen(injected_path)<sizeof(current));strcpy(current,injected_path);}
 else {
  struct stat st;assert(!fstat(p->dentry->fd,&st));
  // macOS F_GETPATH observes real same/cross-directory rename for the held FD.
  if(fcntl(p->dentry->fd,F_GETPATH,current)<0){assert(!st.st_nlink);strcpy(current,p->dentry->last);}
  else strcpy(p->dentry->last,current);
  if(!st.st_nlink)strcat(current," (deleted)"); // Linux d_path's native display convention.
 }
 size_t n=strlen(current)+1;if(n>(size_t)len)return ERR_PTR(-ENAMETOOLONG);
 char*out=buf+len-n;memcpy(out,current,n);return out;
}
static void*kallsyms_lookup_name_by_suffix(const char*n){assert(!strcmp(n,"d_path"));return missing?NULL:host_d_path;}
struct file {int fd;struct file*backing;};
struct kiocb;struct iov_iter {char*data;size_t count;};
struct nm_kiocb_head {struct file*ki_filp;int64_t ki_pos;void*ki_complete;};
struct nm_file_io_callbacks {long(*read_iter)(struct kiocb*,struct iov_iter*);};
static long host_read(struct kiocb*r,struct iov_iter*i){struct nm_kiocb_head*k=(void*)r;long n=pread(k->ki_filp->fd,i->data,i->count,k->ki_pos);if(n>=0)k->ki_pos+=n;return n;}
static struct nm_file_io_callbacks io={host_read};
static unsigned nm_file_flags(struct file*f){return 0;}
static const void*nm_file_cred(struct file*f){return NULL;}
static void*nm_inode_private(struct inode*i){return i->info;}
static void nm_set_file_private(struct file*f,struct file*b){f->backing=b;}
static struct file*nm_file_private(struct file*f){return f->backing;}
static const void*nm_file_ops(struct file*f){return &io;}
static const struct nm_file_io_callbacks*nm_file_io(const void*p){return p;}
static int(*nm_backing_open_permission)(const struct nm_path*);
static int(*nm_backing_write_open_permission)(const struct nm_path*,unsigned);
static struct file*kf_nm_dentry_open(const struct nm_path*p,int flags,const void*c){
 assert(!flags&&!c);struct file*f=calloc(1,sizeof(*f));assert(f);f->fd=dup(p->dentry->fd);assert(f->fd>=0);return f;
}
static void kf_nm_fput(struct file*f){assert(!close(f->fd));free(f);}
'''
TEST = r'''
static char observed[4096];
static void expect_list(const char*expected){
 struct nm_payload p={0};assert(!nm_control_list(&p)&&p.arg1==1);
 struct nm_rule_hdr h;memcpy(&h,p.buffer,sizeof(h));assert(h.r_len==strlen(expected));
 assert(p.data_size==sizeof(h)+h.v_len+h.r_len);
 memcpy(observed,p.buffer+sizeof(h)+h.v_len,h.r_len);observed[h.r_len]=0;assert(!strcmp(observed,expected));
 p.arg1=1;assert(!nm_control_list(&p)&&!p.data_size);
}
static void content(struct file*f,const char*s){
 char out[64]={0};struct nm_kiocb_head k={.ki_filp=f};struct iov_iter i={out,sizeof(out)};
 assert(nm_read_iter((void*)&k,&i)==(long)strlen(s));assert(!strcmp(out,s)&&k.ki_filp==f);
}
static void write_file(const char*p,const char*s){int fd=open(p,O_CREAT|O_TRUNC|O_WRONLY,0600);assert(fd>=0);assert(write(fd,s,strlen(s))==(ssize_t)strlen(s));close(fd);}
static char from[PATH_MAX],to[PATH_MAX];
static void*renamer(void*unused){for(int i=0;i<200;i++){assert(!rename(from,to));assert(!rename(to,from));}return NULL;}
int main(int argc,char**argv){
 assert(argc==2);char original[PATH_MAX],same[PATH_MAX],cross[PATH_MAX],folder[PATH_MAX],replacement[PATH_MAX];
 snprintf(original,sizeof(original),"%s/original",argv[1]);snprintf(same,sizeof(same),"%s/same",argv[1]);
 snprintf(folder,sizeof(folder),"%s/folder",argv[1]);assert(!mkdir(folder,0700));snprintf(cross,sizeof(cross),"%s/cross",folder);
 write_file(original,"original inode");
 struct nomount_rule*rule=nm_alloc_rule(original,strlen(original),0,0);assert(!IS_ERR(rule));
 struct nm_inode_info info={0};nm_bind_inode_path(&info,rule);struct inode outer={.info=&info};struct file fd={0};assert(!nm_open(&outer,&fd));
 struct nm_rule_array*array=calloc(1,sizeof(*array)+2*sizeof(rule));array->count=1;array->rules[0]=rule;
 struct nomount_leaf*leaf=calloc(1,sizeof(*leaf)+4096);leaf->rules=array;leaf->v_len=2;memcpy(leaf->paths,"/v",2);
 struct nm_topology_leaf entry={.leaf=leaf};nm_topology_leaves=&entry;
 expect_list(original);assert(!rename(original,same));expect_list(same);content(&fd,"original inode");
 assert(!rename(same,cross));expect_list(cross);content(&fd,"original inode");
 // Actual rename/list overlap; path references keep the object alive throughout.
 strcpy(from,cross);snprintf(to,sizeof(to),"%s/moving",folder);pthread_t thread;assert(!pthread_create(&thread,NULL,renamer,NULL));
 for(int i=0;i<200;i++){
  struct nm_payload p={0};assert(!nm_control_list(&p));struct nm_rule_hdr h;memcpy(&h,p.buffer,sizeof(h));
  memcpy(observed,p.buffer+sizeof(h)+h.v_len,h.r_len);observed[h.r_len]=0;assert(!strcmp(observed,from)||!strcmp(observed,to));content(&fd,"original inode");
 }
 assert(!pthread_join(thread,NULL));expect_list(cross);
 assert(!unlink(cross));char deleted[PATH_MAX+16];snprintf(deleted,sizeof(deleted),"%s (deleted)",cross);expect_list(deleted);content(&fd,"original inode");
 write_file(cross,"replacement inode");expect_list(deleted);content(&fd,"original inode");
 struct nm_inode_info after={0};nm_bind_inode_path(&after,rule);struct inode later={.info=&after};struct file fresh={0};assert(!nm_open(&later,&fresh));content(&fresh,"original inode");
 struct nomount_rule*newrule=nm_alloc_rule(cross,strlen(cross),0,0);assert(!IS_ERR(newrule)&&newrule->r_path.dentry!=rule->r_path.dentry);
 array->rules[0]=newrule;expect_list(cross);content(&fd,"original inode");array->rules[0]=rule;
 // Legitimate suffix remains plain native text; no suffix-to-state conversion.
 injected_path="/valid (deleted)";expect_list(injected_path);
 // NUL must not reduce wire capacity: 24 + 2 + 4042 == 4068.
 char large[4096];memset(large,'a',sizeof(large));large[0]='/';large[4042]=0;injected_path=large;
 struct nm_payload p={0};assert(!nm_control_list(&p)&&p.data_size==4068&&p.arg1==1);
 large[4042]='a';large[4043]=0;p=(struct nm_payload){0};assert(nm_control_list(&p)==-ENAMETOOLONG&&!p.data_size&&!p.arg1);
 // First page fills with one record; second page retries exactly the same next rule.
 large[2020]=0;array->count=2;array->rules[1]=newrule;p=(struct nm_payload){0};
 assert(!nm_control_list(&p)&&p.arg1==1&&p.data_size==2046);assert(!nm_control_list(&p)&&p.arg1==2&&p.data_size==2046);
 assert(!nm_control_list(&p)&&!p.data_size);array->count=1;
 injected_path=NULL;injected_error=-EIO;p=(struct nm_payload){0};assert(nm_control_list(&p)==-EIO&&!p.data_size&&!p.arg1);injected_error=0;
 missing=true;p=(struct nm_payload){0};assert(nm_control_list(&p)==-EOPNOTSUPP&&!p.data_size);missing=false;
 struct nm_path saved=rule->r_path;rule->r_path.dentry=NULL;p=(struct nm_payload){0};assert(nm_control_list(&p)==-ESTALE&&!p.data_size);rule->r_path=saved;
 u16 flags=rule->flags;rule->flags=NM_FLAG_WHITEOUT;missing=true;p=(struct nm_payload){0};assert(!nm_control_list(&p)&&p.data_size==26);rule->flags=flags;missing=false;
 expect_list(deleted);content(&fd,"original inode");
 assert(!nm_release(&outer,&fd)&&!nm_release(&later,&fresh));kf_nm_path_put(&info.r_path);kf_nm_path_put(&after.r_path);
 nm_rule_put(rule);nm_rule_put(newrule);free(array);free(leaf);assert(paths_opened==paths_closed&&!locked);
 assert(!unlink(cross)&&!rmdir(folder));
 puts("PASS production fixed binding/open/read/list: same/cross rename, 200 concurrent reads, unlink/recreate, explicit republish, exact-full/+1/paging, native errors and balanced references");
 return 0;
}
'''

def check_target(btf_path, symbols_path, output):
    sys.path.insert(0, str(ROOT / 're_kernel/tools'))
    from test_btf import index_btf
    data = btf_path.read_bytes()
    records, strings = index_btf(data)

    def text(offset):
        start = strings + offset
        return data[start:data.index(b'\0', start)].decode()

    def record(type_id):
        name, info, value = struct.unpack_from('<III', data, records[type_id])
        return text(name), (info >> 24) & 31, value, info & 65535

    def plain(type_id):
        while record(type_id)[1] in (8, 9, 10, 11, 18):
            type_id = record(type_id)[2]
        return type_id

    found = [i for i in range(1, len(records)) if record(i)[:2] == ('d_path', 12)]
    assert len(found) == 1
    proto = record(found[0])[2]
    _, kind, result, count = record(proto)
    assert kind == 13 and count == 3
    params = [struct.unpack_from('<II', data, records[proto] + 12 + i * 8)[1] for i in range(count)]
    for char_pointer in (result, params[1]):
        _, kind, pointee, _ = record(plain(char_pointer))
        assert kind == 2 and record(plain(pointee))[:3] == ('char', 1, 1)
    assert record(plain(params[2]))[:3] == ('int', 1, 4)
    _, kind, pointee, _ = record(plain(params[0]))
    assert kind == 2
    path = plain(pointee)
    assert record(path)[:3] == ('path', 4, 16)
    members = {}
    for i in range(record(path)[3]):
        name, type_id, bits = struct.unpack_from('<III', data, records[path] + 12 + i * 12)
        members[text(name)] = bits // 8
    assert members['mnt'] == 0 and members['dentry'] == 8
    symbols = [row for row in json.loads(symbols_path.read_text()) if row[2] == 'd_path']
    assert symbols and all(row[1] in ('t', 'T') for row in symbols)
    receipt = {'target': 'boot_405 / 6.12.69-android16-6', 'function': 'char *d_path(const struct path *, char *, int)',
               'path_size': 16, 'members': members, 'symbols': symbols,
               'scope': 'Offline BTF and symbols, not runtime invocation'}
    (output / 'target-abi.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--btf',required=True,type=Path);p.add_argument('--symbols',required=True,type=Path)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    check_target(args.btf,args.symbols,args.output)
    source=PRE+(ROOT/'nomount/nm_rules.h').read_text().replace('#include "nm_structs.h"','')
    source+=(ROOT/'nomount/nm_protocol.h').read_text()+BOUNDARY
    source+='static bool (*nm_rule_inode_is_virtual)(struct inode*);\n'
    for name in ('nm_trim_path','nm_rule_path_valid','nm_alloc_rule','nm_rule_put'):
        source+=function('nomount/nm_rules.c',name)
    source+=function('nomount/nm_inode.c','nm_bind_inode_path')
    for name in ('nm_open','nm_release','nm_read_iter'):
        source+=function('nomount/nm_file.c',name)
    source+=function('nomount/nm_control.c','nm_control_list')+TEST
    files=args.output.resolve()/'files';files.mkdir()
    compile_run(source,args.output/'dpath',(files,))
