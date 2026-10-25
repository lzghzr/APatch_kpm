#!/usr/bin/env python3
"""在1189处宿主断言之后追加A档setxattr路由、权限模型与拒绝路径。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = {'int': '8bc449c755f82c10df91b5acb516bea7ec89e83bd5514c54ccbcdd9358e7d589',
           'bool': 'f27370ec8f4cb4e819ce69858874ed3afffb5cb35cbce98c573c814be7c31386'}
PRE = r'''
static int xw_shape,xw_query_error,xw_missing,xw_fail_wrap;
static bool xw_btf_missing;
static unsigned xw_wraps,xw_count,xw_ro_calls,xw_native_calls,xw_locks,xw_unlocks,xw_lsm_calls;
static struct {void*target;void*before;int count;} xw_hooks[2];
static struct vfsmount*xw_expected_mount;
static bool xw_readonly(struct vfsmount*m){assert(m==xw_expected_mount);xw_ro_calls++;return ((struct nm_mount_context_head*)m)->flags&0x40;}
static unsigned long xw_lookup(const char*n){
 if(!strcmp(n,"vfs_setxattr"))return xw_missing==1?0:0x5000;
 if(!strcmp(n,"do_set_acl"))return xw_missing==2?0:xw_missing==3?0x5000:xw_shape?0x6000:0;
 if(!strcmp(n,"__mnt_is_readonly"))return xw_missing==4?0:(uintptr_t)xw_readonly;
 return 0;
}
static int calculate_btf_xattr_write(int context,bool*unavailable){*unavailable=xw_btf_missing;return xw_btf_missing?-ENODATA:xw_query_error?xw_query_error:xw_shape;}
static hook_err_t xw_wrap(void*t,int n,void*b,void*a,void*u){
 xw_wraps++;if((int)xw_wraps==xw_fail_wrap)return -1;
 assert(xw_count<2&&!a&&!u&&(n==5||n==6));xw_hooks[xw_count++]=(typeof(xw_hooks[0])){t,b,n};return 0;
}
'''
TEST = r'''
static void xw_reset(int context,bool acl){
 nm_xattr_writes_ready=nm_xattr_set_installed=nm_xattr_set_acl_installed=false;
 nm_xattr_set_target=nm_xattr_set_acl_target=NULL;nm_xattr_write_readonly=NULL;nm_xattr_write_status=-EOPNOTSUPP;
 xw_shape=acl;xw_query_error=xw_missing=xw_fail_wrap=0;xw_btf_missing=false;xw_wraps=xw_count=0;
 xw_ro_calls=xw_native_calls=xw_locks=xw_unlocks=xw_lsm_calls=0;
 nm_xattr_resident=true;struct_offset.getattr_context_kind=context;struct_offset.permission_abi=context+1;
 struct_offset.getattr_callback_args=context?5:4;
}
static struct dentry*xw_source;
static bool xw_cap_admin,xw_present;
static int xw_lsm_error;
static char xw_value[64];static size_t xw_length;
/* 完整原生VFS的权限/LSM/handler模型；不是实际SELinux或文件系统。 */
static int xw_native(uint64_t*a,bool acl){
 unsigned at=nm_xattr_set_context?1:0;xw_native_calls++;
 assert((void*)a[at]==xw_source);
 if(at)assert((void*)a[0]==((struct nm_mount_context_head*)xw_expected_mount)->context.userns);
 const char*name=(void*)a[at+1];const void*value=(void*)a[at+2];size_t size=a[at+3];int flags=acl?0:(int)a[at+4];
 xw_locks++;int rc=0;
 if(!strncmp(name,"trusted.",8)&&!xw_cap_admin)rc=-EPERM;
 else {xw_lsm_calls++;rc=xw_lsm_error;}
 if(!rc){
  if((flags&1)&&xw_present)rc=-EEXIST;
  else if((flags&2)&&!xw_present)rc=-ENODATA;
  else if(size>sizeof(xw_value))rc=-E2BIG;
  else {if(size)memcpy(xw_value,value,size);xw_length=size;xw_present=true;}
 }
 xw_unlocks++;return rc;
}
static int xw_set(struct dentry*d,void*context,const char*n,const void*v,size_t s,int f,bool acl){
 hook_fargs6_t args={0};unsigned at=nm_xattr_set_context?1:0;
 args.args[at]=(uintptr_t)d;args.args[at+1]=(uintptr_t)n;args.args[at+2]=(uintptr_t)v;args.args[at+3]=s;args.args[at+4]=f;
 if(at)args.arg0=(uintptr_t)context;
 unsigned h=acl?1:0;assert(h<xw_count&&xw_hooks[h].count==(acl?5:at?6:5));
 uint64_t before[6];memcpy(before,args.args,sizeof(before));
 ((void(*)(hook_fargs6_t*,void*))xw_hooks[h].before)(&args,NULL);
 if(args.skip_origin)assert(!memcmp(before,args.args,sizeof(before)));
 else for(unsigned i=0;i<6;i++)assert(args.args[i]==(i==at?(uintptr_t)xw_source:before[i]));
 return args.skip_origin?(long)args.ret:xw_native(args.args,acl);
}
static long xw_get(struct dentry*d,void*context,char*buffer){
 hook_fargs5_t args={0};unsigned at=nm_xattr_context?1:0;
 args.args[at]=(uintptr_t)d;args.args[at+1]=(uintptr_t)"user.test";args.args[at+2]=(uintptr_t)buffer;args.args[at+3]=64;
 if(at){args.arg0=(uintptr_t)context;nm_xattr_get_mapped(&args,NULL);}else{
  hook_fargs4_t small={0};memcpy(small.args,args.args,4*sizeof(uint64_t));nm_xattr_get4(&small,NULL);
  if(small.skip_origin)return (long)small.ret;memcpy(args.args,small.args,4*sizeof(uint64_t));
 }
 if(args.skip_origin)return (long)args.ret;
 assert((void*)args.args[at]==xw_source);if(!xw_present)return -ENODATA;
 memcpy(buffer,xw_value,xw_length);return xw_length;
}
static void check_xattr_write_activation(void){
 target();directory_target();xw_reset(0,false);nm_xattr_resident=false;
 assert(nm_activate_xattr_writes_locked()==-ENODEV&&!xw_wraps);nm_xattr_resident=true;
 xw_missing=1;assert(nm_activate_xattr_writes_locked()==-ENOENT&&!xw_wraps);
 xw_reset(0,false);xw_missing=3;assert(nm_activate_xattr_writes_locked()==-EINVAL&&!xw_wraps);
 xw_reset(0,false);xw_query_error=-EINVAL;assert(nm_activate_xattr_writes_locked()==-EINVAL&&!xw_wraps);
 xw_reset(2,true);xw_missing=2;assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!xw_wraps);
 xw_reset(0,false);xw_btf_missing=true;assert(!nm_activate_xattr_writes_locked()&&nm_xattr_write_status==-EOPNOTSUPP&&xw_count==1);
 xw_reset(2,false);xw_btf_missing=true;assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!xw_wraps);
 xw_reset(1,false);xw_missing=4;assert(!nm_activate_xattr_writes_locked()&&nm_xattr_write_status==-ENOENT&&xw_count==1);
 xw_reset(2,true);xw_fail_wrap=1;assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!nm_xattr_writes_ready&&!xw_count);
 xw_fail_wrap=3;assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!nm_xattr_writes_ready&&xw_count==1&&nm_xattr_set_installed&&!nm_xattr_set_acl_installed);
 xw_fail_wrap=0;assert(!nm_activate_xattr_writes_locked()&&nm_xattr_writes_ready&&xw_count==2&&xw_wraps==4);
 assert(!nm_activate_xattr_writes_locked()&&xw_wraps==4);
 hook_fargs6_t prior={.skip_origin=1,.ret=99,.arg0=0x1111};nm_xattr_set_mapped(&prior,NULL);
 assert(prior.skip_origin&&prior.ret==99&&prior.arg0==0x1111);
 /* 普通inode保持直通，部分安装时也不能污染它。 */
 _Alignas(8)unsigned char d[256]={0},i[1024]={0};((struct nm_dentry_head*)d)->d_inode=(void*)i;
 prior=(hook_fargs6_t){.arg0=(uintptr_t)d};nm_xattr_writes_ready=false;nm_xattr_set5(&prior,NULL);
 assert(!prior.skip_origin&&prior.arg0==(uintptr_t)d);
 /* 当前生产控制函数：写hook缺失时，在拓扑发布前拒绝ADD。 */
 nm_xattr_reads_ready=true;xw_reset(0,false);xw_missing=1;
 struct mutex*saved_lock=nm_management_mutex;nm_management_mutex=(void*)1;kf_nm_mutex_lock=control_lock;kf_nm_mutex_unlock=control_unlock;
 struct nm_payload rejected={.cmd=NM_CMD_ADD_RULE};struct nm_rule_hdr rh={.uid=1000,.uid_end=1000,.v_len=11,.flags=NM_FLAG_WHITEOUT};
 memcpy(rejected.buffer,&rh,sizeof(rh));memcpy(rejected.buffer+sizeof(rh),"/xw-blocked",11);rejected.data_size=sizeof(rh)+11;
 assert(nm_control_rules(&rejected,true)==-ENOENT&&rejected.status==-ENOENT&&rejected.arg1==rejected.data_size&&!xw_wraps);
 drain();nm_management_mutex=saved_lock;
 puts("setxattr activation: resident, missing/alias/BTF, partial hooks, retry and ADD refusal PASS");
}
static void check_xattr_writes(void){
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,905));
 struct inode*outer=nm_dentry_inode(outer_root);struct nm_inode_info*info=nm_inode_private(outer);assert(outer&&info&&info->initialized);
 struct nm_mount_context_head source_mount={.context.userns=(void*)0x8765},outer_mount={.flags=0};
 struct nm_path path={&outer_mount,(void*)outer_root};_Alignas(8)unsigned char fd[768]={0},source_sb[256]={0};
 *(struct nm_path*)nm_file_path(fd)=path;void*saved_mnt=backing_path.mnt;void*saved_sb=nm_inode_superblock(backing);
 backing_path.mnt=&source_mount;info->r_path.mnt=&source_mount;*(void**)((uintptr_t)backing+struct_offset.inode_superblock)=source_sb;
 assert(nm_inode_superblock(outer)!=nm_inode_superblock(backing)&&!outer_mount.flags);
 xw_source=backing_path.dentry;xw_expected_mount=(void*)&source_mount;
 unsigned char source_before[768],outer_before[768];char got[64];
 const void*owned[]={nm_inode_engine.inode_ops,nm_inode_engine.directory_ops,nm_inode_engine.symlink_ops};
 for(int context=0;context<3;context++){
  xw_reset(context,context==2);assert(!nm_activate_xattr_writes_locked()&&!nm_xattr_write_status);
  nm_xattr_reads_ready=true;nm_xattr_context=context;void*ctx=context?source_mount.context.userns:NULL;
  for(unsigned kind=0;kind<3;kind++){
   nm_inode_objects(outer)->i_op=owned[kind];
   for(unsigned via=0;via<2;via++){
    struct dentry*d=via?nm_file_path(fd)->dentry:path.dentry;
    memcpy(source_before,backing,768);memcpy(outer_before,outer,768);
    xw_cap_admin=true;xw_lsm_error=0;xw_present=false;memset(xw_value,0,64);xw_length=0;
    source_mount.flags=0x40;unsigned calls=xw_native_calls;
    int ro_rc=xw_set(d,ctx,"user.test","a",1,0,false);
    if(ro_rc!=-EROFS)fprintf(stderr,"RO context=%d kind=%u via=%u rc=%d\n",context,kind,via,ro_rc);
    assert(ro_rc==-EROFS&&xw_native_calls==calls);
    assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768)&&!xw_present&&!xw_length);
    source_mount.flags=0;
    assert(!xw_set(d,ctx,"user.test","a",1,1,false));
    assert(xw_get(via?path.dentry:nm_file_path(fd)->dentry,ctx,got)==1&&got[0]=='a');
    assert(xw_set(d,ctx,"user.test","b",1,1,false)==-EEXIST&&xw_length==1&&xw_value[0]=='a');
    assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
    assert(!xw_set(d,ctx,"user.test","b",1,2,false));
    assert(xw_get(via?path.dentry:nm_file_path(fd)->dentry,ctx,got)==1&&got[0]=='b');
    xw_present=false;assert(xw_set(d,ctx,"user.test","c",1,2,false)==-ENODATA&&!xw_present&&xw_value[0]=='b');
    assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
    xw_cap_admin=false;unsigned lsm=xw_lsm_calls;
    assert(xw_set(d,ctx,"trusted.test","c",1,0,false)==-EPERM&&xw_lsm_calls==lsm&&!xw_present);
    assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));xw_cap_admin=true;
    calls=xw_native_calls;assert(xw_set(d,ctx,"security.capability","c",1,0,false)==-EOPNOTSUPP&&xw_native_calls==calls&&!xw_present);
    /* 审计追加：所有畸形输入必须在源原生调用前拒绝。 */
    assert(xw_set(d,ctx,NULL,"c",1,0,false)==-EINVAL&&xw_native_calls==calls&&!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
    void*saved_mount=info->r_path.mnt;info->r_path.mnt=NULL;
    assert(xw_set(d,ctx,"user.test","c",1,0,false)==-EIO&&xw_native_calls==calls&&!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));info->r_path.mnt=saved_mount;
    ((struct nm_dentry_head*)xw_source)->d_inode=NULL;
    assert(xw_set(d,ctx,"user.test","c",1,0,false)==-EIO&&xw_native_calls==calls&&!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));((struct nm_dentry_head*)xw_source)->d_inode=backing;
    if(context){void*saved_context=source_mount.context.userns;source_mount.context.userns=NULL;
     assert(xw_set(d,ctx,"user.test","c",1,0,false)==-EINVAL&&xw_native_calls==calls&&!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));source_mount.context.userns=saved_context;}
    xw_lsm_error=-EACCES;lsm=xw_lsm_calls;
    assert(xw_set(d,ctx,"security.selinux","c",1,0,false)==-EACCES&&xw_lsm_calls==lsm+1&&!xw_present);
    assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));xw_lsm_error=0;
    assert(!xw_set(d,ctx,"security.selinux","c",1,0,false)&&xw_lsm_calls==lsm+2);
    if(context){calls=xw_native_calls;assert(xw_set(d,(void*)0x1111,"user.test","d",1,0,false)==-EXDEV&&xw_native_calls==calls);}
    calls=xw_native_calls;nm_xattr_write_readonly=NULL;assert(xw_set(d,ctx,"user.test","d",1,0,false)==-ENOENT&&xw_native_calls==calls);nm_xattr_write_readonly=xw_readonly;
    int saved=struct_offset.inode_size;struct_offset.inode_size=-8;assert(xw_set(d,ctx,"user.test","d",1,0,false)==-EINVAL&&xw_native_calls==calls);struct_offset.inode_size=saved;
    nm_xattr_writes_ready=false;assert(xw_set(d,ctx,"user.test","d",1,0,false)==-EOPNOTSUPP&&xw_native_calls==calls);nm_xattr_writes_ready=true;
    info->r_path.dentry=NULL;assert(xw_set(d,ctx,"user.test","d",1,0,false)==-EOPNOTSUPP&&xw_native_calls==calls);info->r_path.dentry=xw_source;
    nm_inode_objects(backing)->i_op=owned[kind];assert(xw_set(d,ctx,"user.test","d",1,0,false)==-ELOOP&&xw_native_calls==calls);nm_inode_objects(backing)->i_op=NULL;
    assert(xw_locks==xw_unlocks);
   }
  }
  /* 同一负例分别经过path与held-FD来源，显式比较返回值。 */
  int path_rc,fd_rc;source_mount.flags=0x40;
  memcpy(source_before,backing,768);memcpy(outer_before,outer,768);
  path_rc=xw_set(path.dentry,ctx,"user.test","x",1,0,false);
  fd_rc=xw_set(nm_file_path(fd)->dentry,ctx,"user.test","x",1,0,false);
  assert(path_rc==-EROFS&&fd_rc==path_rc&&!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));source_mount.flags=0;
  xw_present=true;path_rc=xw_set(path.dentry,ctx,"user.test","x",1,1,false);fd_rc=xw_set(nm_file_path(fd)->dentry,ctx,"user.test","x",1,1,false);
  assert(path_rc==-EEXIST&&fd_rc==path_rc);
  xw_present=false;path_rc=xw_set(path.dentry,ctx,"user.test","x",1,2,false);fd_rc=xw_set(nm_file_path(fd)->dentry,ctx,"user.test","x",1,2,false);
  assert(path_rc==-ENODATA&&fd_rc==path_rc);
  xw_cap_admin=false;path_rc=xw_set(path.dentry,ctx,"trusted.test","x",1,0,false);fd_rc=xw_set(nm_file_path(fd)->dentry,ctx,"trusted.test","x",1,0,false);
  assert(path_rc==-EPERM&&fd_rc==path_rc);xw_cap_admin=true;
  path_rc=xw_set(path.dentry,ctx,"security.capability","x",1,0,false);fd_rc=xw_set(nm_file_path(fd)->dentry,ctx,"security.capability","x",1,0,false);
  assert(path_rc==-EOPNOTSUPP&&fd_rc==path_rc);
  if(context){path_rc=xw_set(path.dentry,(void*)0x1111,"user.test","x",1,0,false);fd_rc=xw_set(nm_file_path(fd)->dentry,(void*)0x1111,"user.test","x",1,0,false);assert(path_rc==-EXDEV&&fd_rc==path_rc);}
  if(context==2){const char*names[]={"system.posix_acl_access","system.posix_acl_default"};
   for(unsigned n=0;n<2;n++){
    assert(!xw_set(path.dentry,ctx,names[n],"acl",3,0,true));
    assert(!xw_set(nm_file_path(fd)->dentry,ctx,names[n],"acl",3,0,true));
    unsigned calls=xw_native_calls;assert(xw_set(path.dentry,(void*)0x1111,names[n],"acl",3,0,true)==-EXDEV&&xw_native_calls==calls);
   }
  }
 }
 nm_inode_objects(outer)->i_op=nm_inode_engine.inode_ops;
 *(void**)((uintptr_t)backing+struct_offset.inode_superblock)=saved_sb;backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;
 port_iput(outer);assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 puts("setxattr path/FD x 3 inode kinds x 3 contexts: cross-sb RO, CREATE/REPLACE, trusted capability, LSM, nscap refusal, EXDEV and ACL PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    configs = sorted((ROOT / 'local/nomount/configs').glob('*v4.json'))
    if len(configs) != 12:
        raise FileNotFoundError('12 local static regression profiles required in local/nomount/configs; '
                                'restore the target-bound evidence before running this test')
    a.output.mkdir(parents=True, exist_ok=False)
    code = (ROOT / 'nomount/nm_xattr_write.c').read_text().replace('kallsyms_lookup_name_by_suffix(', 'xw_lookup(').replace('hook_wrap(', 'xw_wrap(')
    static = function(code, 'nm_activate_xattr_writes_locked').replace('nm_activate_xattr_writes_locked(', 'xw_activate_static(', 1)
    rows = []
    for abi, digest in DIGESTS.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1189
        source = original.replace(function(original, 'nm_control_rules'), function((ROOT / 'nomount/nm_control.c').read_text(), 'nm_control_rules'), 1)
        source = source.replace('static void nm_control_error', PRE+'\n#undef CONFIG_KPM_BASELINES\n'+code+'\n#define CONFIG_KPM_BASELINES 1\n'+static+'\nstatic void nm_control_error', 1)
        assert re.findall(r'\bassert\s*\([^;]+\);', source.replace(PRE, '', 1)) == before
        prefix_asserts = re.findall(r'\bassert\s*\([^;]+\);', source)
        entry = 'int main(void){assert(!previous_prepare_chain_main());check_cold_prepare_chain();return 0;}'
        assert source.count(entry) == 1
        source = source.replace(entry, entry.replace('int main(', 'static int previous_write_main('), 1)
        matrix = '\nstatic void check_xattr_write_static(void){\n'
        for config in configs:
            values = json.loads(config.read_text())['offsets']
            matrix += 'struct_offset=(struct struct_offset){' + ','.join(f'.{k}={v}' for k,v in values.items()) + '};\n'
            matrix += '''{int context=struct_offset.getattr_context_kind;struct struct_offset profile=struct_offset;xw_reset(context,false);struct_offset=profile;
 _Alignas(8)unsigned char inode[1024]={0},d[256]={0};nm_inode_engine.inode_ops=(void*)0x7777;nm_inode_objects(inode)->i_op=nm_inode_engine.inode_ops;((struct nm_dentry_head*)d)->d_inode=(void*)inode;
 assert(!xw_activate_static()&&nm_xattr_write_status==-EOPNOTSUPP);
 assert(xw_set((void*)d,NULL,"user.test","a",1,0,false)==-EOPNOTSUPP&&!xw_native_calls&&!xw_ro_calls);}\n'''
        matrix += 'nm_inode_engine=(struct nm_inode_engine){0};puts("12 static xattr writer profiles: registered refusal PASS");}\n'
        source += TEST + matrix + '\nint main(void){nm_xattr_writes_ready=true;assert(!previous_write_main());check_xattr_write_activation();check_xattr_writes();check_xattr_write_static();return 0;}\n'
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        # 新helper在旧源码中间插入；先逐条核对剔除PRE后的旧断言，再核对追加前缀。
        assert after[:len(prefix_asserts)] == prefix_asserts
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn',
             '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'),
             str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before),
                     'total_assert_sites': len(after), 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer ASan/UBSan host; native permissions/LSM/handler modeled, not real syscall/SELinux proof', 'host': rows}, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
