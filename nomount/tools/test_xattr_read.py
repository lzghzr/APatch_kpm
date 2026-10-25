#!/usr/bin/env python3
"""在989条宿主断言后追加实际get/list接入、控制门禁及FD来源一致性。"""
import argparse,hashlib,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
INPUTS={'int':'ae63b0c5f00fb4ffc3b53d7aac88a92b87a20a76af6292ddb39f5243bbd3d596','bool':'0260fce0ebe1acba4c13052e8ad8ee3bedf98fe1a1858a8eb5dd63f93da5b751'}
MOCK=r'''
typedef int hook_err_t;
static unsigned xr_wrap_calls,xr_fail_call,xr_count;
static int xr_missing;
static struct {void*target;void*before;int count;} xr_hooks[4];
static unsigned long xr_lookup(const char*n){if(!strcmp(n,"vfs_getxattr"))return xr_missing==1?0:0x1000;if(!strcmp(n,"vfs_listxattr"))return xr_missing==2?0:xr_missing==3?0x1000:0x2000;return 0;}
static hook_err_t hook_wrap(void*t,int n,void*b,void*a,void*u){xr_wrap_calls++;if(xr_fail_call==xr_wrap_calls)return -1;assert(xr_count<4&&!a&&!u&&(n>=3&&n<=6));xr_hooks[xr_count++]=(typeof(xr_hooks[0])){t,b,n};return 0;}
static hook_err_t hook_wrap4(void*t,void(*b)(hook_fargs4_t*,void*),void*a,void*u){return hook_wrap(t,4,(void*)b,a,u);}
static hook_err_t hook_wrap3(void*t,void(*b)(hook_fargs3_t*,void*),void*a,void*u){return hook_wrap(t,3,(void*)b,a,u);}
#ifndef nm_log_error
#define nm_log_error(...) ((void)0)
#endif
'''
TEST=r'''
static unsigned xr_native_calls;
static int xr_native_error;
static const char*xr_security_value="source-label";
static const char*xr_user_value="source-user";
static struct dentry*xr_source;
static void*xr_context;
static long xr_native(uint64_t*a,bool list,int mapped){
 xr_native_calls++;assert((void*)a[mapped]==xr_source);if(mapped)assert((void*)a[0]==xr_context);
 if(xr_native_error)return xr_native_error;
 char*buffer=(void*)a[mapped+(list?1:2)];unsigned long size=a[mapped+(list?2:3)];
 const char*value=list?"user.test\0security.selinux\0":!strcmp((void*)a[mapped+1],"security.selinux")?xr_security_value:xr_user_value;
 unsigned long length=list?27:strlen(value);if(!size)return length;if(size<length)return -ERANGE;memcpy(buffer,value,length);return length;
}
static long xr_query(struct dentry*d,bool list,void*context,char*b,unsigned long size,const char*name){
 hook_fargs5_t args={0};unsigned at=!list&&nm_xattr_context?1:0;
 args.args[at]=(uintptr_t)d;args.args[at+1]=(uintptr_t)(list?b:name);args.args[at+2]=list?size:(uintptr_t)b;if(!list)args.args[at+3]=size;
 if(at)args.arg0=(uintptr_t)context;
 if(list){hook_fargs3_t small={0};for(unsigned n=0;n<3;n++)small.args[n]=args.args[n];nm_xattr_list3(&small,NULL);if(small.skip_origin)return (long)small.ret;return xr_native(small.args,true,0);}
 if(at)nm_xattr_get_mapped(&args,NULL);else{hook_fargs4_t small={0};for(unsigned n=0;n<4;n++)small.args[n]=args.args[n];nm_xattr_get4(&small,NULL);if(small.skip_origin)return (long)small.ret;return xr_native(small.args,false,0);}
 return args.skip_origin?(long)args.ret:xr_native(args.args,false,1);
}
static void xr_reset(void){nm_xattr_reads_ready=false;nm_xattr_get_installed=nm_xattr_list_installed=false;nm_xattr_get_target=nm_xattr_list_target=NULL;nm_xattr_get_args=nm_xattr_context=0;xr_wrap_calls=xr_fail_call=xr_count=0;xr_missing=0;}
static void check_xattr_reads(void){
 target();directory_target();xr_reset();nm_xattr_resident=false;assert(nm_activate_xattr_reads_locked()==-ENODEV&&!xr_wrap_calls);
 nm_xattr_resident=true;
 for(xr_missing=1;xr_missing<=3;xr_missing++){assert(nm_activate_xattr_reads_locked()==(xr_missing==3?-EINVAL:-ENOENT)&&!xr_wrap_calls&&!nm_xattr_reads_ready);}xr_missing=0;
 struct struct_offset saved=struct_offset;struct_offset.permission_abi=9;assert(nm_activate_xattr_reads_locked()==-EOPNOTSUPP&&!xr_wrap_calls);struct_offset=saved;
 struct_offset.getattr_context_kind=2;struct_offset.permission_abi=3;assert(nm_activate_xattr_reads_locked()==-EOPNOTSUPP&&!xr_wrap_calls);struct_offset=saved;
 struct mutex*prior_lock=nm_management_mutex;nm_management_mutex=(void*)1;kf_nm_mutex_lock=control_lock;kf_nm_mutex_unlock=control_unlock;
 struct nm_payload rejected={.cmd=NM_CMD_ADD_RULE};struct nm_rule_hdr rh={.uid=1000,.uid_end=1000,.v_len=7,.flags=NM_FLAG_WHITEOUT};memcpy(rejected.buffer,&rh,sizeof(rh));memcpy(rejected.buffer+sizeof(rh),"/absent",7);rejected.data_size=sizeof(rh)+7;
 nm_xattr_resident=false;assert(nm_control_rules(&rejected,true)==-ENODEV&&rejected.status==-ENODEV&&rejected.arg1==rejected.data_size&&!xr_wrap_calls);drain();nm_xattr_resident=true;nm_management_mutex=prior_lock;
 xr_fail_call=1;assert(nm_activate_xattr_reads_locked()==-EOPNOTSUPP&&!nm_xattr_get_installed&&!nm_xattr_reads_ready);xr_fail_call=3;
 assert(nm_activate_xattr_reads_locked()==-EOPNOTSUPP&&nm_xattr_get_installed&&!nm_xattr_list_installed&&!nm_xattr_reads_ready);
 hook_fargs4_t pending={.skip_origin=1,.ret=99,.arg0=0x1234};nm_xattr_get4(&pending,NULL);assert(pending.skip_origin&&pending.ret==99&&pending.arg0==0x1234);
 pending=(hook_fargs4_t){.arg0=0x1234,.arg1=0x4567};nm_xattr_get4(&pending,NULL);assert(!pending.skip_origin&&pending.arg0==0x1234&&pending.arg1==0x4567);
 xr_fail_call=0;assert(!nm_activate_xattr_reads_locked()&&xr_wrap_calls==4&&xr_count==2&&nm_xattr_reads_ready);assert(!nm_activate_xattr_reads_locked()&&xr_wrap_calls==4);
 _Alignas(8) unsigned char outer[1024]={0},src[1024]={0},dentry[256]={0},real[256]={0},fd[768]={0};struct nm_mount_context_head mount={0};
 xr_source=(void*)real;((struct nm_dentry_head*)real)->d_inode=(void*)src;((struct nm_dentry_head*)dentry)->d_inode=(void*)outer;
 const void*owned[]={(void*)0x3100,(void*)0x3200,(void*)0x3300};nm_inode_engine.inode_ops=(void*)owned[0];nm_inode_engine.directory_ops=owned[1];nm_inode_engine.symlink_ops=(void*)owned[2];
 struct nm_inode_info info={.r_path={(void*)&mount,(void*)real},.initialized=true};nm_set_inode_private(outer,&info);char path_value[64],fd_value[64];
 *(struct nm_path*)nm_file_path(fd)=(struct nm_path){.dentry=(void*)dentry};
 for(unsigned kind=0;kind<3;kind++)for(int ctx=0;ctx<=2;ctx++){
  nm_inode_objects(outer)->i_op=owned[kind];nm_xattr_context=ctx;xr_context=(void*)0x5678;mount.context.idmap=xr_context;
  const char*names[]={"user.test","security.selinux"};
  for(unsigned n=0;n<2;n++){
   memset(path_value,0xa5,64);memset(fd_value,0xa5,64);
   long p=xr_query((void*)dentry,false,(void*)0x9999,path_value,64,names[n]);long f=xr_query(nm_file_path(fd)->dentry,false,(void*)0x8888,fd_value,64,names[n]);
   assert(p==f&&p>0&&!memcmp(path_value,fd_value,64)&&(unsigned char)path_value[p]==0xa5);
   assert(xr_query((void*)dentry,false,NULL,NULL,0,names[n])==p);assert(xr_query((void*)dentry,false,NULL,path_value,1,names[n])==-ERANGE);
  }
  assert(xr_query((void*)dentry,true,NULL,path_value,64,NULL)==27&&xr_query(nm_file_path(fd)->dentry,true,NULL,fd_value,64,NULL)==27&&!memcmp(path_value,fd_value,27));
  assert(xr_query((void*)dentry,true,NULL,NULL,0,NULL)==27&&xr_query((void*)dentry,true,NULL,path_value,1,NULL)==-ERANGE);
  const int errors[]={-EACCES,-EPERM,-ENODATA,-EOPNOTSUPP,-ENOMEM,-EIO};for(unsigned e=0;e<6;e++){xr_native_error=errors[e];assert(xr_query((void*)dentry,false,NULL,path_value,64,"user.test")==errors[e]);assert(xr_query((void*)dentry,true,NULL,path_value,64,NULL)==errors[e]);}xr_native_error=0;
  xr_security_value="new-source-label";assert(xr_query(nm_file_path(fd)->dentry,false,NULL,fd_value,64,"security.selinux")==16&&!memcmp(fd_value,xr_security_value,16));
 }
 // 外层规则已退役的持有FD仍走info的独立源path；不重查规则索引。
 nm_xattr_context=0;assert(xr_query(nm_file_path(fd)->dentry,false,NULL,fd_value,64,"user.test")==11);
 unsigned calls=xr_native_calls;info.r_path.dentry=(void*)dentry;assert(xr_query((void*)dentry,false,NULL,fd_value,64,"user.test")==-ELOOP&&xr_native_calls==calls);info.r_path.dentry=(void*)real;
 nm_inode_objects(src)->i_op=owned[0];assert(xr_query((void*)dentry,true,NULL,fd_value,64,NULL)==-ELOOP&&xr_native_calls==calls);nm_inode_objects(src)->i_op=NULL;
 ((struct nm_dentry_head*)real)->d_inode=NULL;assert(xr_query((void*)dentry,true,NULL,fd_value,64,NULL)==-EIO&&xr_native_calls==calls);((struct nm_dentry_head*)real)->d_inode=(void*)src;
 nm_set_inode_private(outer,NULL);assert(xr_query((void*)dentry,true,NULL,fd_value,64,NULL)==-EIO&&xr_native_calls==calls);nm_set_inode_private(outer,&info);
 info.r_path.mnt=NULL;assert(xr_query((void*)dentry,false,NULL,fd_value,64,"user.test")==-EIO&&xr_native_calls==calls);info.r_path.mnt=(void*)&mount;
 nm_xattr_context=1;mount.context.userns=NULL;assert(xr_query((void*)dentry,false,NULL,fd_value,64,"user.test")==-EINVAL&&xr_native_calls==calls);
 hook_fargs4_t untouched={.arg0=(uintptr_t)dentry,.arg1=0x4567,.arg2=0x789a,.arg3=0};info.r_path.dentry=NULL;nm_xattr_list3(&untouched,NULL);assert(!untouched.skip_origin&&untouched.arg0==(uintptr_t)dentry&&untouched.arg1==0x4567);
 nm_inode_objects(outer)->i_op=(void*)0x1111;nm_xattr_get4(&untouched,NULL);assert(!untouched.skip_origin&&untouched.arg0==(uintptr_t)dentry);nm_inode_engine=(struct nm_inode_engine){0};
 puts("xattr get/list: source dentry/context, native errors, path/FD agreement, cycles and resident partial-registration gates PASS");
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle-output',type=Path,required=True);p.add_argument('--cli-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 sdk=(ROOT/'KernelPatch/kernel/include/hook.h').read_text();sdk=sdk[sdk.index('#define HOOK_LOCAL_DATA_NUM'):sdk.index('typedef void (*hook_chain0_callback')]
 rows=[]
 for abi,digest in INPUTS.items():
  original=(a.oracle_output/abi/'contracts.c').read_text();assert hashlib.sha256(original.encode()).hexdigest()==digest;before=re.findall(r'\bassert\s*\([^;]+\);',original);source=original
  code=(ROOT/'nomount/nm_xattr.c').read_text().replace('kallsyms_lookup_name_by_suffix(', 'xr_lookup(')
  source=source.replace(function(source,'nm_control_rules'),function((ROOT/'nomount/nm_control.c').read_text(),'nm_control_rules'),1)
  source=source.replace(function(source,'nm_register_control'),function((ROOT/'nomount/nm_control_key.c').read_text(),'nm_register_control').replace('kallsyms_lookup_name_by_suffix(', 'control_lookup('),1)
  assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
  source=source.replace('static void nm_control_error',sdk+MOCK+code+'\nstatic void nm_control_error',1)
  source=source.replace('int main(void){assert(!previous_consistency_main());','static int previous_xattr_main(void){assert(!previous_consistency_main());',1)
  source+=TEST+'\nint main(void){nm_xattr_resident=true;assert(!previous_xattr_main());check_xattr_reads();return 0;}\n'
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log');run([str((out/'contracts').resolve())],out/'run.log')
  rows.append({'abi':abi,'prior_assert_sites':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',source))-len(before),'result':'PASS'})
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer callback and controller fixtures, not native syscall/LSM/CFI proof','results':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
