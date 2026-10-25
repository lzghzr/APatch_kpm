#!/usr/bin/env python3
"""保留读取族1021条断言，追加独立ACL接入与动态签名失败传播。"""
import argparse,hashlib,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
INPUTS={'int': '66269ce9d6b38b44ed52dcf92f9046418223ac18b0b9345b5c5dd44a9578bbca', 'bool': '545be71677b26e306f18f484bced012d717750d042d6d147c968766ecdfad958'}
PRE=r'''
static bool nm_xattr_acl_installed;
static void*nm_xattr_acl_target;
static int acl_mode,acl_error;
static bool acl_missing,acl_alias;
static unsigned long acl_lookup(const char*n){if(!strcmp(n,"do_get_acl"))return acl_mode&&!acl_missing?(acl_alias?0x1000:0x3000):0;return xr_lookup(n);}
static int calculate_btf_xattr_read(int ctx,bool*unavailable){*unavailable=!acl_mode;return acl_mode?ctx?5:4:-ENODATA;}
static int calculate_btf_xattr_acl(int ctx,bool*unavailable){*unavailable=!acl_mode;return acl_mode?(acl_error?acl_error:1):-ENODATA;}
'''
TEST=r'''
static void acl_reset(void){xr_reset();nm_xattr_acl_installed=false;nm_xattr_acl_target=NULL;acl_mode=1;acl_missing=acl_alias=false;acl_error=0;nm_xattr_resident=true;target();directory_target();struct_offset.getattr_context_kind=2;struct_offset.permission_abi=3;}
static void check_acl_reads(void){
 acl_reset();acl_error=-EINVAL;assert(nm_activate_xattr_reads_locked()==-EINVAL&&!xr_wrap_calls&&!nm_xattr_reads_ready);
 acl_reset();acl_missing=true;assert(nm_activate_xattr_reads_locked()==-ENOENT&&!xr_wrap_calls);
 acl_reset();acl_alias=true;assert(nm_activate_xattr_reads_locked()==-EINVAL&&!xr_wrap_calls);
 acl_reset();xr_fail_call=3;assert(nm_activate_xattr_reads_locked()==-EOPNOTSUPP&&xr_wrap_calls==3&&xr_count==2&&!nm_xattr_reads_ready&&!nm_xattr_acl_installed);
 hook_fargs5_t pending={.arg0=0x1,.arg1=0x2};nm_xattr_get_mapped(&pending,NULL);assert(pending.arg0==1&&pending.arg1==2&&!pending.skip_origin);
 xr_fail_call=0;assert(!nm_activate_xattr_reads_locked()&&xr_wrap_calls==4&&xr_count==3&&nm_xattr_acl_installed&&nm_xattr_reads_ready);assert(!nm_activate_xattr_reads_locked()&&xr_wrap_calls==4);
 assert(xr_hooks[2].target==(void*)0x3000&&xr_hooks[2].count==5&&xr_hooks[2].before==(void*)nm_xattr_get_mapped);
 _Alignas(8) unsigned char inode[1024]={0},source[1024]={0},outer[256]={0},real[256]={0},fd[768]={0};struct nm_mount_context_head mount={.context.idmap=(void*)0x4567};
 nm_inode_engine.inode_ops=(void*)0x7777;nm_inode_objects(inode)->i_op=nm_inode_engine.inode_ops;((struct nm_dentry_head*)outer)->d_inode=(void*)inode;((struct nm_dentry_head*)real)->d_inode=(void*)source;
 struct nm_inode_info info={.r_path={(void*)&mount,(void*)real},.initialized=true};nm_set_inode_private(inode,&info);*(struct nm_path*)nm_file_path(fd)=(struct nm_path){.dentry=(void*)outer};
 const char*names[]={"system.posix_acl_access","system.posix_acl_default"};char b[16];
 for(unsigned n=0;n<2;n++){
  hook_fargs5_t path={.arg0=0x1111,.arg1=(uintptr_t)outer,.arg2=(uintptr_t)names[n],.arg3=(uintptr_t)b,.arg4=sizeof(b)},descriptor=path;descriptor.arg1=(uintptr_t)nm_file_path(fd)->dentry;
  ((void(*)(hook_fargs5_t*,void*))xr_hooks[2].before)(&path,NULL);((void(*)(hook_fargs5_t*,void*))xr_hooks[2].before)(&descriptor,NULL);
  assert(!path.skip_origin&&!descriptor.skip_origin&&!memcmp(path.args,descriptor.args,5*sizeof(uint64_t)));
  assert(path.arg0==(uintptr_t)mount.context.idmap&&path.arg1==(uintptr_t)real&&path.arg2==(uintptr_t)names[n]&&path.arg3==(uintptr_t)b&&path.arg4==16);
  path=(hook_fargs5_t){.arg0=0x1111,.arg1=(uintptr_t)outer};mount.context.idmap=NULL;nm_xattr_get_mapped(&path,NULL);assert(path.skip_origin&&(long)path.ret==-EINVAL&&path.arg0==0x1111&&path.arg1==(uintptr_t)outer);mount.context.idmap=(void*)0x4567;
 }
 nm_inode_engine=(struct nm_inode_engine){0};puts("ACL access/default get: source idmap/dentry, path/FD arguments, third-wrap failure and retry gates PASS");
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle-output',type=Path,required=True);p.add_argument('--cli-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for abi,digest in INPUTS.items():
  original=(a.oracle_output/abi/'contracts.c').read_text();assert hashlib.sha256(original.encode()).hexdigest()==digest;before=re.findall(r'\bassert\s*\([^;]+\);',original);source=original
  new=function((ROOT/'nomount/nm_xattr.c').read_text(),'nm_activate_xattr_reads_locked').replace('kallsyms_lookup_name_by_suffix(', 'acl_lookup(')
  source=source.replace(function(source,'nm_activate_xattr_reads_locked'),PRE+'\n#undef CONFIG_KPM_BASELINES\n'+new+'\n#define CONFIG_KPM_BASELINES 1',1);assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
  source=source.replace('int main(void){nm_xattr_resident=true;', 'static int previous_acl_main(void){nm_xattr_resident=true;',1);source+=TEST+'\nint main(void){assert(!previous_acl_main());check_acl_reads();return 0;}\n'
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log');run([str((out/'contracts').resolve())],out/'run.log');rows.append({'abi':abi,'prior_assert_sites':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',source))-len(before),'result':'PASS'})
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer SDK callback-argument and dynamic factory fixture; no native ACL conversion/permissions/syscall proof','results':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
