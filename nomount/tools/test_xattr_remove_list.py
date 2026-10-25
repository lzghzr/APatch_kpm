#!/usr/bin/env python3
"""保留1666处Oracle，真实窗口推导 + 原生list源码片段 + 宿主文件xattr。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <sys/xattr.h>
static unsigned char*xf_image,*xf_original;static size_t xf_size;
static bool xf_enabled,xf_alias,xf_has_acl;static const char*xf_missing;
static unsigned xf_queries,xf_wraps,xf_count,xf_fail_wrap;
static int xf_mode,xf_btf_error;static bool xf_unavailable;
static struct{void*target;void*before;int count;}xf_hooks[3];
static uintptr_t xf_lookup(const char*n){xf_queries++;if(!xf_enabled||(xf_missing&&!strcmp(n,xf_missing)))return 0;
 if(xf_has_acl&&!strcmp(n,"vfs_remove_acl"))return 0x7000;
 if(xf_alias&&!strcmp(n,"listxattr"))return (uintptr_t)(xf_image+xf_offsets[0]);
 for(unsigned i=0;i<XF_NAMES;i++)if(!strcmp(n,xf_names[i]))return (uintptr_t)(xf_image+xf_offsets[i]);return 0;}
static int calculate_btf_xattr_remove(int context,bool*unavailable){*unavailable=xf_unavailable;return xf_mode?xf_btf_error:-ENODATA;}
static int calculate_btf_xattr_internal_list(bool*unavailable){*unavailable=xf_unavailable;return xf_mode?xf_btf_error:-ENODATA;}
static int calculate_btf_xattr_remove_acl(int context,bool*unavailable){*unavailable=xf_unavailable;return xf_mode?(xf_btf_error?xf_btf_error:xf_has_acl?1:0):-ENODATA;}
static hook_err_t xf_wrap(void*t,int n,void*b,void*a,void*u){
 xf_wraps++;if(xf_fail_wrap==(int)xf_wraps)return -1;
 if(xf_count>=3||(n!=2&&n!=3)||a||u)return -1;xf_hooks[xf_count++]=(typeof(xf_hooks[0])){t,b,n};return 0;}
'''
NATIVE=r'''
static int xf_fd,xf_lsm_error,xf_copy_error;static bool xf_cap_admin;
static struct dentry*xf_source;static unsigned xf_lsm_calls,xf_native_removes,xf_allocs,xf_copies;
static ssize_t xf_host_list(char*b,size_t n){
#ifdef __APPLE__
 ssize_t rc=flistxattr(xf_fd,b,n,0);
#else
 ssize_t rc=flistxattr(xf_fd,b,n);
#endif
 return rc<0?-errno:rc;}
static int xf_host_set(const char*n,const char*v){
#ifdef __APPLE__
 return fsetxattr(xf_fd,n,v,strlen(v),0,0);
#else
 return fsetxattr(xf_fd,n,v,strlen(v),0);
#endif
}
static ssize_t xf_host_get(const char*n,char*b,size_t size){
#ifdef __APPLE__
 ssize_t rc=fgetxattr(xf_fd,n,b,size,0,0);
#else
 ssize_t rc=fgetxattr(xf_fd,n,b,size);
#endif
#ifdef ENOATTR
 if(rc<0&&errno==ENOATTR)return -ENODATA;
#endif
 return rc<0?-errno:rc;}
static int xf_native_remove(struct dentry*d,const char*n){
 assert(d==xf_source);xf_native_removes++;
 if(!strncmp(n,"trusted.",8)&&!xf_cap_admin)return -EPERM;
 xf_lsm_calls++;if(xf_lsm_error)return xf_lsm_error;
#ifdef __APPLE__
 int rc=fremovexattr(xf_fd,n,0);
#else
 int rc=fremovexattr(xf_fd,n);
#endif
#ifdef ENOATTR
 if(rc<0&&errno==ENOATTR)return -ENODATA;
#endif
 return rc<0?-errno:0;}
static ssize_t xf_fs_list(struct dentry*d,char*b,size_t n){assert(d==xf_source);return xf_host_list(b,n);}
static ssize_t(*xf_list_op(struct inode*i))(struct dentry*,char*,size_t){return nm_operation_callback(nm_inode_ops(i),136);}
static int xf_security_list(struct dentry*d){if(((struct nm_inode_owner_prefix*)nm_dentry_inode(d))->i_flags&512)return 0;xf_lsm_calls++;return xf_lsm_error;}
static ssize_t xf_listsecurity(struct inode*i,char*b,size_t n){return ((struct nm_inode_owner_prefix*)i)->i_flags&512?0:xf_host_list(b,n);}
static void*xf_alloc(size_t n,int flags){xf_allocs++;return malloc(n);}
static int xf_copy_user(void*d,const void*s,size_t n){xf_copies++;if(xf_copy_error)return 1;memcpy(d,s,n);return 0;}
#ifndef IOP_XATTR
#define IOP_XATTR XF_IOP_XATTR
#endif
#define XATTR_LIST_MAX 65536
'''
TEST=r'''
static void xf_reset(void){
 memcpy(xf_image,xf_original,xf_size);xf_enabled=true;xf_missing=NULL;xf_alias=false;
 xf_has_acl=false;xf_mode=0;xf_unavailable=true;xf_btf_error=0;xf_wraps=xf_count=xf_fail_wrap=0;
 nm_xattr_resident=nm_xattr_reads_ready=nm_xattr_writes_ready=true;
 nm_xattr_extra_ready=nm_xattr_remove_installed=nm_xattr_internal_list_installed=nm_xattr_remove_acl_installed=false;
 nm_xattr_remove_target=nm_xattr_internal_list_target=nm_xattr_remove_acl_target=NULL;
 nm_xattr_set_context=0;nm_xattr_write_status=0;nm_xattr_write_readonly=xw_readonly;
 nm_setattr_status=0;nm_setattr_layout=(struct nm_setattr_layout){160,1,112,0};
 struct_offset.getattr_context_kind=0;struct_offset.permission_abi=0;
 nm_xattr_get_target=(void*)0x1000;nm_xattr_list_target=(void*)0x2000;nm_xattr_set_target=(void*)0x5000;
 nm_xattr_set_acl_target=nm_xattr_acl_target=NULL;
}
static int xf_remove_derive(void){return calculate_function_xattr_remove(0,&nm_setattr_layout);}
static void check_xattr_extra_proofs(void){
 xf_reset();unsigned*flag_words=(void*)(xf_image+xf_offsets[6]);
 assert(nm_load(flag_words[64],1,23)&&inst_get_ldr_imm_rt(flag_words[64])==9&&inst_get_ldr_imm_imm(flag_words[64])==offsetof(struct nm_inode_owner_prefix,i_opflags));
 assert(inst_is_tbnz(flag_words[65])&&inst_get_tbnz_rt(flag_words[65])==9&&(1U<<inst_get_tbnz_bit(flag_words[65]))==XF_IOP_XATTR);
 assert(!xf_remove_derive());assert(!calculate_function_xattr_internal_list(0));
 assert(!nm_activate_xattr_extra_locked()&&nm_xattr_extra_ready&&xf_count==2&&xf_hooks[0].count==3&&xf_hooks[1].count==2);
 assert(!nm_activate_xattr_extra_locked()&&xf_wraps==2);
 unsigned*r=(void*)(xf_image+xf_offsets[0]);unsigned*l=(void*)(xf_image+xf_offsets[1]);
 unsigned*s=(void*)(xf_image+xf_offsets[2]);unsigned*q=(void*)(xf_image+xf_offsets[6]);
 unsigned*ls=(void*)(xf_image+xf_offsets[7]);
 const unsigned critical[]={8,9,12,13,14,20,21,22,23,24,25,27,28};
 for(unsigned i=0;i<sizeof(critical)/sizeof(*critical);i++){xf_reset();r[critical[i]]=0;assert(xf_remove_derive()<0);}
 for(unsigned i=0;i<16;i++){xf_reset();l[i]=0;assert(xf_remove_derive()<0);}
 for(unsigned i=0;i<9;i++){xf_reset();s[i]=0;assert(xf_remove_derive()<0);}
 for(unsigned i=0;i<25;i++){xf_reset();q[i]=0;assert(calculate_function_xattr_internal_list(0)<0);}
 for(unsigned i=0;i<9;i++){xf_reset();ls[i]=0;assert(calculate_function_xattr_internal_list(0)<0);}
 xf_reset();r[12]+=8U<<10;assert(xf_remove_derive()<0);
 xf_reset();l[5]+=8U<<10;assert(xf_remove_derive()<0);
 xf_reset();r[22]=0xaa0303e2U;assert(xf_remove_derive()<0); // 原生delegation输出必须来自sp。
 xf_reset();l[11]=il_bl((uintptr_t)&l[11],(uintptr_t)(xf_image+xf_offsets[2]));assert(xf_remove_derive()<0);
 xf_reset();nm_setattr_layout.lock_offset=168;assert(xf_remove_derive()==-EINVAL);
 xf_reset();assert(calculate_function_xattr_remove(1,&nm_setattr_layout)==-EOPNOTSUPP);
 assert(calculate_function_xattr_remove(2,&nm_setattr_layout)==-EOPNOTSUPP);
 assert(calculate_function_xattr_internal_list(1)==-EOPNOTSUPP);
 for(unsigned i=0;i<XF_NAMES;i++){
  xf_reset();xf_missing=xf_names[i];assert(nm_activate_xattr_extra_locked()<0&&!nm_xattr_extra_ready&&!xf_count);
 }
 xf_reset();xf_alias=true;assert(nm_activate_xattr_extra_locked()==-EINVAL&&!xf_count);
 xf_reset();xf_mode=1;xf_unavailable=false;xf_btf_error=-EINVAL;
 assert(nm_activate_xattr_extra_locked()==-EINVAL&&!xf_count);
 xf_reset();xf_unavailable=false;assert(nm_activate_xattr_extra_locked()==-ENODATA&&!xf_count);
 xf_reset();xf_fail_wrap=1;assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&!xf_count&&!nm_xattr_extra_ready);
 xf_reset();xf_fail_wrap=2;assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&xf_count==1&&!nm_xattr_extra_ready);
 xf_fail_wrap=0;assert(!nm_activate_xattr_extra_locked()&&xf_count==2&&xf_wraps==3&&nm_xattr_extra_ready);
 // 三份实际BTF具备独立ACL删除；这里仅测试已证三参hook发布/重试，不声称4.19有此ABI。
 xf_reset();xf_has_acl=true;assert(nm_activate_xattr_extra_locked()==-ENODATA&&!xf_count);
 xf_reset();xf_mode=1;xf_unavailable=false;xf_has_acl=true;nm_xattr_set_context=2;xf_fail_wrap=3;
 assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&xf_count==2&&!nm_xattr_extra_ready);
 // 正在安装/失败状态：已经装上的list回调也拒绝managed，不污染参数。
 _Alignas(8)unsigned char d[256]={0},inode[1024]={0};nm_inode_engine.inode_ops=(void*)0x7777;
 nm_inode_objects(inode)->i_op=nm_inode_engine.inode_ops;((struct nm_dentry_head*)d)->d_inode=(void*)inode;
 hook_fargs3_t a={.arg0=(uintptr_t)d,.arg1=0x1234,.arg2=7};nm_xattr_extra_ready=false;nm_xattr_internal_list3(&a,NULL);
 assert(a.skip_origin&&(long)a.ret==-EOPNOTSUPP&&a.arg0==(uintptr_t)d&&a.arg1==0x1234&&a.arg2==7);
 hook_fargs3_t pending={.arg0=0x1234,.arg1=(uintptr_t)d,.arg2=(uintptr_t)"user.test"};nm_xattr_remove_mapped(&pending,NULL);
 assert(pending.skip_origin&&(long)pending.ret==-EOPNOTSUPP&&pending.arg0==0x1234&&pending.arg1==(uintptr_t)d);
 xf_fail_wrap=0;assert(!nm_activate_xattr_extra_locked()&&xf_count==3&&xf_hooks[2].count==3&&nm_xattr_remove_acl_installed);
 nm_inode_engine=(struct nm_inode_engine){0};
 xf_reset();struct nm_topology_leaf*leaves=nm_topology_leaves;struct mutex*saved_lock=nm_management_mutex;nm_management_mutex=(void*)0x1234;
 control_request(NM_CMD_ADD_RULE);control_append("/system/xf",NULL,NM_FLAG_WHITEOUT,1000);xf_missing="listxattr";
 assert(xf_control_dynamic(&control_user,true)==-ENOENT&&control_user.status==-ENOENT&&nm_topology_leaves==leaves&&!xf_count);
 nm_management_mutex=saved_lock;
 puts("remove2 lock + independent permission/security; internal list dentry/size/security proof and refusal fixtures PASS");
}
static int xf_remove_call(struct dentry*d,void*context,const char*n){
 hook_fargs3_t a={0};unsigned at=nm_xattr_remove_context?1:0;
 a.args[at]=(uintptr_t)d;a.args[at+1]=(uintptr_t)n;if(at)a.arg0=(uintptr_t)context;
 if(at)nm_xattr_remove_mapped(&a,NULL);else nm_xattr_remove2((void*)&a,NULL);
 return a.skip_origin?(long)a.ret:xf_native_remove((void*)a.args[at],(void*)a.args[at+1]);
}
static ssize_t xf_list_call(struct dentry*d,char*b,size_t n){
 hook_fargs3_t a={.arg0=(uintptr_t)d,.arg1=(uintptr_t)b,.arg2=n};
 nm_xattr_internal_list3(&a,NULL);
 return a.skip_origin?(long)a.ret:xf_native_user_list((void*)a.arg0,(void*)a.arg1,a.arg2);
}
static unsigned xf_nameset(const char*b,size_t n){
 unsigned bits=0;for(size_t p=0;p<n;){size_t length=strlen(b+p);assert(length&&p+length<n);
  if(!strcmp(b+p,"user.test")){assert(length==9);bits|=1;}
  if(!strcmp(b+p,"security.selinux")){assert(length==16);bits|=2;}
  p+=length+1;}return bits;
}
static void check_xattr_extra_io(void){
 security_fixture_reset();security_target();security_set_sid(backing,71);
 struct nomount_rule rule={.r_path=backing_path,.refs=1};security_query(outer_root);
 assert(!nm_materialize_file(parent,(void*)outer_root,&rule,919));
 struct inode*outer=nm_dentry_inode(outer_root);struct nm_inode_info*info=nm_inode_private(outer);
 struct nm_mount_context_head mount={0};void*saved_mnt=info->r_path.mnt;info->r_path.mnt=&mount;
 _Alignas(8)unsigned char fd[768]={0};*(struct nm_path*)nm_file_path(fd)=(struct nm_path){&mount,(void*)outer_root};
 char file[]="/tmp/nomount-xattrs-XXXXXX";xf_fd=mkstemp(file);assert(xf_fd>=0);
 assert(!xf_host_set("security.selinux","u:object_r:test:s0"));assert(!xf_host_set("user.test","world_updated"));
 xf_source=backing_path.dentry;xw_source=xf_source;xw_expected_mount=(void*)&mount;
 ((struct nm_inode_owner_prefix*)backing)->i_flags&=~512U;
 ((struct nm_inode_owner_prefix*)backing)->i_opflags|=IOP_XATTR;
 const void*old_iops=nm_inode_ops(backing);_Alignas(8)unsigned char source_ops[512]={0};nm_inode_objects(backing)->i_op=source_ops;nm_set_operation_callback(source_ops,136,xf_fs_list);
 xf_lsm_error=xf_copy_error=0;xf_cap_admin=true;
 char source[512]={0},path[512]={0},held[512]={0};ssize_t need=xf_native_user_list(xf_source,NULL,0);
 assert(need>0&&need<512);assert(xf_native_user_list(xf_source,source,512)==need&&xf_nameset(source,need)==3);
 // 真实Image确认的内联调用形态：只装导出hook时内部helper仍看到虚拟inode的空表/S_PRIVATE。
 assert(xf_native_user_list((void*)outer_root,NULL,0)==0);
 xf_reset();assert(!nm_activate_xattr_extra_locked()&&xf_count==2);
 xf_allocs=xf_copies=0;
 assert(xf_list_call((void*)outer_root,NULL,0)==need&&xf_allocs==0&&xf_copies==0);
 assert(xf_list_call(nm_file_path(fd)->dentry,NULL,0)==need&&xf_allocs==0&&xf_copies==0);
 assert(xf_list_call((void*)outer_root,path,512)==need&&xf_list_call(nm_file_path(fd)->dentry,held,512)==need);
 assert(!memcmp(source,path,need)&&!memcmp(source,held,need)&&xf_nameset(path,need)==3&&xf_nameset(held,need)==3);
 memset(path,0xa5,512);assert(xf_list_call((void*)outer_root,path,1)==-ERANGE&&(unsigned char)path[0]==0xa5);
 xf_copy_error=1;assert(xf_list_call((void*)outer_root,path,512)==-EFAULT);xf_copy_error=0;
 xf_lsm_error=-EACCES;assert(xf_list_call((void*)outer_root,NULL,0)==-EACCES);xf_lsm_error=0;
 unsigned calls=xf_native_removes;mount.flags=0x40;
 assert(xf_remove_call((void*)outer_root,NULL,"user.test")==-EROFS&&xf_native_removes==calls);
 assert(xf_host_get("user.test",path,512)==13&&!memcmp(path,"world_updated",13));mount.flags=0;
 xf_cap_admin=false;assert(xf_remove_call((void*)outer_root,NULL,"trusted.test")==-EPERM);xf_cap_admin=true;
 xf_lsm_error=-EACCES;assert(xf_remove_call((void*)outer_root,NULL,"user.test")==-EACCES&&xf_host_get("user.test",path,512)==13);xf_lsm_error=0;
 assert(!xf_remove_call((void*)outer_root,NULL,"user.test"));
 assert(xf_host_get("user.test",path,512)==-ENODATA);
 assert(xf_remove_call(nm_file_path(fd)->dentry,NULL,"user.test")==-ENODATA);
 ssize_t after=xf_list_call((void*)outer_root,NULL,0);assert(after>0&&after<need);
 assert(xf_list_call(nm_file_path(fd)->dentry,held,512)==after&&xf_nameset(held,after)==2);
 // 同一宿主真实源重建属性，FD删除同样作用于源，路径重复删除仍ENODATA。
 assert(!xf_host_set("user.test","again"));assert(!xf_remove_call(nm_file_path(fd)->dentry,NULL,"user.test"));
 assert(xf_remove_call((void*)outer_root,NULL,"user.test")==-ENODATA);
 nm_xattr_set_context=nm_xattr_remove_context=1;mount.context.userns=(void*)0x1234;calls=xf_native_removes;
 assert(xf_remove_call((void*)outer_root,(void*)0x5678,"user.test")==-EXDEV&&xf_native_removes==calls);
 for(int ctx=1;ctx<=2;ctx++){
  nm_xattr_set_context=nm_xattr_remove_context=ctx;
  assert(!xf_host_set("user.test","mapped"));
  assert(!xf_remove_call(nm_file_path(fd)->dentry,(void*)0x1234,"user.test"));
  assert(xf_remove_call((void*)outer_root,(void*)0x1234,"user.test")==-ENODATA);
 }
 nm_xattr_set_context=nm_xattr_remove_context=0;
 nm_inode_objects(backing)->i_op=old_iops;info->r_path.mnt=saved_mnt;port_iput(outer);
 assert(!close(xf_fd)&&!unlink(file));xf_enabled=false;
 puts("real host xattr: inline-list reproduction, size0/bytes/items/ERANGE/EFAULT/LSM, path/FD remove/ENODATA/RO/idmap PASS");
}
'''
def native_function(source,name):
 m=re.search(r'(?m)^(?:static )?ssize_t\s*\n'+name+r'\([^;]*?\)\s*\{',source);assert m,name
 end=m.end();depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[m.start():end]
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('oracle-output','cli-source','image','reference-image','symbols','native-xattr','native-header','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);symbols={n:at for at,t,n in json.loads(a.symbols.read_text())}
 macro=re.search(r'(?m)^#define\s+IOP_XATTR\s+(0x[0-9a-fA-F]+|[0-9]+)',a.native_header.read_text());assert macro
 iop_xattr=int(macro[1],0)
 names=['vfs_removexattr','__vfs_removexattr_locked','security_inode_removexattr','xattr_permission','down_write','up_write','listxattr','security_inode_listxattr','kvmalloc_node','_stext','_etext']
 data='#define XF_IOP_XATTR '+str(iop_xattr)+'U\n'
 data+='enum{XF_NAMES='+str(len(names))+'};\nstatic const char*xf_names[]={'+','.join('"'+n+'"'for n in names)+'};\n'
 data+='static const unsigned xf_offsets[]={'+','.join(str(symbols[n])for n in names)+'};\n'
 query=(ROOT/'nomount/nm_xattr_entry_signatures.c').read_text().replace('kallsyms_lookup_name_by_suffix(', 'xf_lookup(').replace('kallsyms_lookup_name(', 'xf_lookup(')
 extra=(ROOT/'nomount/nm_xattr_extra.c').read_text().replace('kallsyms_lookup_name_by_suffix(', 'xf_lookup(').replace('hook_wrap3(', 'xf_wrap3(').replace('hook_wrap(', 'xf_wrap(')
 extra='static hook_err_t xf_wrap3(void*t,void*b,void*a,void*u){return xf_wrap(t,3,b,a,u);}\n'+extra
 native=a.native_xattr.read_text();kernel=native_function(native,'vfs_listxattr').replace('ssize_t\nvfs_listxattr','static ssize_t\nxf_inline_vfs_list').replace('d_inode(', 'nm_dentry_inode(').replace('inode->i_op->listxattr','xf_list_op(inode)').replace('inode->i_opflags','((struct nm_inode_owner_prefix*)inode)->i_opflags').replace('security_inode_listxattr(', 'xf_security_list(').replace('security_inode_listsecurity(', 'xf_listsecurity(')
 user=native_function(native,'listxattr').replace('listxattr(', 'xf_native_user_list(',1).replace('vfs_listxattr(', 'xf_inline_vfs_list(').replace('__user','').replace('kvmalloc(', 'xf_alloc(').replace('GFP_KERNEL','0').replace('copy_to_user(', 'xf_copy_user(').replace('kvfree(', 'free(')
 rows=[]
 for abi in ('int','bool'):
  original=(a.oracle_output/abi/'contracts.c').read_text();before=assertions(original);assert len(before)==1666
  write=(ROOT/'nomount/nm_xattr_write.c').read_text()
  mutation=function(write,'nm_xattr_mutate_path')+'\n'+function(write,'nm_xattr_write_path')
  source=original.replace(function(original,'nm_xattr_write_path'),mutation,1)
  marker='static void nm_control_error';assert source.count(marker)==1
  source=source.replace(marker,data+PRE+'\n'+query+'\n#undef CONFIG_KPM_BASELINES\n'+extra+'\n#define CONFIG_KPM_BASELINES 1\n'+marker,1)
  assert assertions(source)==before
  source=source.replace('int main(int argc,char**argv)','static int previous_extra_main(int argc,char**argv)',1)
  dynamic=function((ROOT/'nomount/nm_control.c').read_text(),'nm_control_rules').replace('nm_control_rules(', 'xf_control_dynamic(',1)
  source+='\n#undef CONFIG_KPM_BASELINES\n'+dynamic+'\n#define CONFIG_KPM_BASELINES 1\n'
  source+=NATIVE+kernel+'\n'+user+'\n'+TEST+r'''
int main(int argc,char**argv){
 assert(!previous_extra_main(argc,argv));FILE*f=fopen(argv[2],"rb");assert(f);assert(!fseek(f,0,SEEK_END));xf_size=ftell(f);rewind(f);
 xf_original=malloc(xf_size);xf_image=mmap(NULL,xf_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(xf_original&&xf_image!=MAP_FAILED);assert(fread(xf_original,1,xf_size,f)==xf_size);assert(!fclose(f));
 check_xattr_extra_proofs();check_xattr_extra_io();assert(!munmap(xf_image,xf_size));free(xf_original);return 0;
}
'''
  assert assertions(source)[:1666]==before
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
  run([str((out/'contracts').resolve()),str(a.reference_image.resolve()),str(a.image.resolve())],out/'run.log')
  rows.append({'abi':abi,'original_assert_sites':1666,'added_assert_sites':len(assertions(source))-1666,'total_assert_sites':len(assertions(source)),'result':'PASS'})
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer actual Image windows, original Sony list bodies with opaque-field/API adapters, host file xattrs; no ARM/LSM/device proof','IOP_XATTR_from_native_header':iop_xattr,'native_body_adapters':['d_inode/opaque inode fields -> production accessors','security/copy/allocator -> host stubs','inlined vfs body remains outside exported hook'], 'host':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
