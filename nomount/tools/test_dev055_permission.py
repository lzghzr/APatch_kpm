#!/usr/bin/env python3
"""DEV-055 DAC：保留1837处Oracle，追加原生DAC、外层LSM门控及两目标ABI证据。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run
ROOT = Path(__file__).resolve().parents[2]
PRE = r'''
static bool nm_rule_entry_save(uint32_t);
static bool nm_move32(uint32_t,int,int);
static bool nm_move(uint32_t,int,int);
static bool nm_load(uint32_t,int,int);
static bool nm_load_at(uint32_t,int,int,int);
static bool nm_zero64(uint32_t,int);
static bool nm_vfs_frame_save(uint32_t);
static bool nm_code_matches(uintptr_t,uintptr_t,uintptr_t,uintptr_t);
static int p055_generic(struct inode*,int);
static int p055_mapped(void*,struct inode*,int);
static uintptr_t p055_lookup(const char*);
static int calculate_btf_owned_permission(bool*,int*,int*);
'''
STUB = r'''
static int p055_btf_rc,p055_slot=16,p055_second=24,p055_calls,p055_mask,p055_acl_calls,p055_acl_rc=-EAGAIN;
static bool p055_unavailable,p055_missing,p055_native,p055_cap,p055_acl,p055_clear;
static unsigned p055_uid,p055_gid;static struct inode*p055_seen;static void*p055_context;
static unsigned char*p055_image;static unsigned p055_target;static size_t p055_size;
static int calculate_btf_owned_permission(bool*u,int*s,int*t){*u=p055_unavailable;*s=p055_slot;*t=p055_second;return p055_btf_rc;}
static uintptr_t p055_lookup(const char*n){
 if(p055_native){for(unsigned i=0;i<P055_NAMES;i++)if(!strcmp(n,p055_names[i]))return p055_offsets[p055_target][i]?(uintptr_t)p055_image+p055_offsets[p055_target][i]:0;return 0;}
 if(!strcmp(n,"generic_permission"))return p055_missing?0:struct_offset.permission_abi<2?(uintptr_t)p055_generic:(uintptr_t)p055_mapped;
 return 0;
}
static int p055_check_acl(struct inode*i,int m){p055_acl_calls++;p055_seen=i;return p055_acl_rc;}
#define likely(x) (x)
#define unlikely(x) (x)
#define current_fsuid() p055_uid
#define uid_eq(a,b) ((a)==(b))
#define in_group_p(g) ((g)==p055_gid)
#define IS_POSIXACL(i) p055_acl
#define capable_wrt_inode_uidgid(i,c) p055_cap
#define CAP_DAC_READ_SEARCH 2
#define CAP_DAC_OVERRIDE 1
#ifndef S_IRWXG
#define S_IRWXG 0070
#endif
#ifndef S_IXUGO
#define S_IXUGO 0111
#endif
#ifndef MAY_READ
#define MAY_READ 4
#define MAY_WRITE 2
#define MAY_EXEC 1
#endif
'''
POST = r'''
#undef current_fsuid
#undef uid_eq
#undef in_group_p
#undef IS_POSIXACL
#undef capable_wrt_inode_uidgid
static int p055_generic(struct inode*i,int m){p055_calls++;p055_seen=i;p055_mask=m;if(p055_clear)nm_inode_mmap_ready(p055_clear_inode);return p055_native_dac(i,m);}
static int p055_mapped(void*c,struct inode*i,int m){p055_context=c;return p055_generic(i,m);}
static int p055_lsm_calls,p055_outer_calls;
#define IS_PRIVATE(i) (((struct nm_inode_owner_prefix*)(i))->i_flags&512U)
#define call_int_hook(...) (++p055_lsm_calls,0)
'''
TEST = r'''
#undef IS_PRIVATE
#undef call_int_hook
static int p055_outer_permission(struct inode*i,int m){int rc=nm_permission_plain(i,m);if(rc)return rc;p055_outer_calls++;return p055_native_security(i,m);}
static void check_dev055(void){
 security_fixture_reset();security_target();p055_btf_rc=0;p055_unavailable=false;
 assert(!nm_install_owned_permissions());
 assert(nm_operation_callback(nm_inode_engine.inode_ops,16)==nm_permission_plain);
 assert(nm_operation_callback(nm_inode_engine.directory_ops,24)==nm_permission_mount);

 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100755;((struct nm_inode_owner_prefix*)backing)->i_uid=1000;((struct nm_inode_owner_prefix*)backing)->i_gid=1000;
 nm_inode_objects(backing)->i_op=native_iops;nm_set_operation_callback(native_iops,16,NULL);nm_set_operation_callback(native_iops,24,NULL);
 struct nomount_rule rule={.r_path=backing_path,.refs=1};security_query(outer_root);
 assert(!nm_materialize_file(parent,(void*)outer_root,&rule,955));struct inode*i=nm_dentry_inode(outer_root);struct nm_inode_info*info=nm_inode_private(i);
 assert(i&&info&&info->initialized&&!info->init_error);
 p055_uid=1000;p055_gid=2000;p055_calls=p055_acl_calls=0;p055_cap=p055_acl=false;
 assert(!nm_permission_plain(i,1)&&p055_seen==backing&&p055_calls==1&&p055_mask==1);
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100700;((struct nm_inode_owner_prefix*)backing)->i_uid=2000;
 assert(nm_inode_mode(i)==0100755&&nm_permission_plain(i,1)==-EACCES&&p055_seen==backing);
 p055_cap=true;assert(!nm_permission_plain(i,1));p055_cap=false;
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100750;((struct nm_inode_owner_prefix*)backing)->i_gid=p055_gid;
 assert(!nm_permission_mount(NULL,i,1));p055_gid=3000;
 assert(nm_permission_plain(i,1)==-EACCES);
 p055_acl=true;p055_acl_rc=0;assert(!nm_permission_plain(i,1)&&p055_acl_calls&&p055_seen==backing);
 p055_acl_rc=-EACCES;assert(nm_permission_plain(i,1)==-EACCES);p055_acl_rc=-EIO;assert(nm_permission_plain(i,1)==-EIO);
 p055_acl=false;((struct nm_inode_owner_prefix*)backing)->i_mode=0100755;
 int calls=p055_calls;assert(nm_permission_plain(NULL,0x80)==-ECHILD&&p055_calls==calls);
 assert(nm_permission_plain(i,0x81)==-ECHILD&&p055_calls==calls);
 assert(nm_permission_plain(NULL,1)==-EINVAL&&p055_calls==calls);
 void*d=info->r_path.dentry;void*m=info->r_path.mnt;info->r_path.dentry=NULL;
 assert(nm_permission_plain(i,1)==-EIO&&p055_calls==calls);
 info->flags|=NM_FLAG_VIRTUAL_DIR;assert(nm_permission_plain(i,1)==-EIO&&p055_calls==calls);
 info->r_path.mnt=NULL;assert(!nm_permission_plain(i,1)&&p055_seen==i);info->flags&=~NM_FLAG_VIRTUAL_DIR;info->r_path.dentry=d;
 calls=p055_calls;assert(nm_permission_plain(i,1)==-EIO&&p055_calls==calls);info->r_path.mnt=m;
 info->initialized=false;assert(nm_permission_plain(i,1)==-EIO&&p055_calls==calls);info->initialized=true;
 info->init_error=-EIO;assert(nm_permission_plain(i,1)==-EIO&&p055_calls==calls);info->init_error=0;
 ((struct nm_dentry_head*)d)->d_inode=i;assert(nm_permission_plain(i,1)==-ELOOP&&p055_calls==calls);((struct nm_dentry_head*)d)->d_inode=backing;
 nm_set_operation_callback(native_iops,16,(void*)0x1234);assert(nm_permission_plain(i,1)==-EOPNOTSUPP&&p055_calls==calls);
 nm_set_operation_callback(native_iops,16,p055_generic);assert(!nm_permission_plain(i,1)&&p055_calls==calls+1);
 nm_set_operation_callback(native_iops,24,(void*)0x2340);calls=p055_calls;assert(nm_permission_plain(i,1)==-EOPNOTSUPP&&p055_calls==calls);
 nm_set_operation_callback(native_iops,16,NULL);nm_set_operation_callback(native_iops,24,NULL);
 // mapped wrapper只验证生产转交的源context，不把宿主plain DAC算作idmap语义模拟。
 struct nm_mount_context_head mapped={0};void*source_context=(void*)0xabcd; mapped.context.userns=source_context;info->r_path.mnt=(void*)&mapped;
 for(int abi=2;abi<=3;abi++){struct_offset.permission_abi=abi;p055_second=-1;assert(!nm_install_owned_permissions());p055_context=NULL;
  assert(!nm_owned_permission((void*)0x9876,i,1)&&p055_context==source_context&&p055_seen==backing);
  mapped.context.userns=NULL;calls=p055_calls;assert(nm_owned_permission((void*)0x9876,i,1)==-EINVAL&&p055_calls==calls);mapped.context.userns=source_context;
 }
 info->r_path.mnt=m;struct_offset.permission_abi=0;p055_second=24;assert(!nm_install_owned_permissions());
 // 每次只走唯一外层security入口；用真实security函数体及生产清位函数验证交错。
 p055_lsm_calls=p055_outer_calls=0;((struct nm_inode_owner_prefix*)i)->i_flags|=512;
 assert(!p055_outer_permission(i,1)&&p055_outer_calls==1&&p055_lsm_calls==0);
 nm_inode_mmap_ready(i);assert(!p055_outer_permission(i,1)&&p055_outer_calls==2&&p055_lsm_calls==1);
 ((struct nm_inode_owner_prefix*)i)->i_flags|=512;p055_clear_inode=i;p055_clear=true;
 assert(!p055_outer_permission(i,1)&&p055_outer_calls==3&&p055_lsm_calls==2);p055_clear=false;
 assert(!(((struct nm_inode_owner_prefix*)i)->i_flags&512));
 port_iput(i);drain();nm_discard_directory_view();
 // 证据冲突/缺失不安装任何权限槽；完整prepare仍保留原有核心能力。
 security_fixture_reset();security_target();p055_btf_rc=-EINVAL;
 assert(nm_install_owned_permissions()==-EINVAL&&!nm_operation_callback(nm_inode_engine.inode_ops,16));
 p055_btf_rc=0;p055_missing=true;assert(nm_install_owned_permissions()==-ENOENT&&!nm_operation_callback(nm_inode_engine.inode_ops,16));p055_missing=false;
 p055_slot=9999;assert(nm_install_owned_permissions()==-EINVAL);p055_slot=16;
 int slot=-1,second=-1;struct_offset.permission_abi=0;struct_offset.getattr_context_kind=0;
 struct_offset.iop_getattr=offsetof(struct nm_inode_follow_prefix,getattr);assert(!nm_common_owned_permission(&slot,&second)&&slot==16&&second==24);
 struct_offset.iop_getattr=offsetof(struct nm_inode_android_link_prefix,getattr);assert(!nm_common_owned_permission(&slot,&second)&&slot==16&&second==24);
 struct_offset.permission_abi=1;struct_offset.iop_getattr=offsetof(struct nm_inode_plain_link_prefix,getattr);assert(!nm_common_owned_permission(&slot,&second)&&slot==16&&second==-1);
 struct_offset.getattr_context_kind=1;assert(nm_common_owned_permission(&slot,&second)==-EOPNOTSUPP);struct_offset.getattr_context_kind=0;
 struct_offset.iop_getattr=99;assert(nm_common_owned_permission(&slot,&second)==-EOPNOTSUPP);
 nm_discard_directory_view();puts("DEV-055 DAC: retained source mode/owner/group, native generic DAC with ACL dependency, mapped source argument, RCU/unknown/recursive rejection, outer LSM 0/1 and mmap interleave PASS");
}
static void check_dev055_prepare(void){
 for(unsigned failure=0;failure<2;failure++){
  cold_reset();p055_btf_rc=failure?-EINVAL:0;p055_slot=16;p055_second=24;p055_missing=p055_unavailable=false;
  assert(!cold_nomount_init(NULL,"post-fs-data",NULL)&&cold_initialized&&nm_registered_key_type);
  assert(nm_inode_engine.lookup_backing&&nm_backing_open_permission&&nm_backing_write_open_permission);
  assert(nm_operation_callback(nm_inode_engine.inode_ops,16)==(failure?NULL:(void*)nm_permission_plain));
  assert(nm_operation_callback(nm_inode_engine.directory_ops,24)==(failure?NULL:(void*)nm_permission_mount));
  fixture_end_registration();cold_initialized=false;nm_discard_directory_view();
 }
 p055_btf_rc=0;puts("DEV-055 actual dynamic cold initialization installs file/dir permission before publication; unavailable capability retains core PASS");
}
static void check_dev055_native(const char*path,unsigned target){
 FILE*f=fopen(path,"rb");assert(f);fseek(f,0,SEEK_END);p055_size=ftell(f);rewind(f);p055_image=malloc(p055_size);assert(p055_image&&fread(p055_image,1,p055_size,f)==p055_size);fclose(f);
 p055_native=true;p055_target=target;struct_offset.permission_abi=0;struct_offset.getattr_context_kind=0;
 assert(!nm_confirm_generic_dac_abi());
 uintptr_t entry=p055_lookup(target?"__inode_permission2":"inode_permission2"),g=p055_lookup("generic_permission"),start=p055_lookup("_stext"),end=p055_lookup("_etext");
 unsigned*words=(void*)entry;unsigned count=target?39:13;
 assert(nm_find_generic_dac_call(words,count-1,target,g,start,end)==-ENODATA);
 const unsigned indices0[]={0,1,2,3,4,5,6,7,8,9,10,11,12};const unsigned indices1[]={0,1,2,3,4,5,6,7,11,12,36,37,38};
 const unsigned*indices=target?indices1:indices0;
 for(unsigned j=0;j<13;j++){unsigned at=indices[j],saved=words[at];words[at]=0;assert(nm_confirm_generic_dac_abi()<0);words[at]=saved;}
 assert(nm_find_generic_dac_call(words,count,target,g+4,start,end)==-EOPNOTSUPP);
 assert(!nm_confirm_generic_dac_abi());p055_native=false;free(p055_image);p055_image=NULL;
 puts(target?"B2N 39-word bounded generic DAC argument path PASS":"Sony 13-word bounded generic DAC argument path PASS");
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('oracle-output','reference-image','cli-source','image','symbols','legacy-image','legacy-symbols','native-namei','native-security','output'):
  p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 names=['inode_permission2','__inode_permission2','generic_permission','_stext','_etext']
 maps=[]
 for path in (a.symbols,a.legacy_symbols):
  raw=json.loads(path.read_text());s=raw if isinstance(raw,dict) else {n:at for at,_,n in raw};maps.append([s.get(n,0) for n in names])
 data='#define P055_NAMES 5\nstatic const char*p055_names[]={'+','.join(json.dumps(n) for n in names)+'};\nstatic uintptr_t p055_offsets[2][5]='+json.dumps(maps).replace('[','{').replace(']','}')+';\n'
 native=a.native_namei.read_text();native=native.replace('int generic_permission(', 'static int generic_permission(',1)
 dac='\n'.join(function(native,n)for n in ('acl_permission_check','generic_permission'))
 dac=dac.replace('acl_permission_check','p055_acl_permission_check').replace('generic_permission','p055_native_dac').replace('check_acl(', 'p055_check_acl(')
 dac=dac.replace('inode->i_mode','nm_inode_mode(inode)').replace('inode->i_uid','((struct nm_inode_owner_prefix*)inode)->i_uid').replace('inode->i_gid','((struct nm_inode_owner_prefix*)inode)->i_gid')
 security=function(a.native_security.read_text().replace('int security_inode_permission(', 'static int security_inode_permission(',1),'security_inode_permission').replace('security_inode_permission','p055_native_security')
 offsets=(ROOT/'nomount/nm_offsets.c').read_text()
 common='\n'.join(function(offsets,n)for n in ('calculate_function_permission_abi_legacy','calculate_function_permission_abi')).replace('kallsyms_lookup_name_by_suffix(', 'p055_lookup(').replace('kallsyms_lookup_name(', 'p055_lookup(')
 shape=common+'\n'+(ROOT/'nomount/nm_permission_shape.c').read_text();body=(ROOT/'nomount/nm_permission.c').read_text().replace('#include "nm_permission_shape.c"',shape)
 body=body.replace('kallsyms_lookup_name_by_suffix(', 'p055_lookup(').replace('kallsyms_lookup_name(', 'p055_lookup(')
 prepare=function((ROOT/'nomount/nm_backing_inode.c').read_text(),'nm_prepare_backing_inode_engine')
 rows=[]
 for abi in ('int','bool'):
  original=(a.oracle_output/abi/'contracts.c').read_text();old=assertions(original);assert len(old)==1837
  source=original.replace(function(original,'nm_prepare_backing_inode_engine'),PRE+'\n#undef CONFIG_KPM_BASELINES\n'+body+'\n#define CONFIG_KPM_BASELINES 1\n'+prepare,1)
  cold=prepare.replace('nm_prepare_backing_inode_engine(', 'cold_nm_prepare_backing_inode_engine(',1).replace('nm_prepare_backing_inode_functions(', 'cold_nm_prepare_backing_inode_functions(')
  at=cold.index('{')+1;cold=cold[:at]+'\n cold_note("nm_prepare_backing_inode_engine");'+cold[at:]
  source=source.replace(function(source,'cold_nm_prepare_backing_inode_engine'),cold,1)
  assert assertions(source)==old
  source=source.replace('int main(int argc,char**argv)', 'static int previous_dev055_main(int argc,char**argv)',1)
  source+='\n'+data+STUB+dac+'\nstatic struct inode*p055_clear_inode;\n'+POST+security+TEST
  source+='\nint main(int argc,char**argv){assert(!previous_dev055_main(3,argv));check_dev055();check_dev055_prepare();check_dev055_native(argv[2],0);check_dev055_native(argv[3],1);return 0;}\n'
  assert assertions(source)[:1837]==old
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
  run([str((out/'contracts').resolve()),str(a.reference_image.resolve()),str(a.image.resolve()),str(a.legacy_image.resolve())],out/'run.log')
  rows.append({'abi':abi,'unchanged_assert_sites':1837,'added_assert_sites':len(assertions(source))-1837,'total_assert_sites':len(assertions(source)),'result':'PASS'})
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer production callbacks; actual native generic/security bodies with ACL/capability dependencies stubbed; source-context argument forwarding; selected target bytes; no native syscall/CFI/parallel-kernel proof','migrations':[],'host':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
