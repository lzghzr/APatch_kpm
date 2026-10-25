#!/usr/bin/env python3
"""DEV-061：保留1794处Oracle，核验确定不可用降级与真实错误阻断。"""
import argparse
import json
from pathlib import Path
import subprocess
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
TEST = r'''
static void dev061_unavailable(void){
 xf_reset();nm_setattr_status=-EOPNOTSUPP;nm_setattr_derivation_status=-EOPNOTSUPP;
 // 真实故障条件的状态注入：无BTF+未证源锁，不构造新内核ABI。
 xs_enabled=false;xw_reset(0,false);xw_btf_missing=true;nm_setattr_status=-EOPNOTSUPP;
 nm_xattr_reads_ready=true;
 struct_offset.permission_abi=0;struct_offset.iop_getattr=offsetof(struct nm_inode_follow_prefix,getattr);
}
static void check_dev061(void){
 for(unsigned i=0;i<4;i++){
  const int errors[]={-EOPNOTSUPP,-ENOENT,-EINVAL,-EIO};sa_ready(0);dev061_lock_result=errors[i];
  assert(!dev061_prepare_result()&&nm_setattr_status==-EOPNOTSUPP&&nm_setattr_derivation_status==errors[i]);
 }
 security_fixture_reset();security_target();
 assert(!nm_prepare_topology_functions());
 nm_inode_objects(parent)->i_op=native_iops;
 *(const void**)((char*)parent+struct_offset.inode_file_ops)=native_fops;
 nm_set_operation_callback(native_fops,struct_offset.fop_iterate_shared,port_iterate);
 ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;
 ((struct nm_dentry_head*)root_dentry)->d_inode=parent;
 dev061_unavailable();
 assert(dev061_previous_extra()==-EOPNOTSUPP&&!nm_xattr_extra_ready&&!xf_count);
 assert(!nm_activate_xattr_writes_locked()&&nm_xattr_writes_ready&&nm_xattr_write_status==-EOPNOTSUPP&&xw_count==1);
 assert(!nm_activate_xattr_extra_locked()&&!nm_xattr_extra_ready&&!xf_count&&!nm_xattr_remove_target);
 unsigned wraps=xf_wraps;
 assert(!nm_activate_xattr_extra_locked()&&xf_wraps==wraps&&!nm_xattr_extra_ready);
 // 同一真实控制函数：读/写激活→extra能力判定→发布拓扑，不跳过中间层。
 struct mutex*saved_lock=nm_management_mutex;nm_management_mutex=(void*)1;
 kf_nm_mutex_lock=control_lock;kf_nm_mutex_unlock=control_unlock;
 kf_nm_kern_path=control_path;kf_nm_path_put=tree_put;
 set_uid(1000);thread.flags=0;
 control_request(NM_CMD_ADD_RULE);control_append("/system/app/dev061","/file",0,1000);
 int addrc=xf_control_dynamic(&control_user,true);fprintf(stderr,"DEV-061 ADD rc=%d status=%d\n",addrc,control_user.status);
 assert(!addrc&&!control_user.status&&control_user.arg1==control_user.data_size);
 struct nm_topology_leaf*entry=nm_topology_find("/system/app/dev061",strlen("/system/app/dev061"));
 assert(entry&&nm_select_rule(entry->leaf,1000)->r_path.dentry==tree_dentry[6]);
 control_request(NM_CMD_GET_LIST);assert(!nm_control_list(&control_user)&&control_count()==1);
 struct nm_topology_updates updates={0};
 nm_management_lock();
 assert(!nm_topology_remove_scope_locked("/system/app/dev061",strlen("/system/app/dev061"),1000,1000,0,0,&updates));
 nm_management_unlock();
 nm_finish_topology_updates(&updates);drain();flush_rcu();
 assert(!nm_topology_leaves&&!manager_depth);
 // 源锁能力不可用时，物化/读打开/read_iter仍可用；写入口保持拒绝。
 nm_discard_directory_view();security_fixture_reset();security_target();security_set_sid(backing,71);
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;
 struct nomount_rule rule={.r_path=backing_path,.refs=1};security_query(outer_root);
 assert(!nm_materialize_file(parent,(void*)outer_root,&rule,961));
 struct inode*outer=nm_dentry_inode(outer_root);
 assert(outer&&nm_is_file_inode(outer)&&((struct nm_inode_info*)nm_inode_private(outer))->r_path.dentry==backing_path.dentry);
 kf_nm_dentry_open=binding_open;kf_nm_fput=binding_fput;nm_backing_open_permission=binding_permission;
 memset(outer_file,0,sizeof(outer_file));((struct nm_file_inode_ops*)(outer_file+struct_offset.file_inode_ops))->f_inode=outer;
 *(void**)(outer_file+struct_offset.file_cred)=(void*)0xabc;
 assert(!nm_open(outer,(void*)outer_file));
 ((struct nm_file_inode_ops*)(native_regular_file+struct_offset.file_inode_ops))->f_op=native_fops;
 ((struct nm_file_io_ops*)native_fops)->read_iter=port_read;
 struct nm_kiocb_head request={.ki_filp=(void*)outer_file};
 assert(nm_read_iter((void*)&request,(void*)0xbeef)==17&&request.ki_filp==(void*)outer_file&&request.ki_pos==17);
 assert(!nm_release(outer,(void*)outer_file)&&!nm_file_private(outer_file));
 unsigned char before[768];memcpy(before,backing,sizeof(before));unsigned native=xw_native_calls;
 assert(xw_set((void*)outer_root,NULL,"user.test","blocked",7,0,false)==-EOPNOTSUPP&&xw_native_calls==native);
 assert(!memcmp(before,backing,sizeof(before)));
 struct nm_iattr_head mode={1};assert(nm_setattr((void*)outer_root,&mode)==-EOPNOTSUPP);
 hook_fargs2_t removal={.arg0=(uintptr_t)outer_root,.arg1=(uintptr_t)"user.test"};nm_xattr_remove2(&removal,NULL);
 assert(removal.skip_origin&&(long)removal.ret==-EOPNOTSUPP&&removal.arg0==(uintptr_t)outer_root);
 assert(!memcmp(before,backing,sizeof(before)));
 assert(!nm_operation_callback(nm_inode_ops(outer),DEV061_REMOVE_SLOT));
 assert(dev061_native_remove_guard((void*)outer_root,"user.test")==-EOPNOTSUPP);
 assert(dev061_native_remove_guard((void*)outer_root,"security.selinux")==-EOPNOTSUPP);
 // 未安装删除hook时，本目标族原生removexattr在NULL操作槽直接拒绝（见报告源码依据）。
 // 不把直接调用未发布hook当作真实系统调用证据。
 port_iput(outer);drain();nm_backing_open_permission=NULL;nm_discard_directory_view();
 for(unsigned i=0;i<3;i++){
  const int errors[]={-EINVAL,-EIO,-ENOENT};dev061_unavailable();nm_setattr_status=errors[i];
  assert(nm_activate_xattr_extra_locked()==errors[i]&&!nm_xattr_extra_ready&&!xf_count);
 }
 for(unsigned i=0;i<4;i++){
  const int errors[]={-EINVAL,-EIO,-ENODATA,0};dev061_unavailable();nm_setattr_derivation_status=errors[i];
  assert(nm_activate_xattr_extra_locked()==(errors[i]?errors[i]:-EINVAL)&&!xf_count);
 }
 dev061_unavailable();nm_setattr_derivation_status=-ENOENT;
 assert(!nm_activate_xattr_extra_locked()&&!nm_xattr_extra_ready&&!xf_count);
 dev061_unavailable();xf_mode=1;xf_unavailable=false;xf_btf_error=-EINVAL;
 assert(nm_activate_xattr_extra_locked()==-EINVAL&&!xf_count);
 dev061_unavailable();xf_unavailable=false;
 assert(nm_activate_xattr_extra_locked()==-ENODATA&&!xf_count);
 dev061_unavailable();xf_mode=1;xf_unavailable=false;xf_btf_error=-EOPNOTSUPP;
 assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&!xf_count);
 dev061_unavailable();struct_offset.permission_abi=1;struct_offset.iop_getattr=offsetof(struct nm_inode_plain_link_prefix,getattr);
 assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&!xf_count);
 dev061_unavailable();struct_offset.iop_getattr=offsetof(struct nm_inode_android_link_prefix,getattr);
 assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&!xf_count);
 dev061_unavailable();xf_has_acl=true;
 assert(nm_activate_xattr_extra_locked()==-EOPNOTSUPP&&!xf_count);
 dev061_unavailable();xf_alias=true;
 assert(nm_activate_xattr_extra_locked()==-EINVAL&&!xf_count);
 dev061_unavailable();xf_missing="listxattr";
 assert(nm_activate_xattr_extra_locked()==-ENOENT&&!xf_count);
 dev061_unavailable();xf_mode=1;xf_unavailable=false;xf_btf_error=-EINVAL;
 struct nm_topology_leaf*leaves=nm_topology_leaves;
 control_request(NM_CMD_ADD_RULE);control_append("/system/app/dev061-error",NULL,NM_FLAG_WHITEOUT,1000);
 assert(xf_control_dynamic(&control_user,true)==-EINVAL&&control_user.status==-EINVAL&&nm_topology_leaves==leaves);
 xf_enabled=false;nm_management_mutex=saved_lock;
 puts("DEV-061: unavailable extra permits ADD/read, writes closed; conflicts/missing/invalid BTF still abort PASS");
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output','cli-source','reference-image','image','native-xattr','native-header','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    current=function((ROOT/'nomount/nm_xattr_extra.c').read_text(),'nm_activate_xattr_extra_locked')
    current=current.replace('kallsyms_lookup_name_by_suffix(', 'xf_lookup(').replace('hook_wrap3(', 'xf_wrap3(').replace('hook_wrap(', 'xf_wrap(')
    # 只执行真实4.4源码的NULL-op早退前缀，后段以到达标记返回0；不模拟后续原生权限/LSM。
    native=a.native_xattr.read_text()
    import re
    match=re.search(r"int\s*\nvfs_removexattr\(struct dentry \*dentry, const char \*name\)\s*\{",native)
    assert match
    prefix=native[match.start():native.index('error = xattr_permission',match.end())]
    prefix=prefix.replace('vfs_removexattr(', 'dev061_native_remove_guard(',1)
    prefix='static '+prefix.replace('dentry->d_inode','nm_dentry_inode(dentry)').replace('inode->i_op->removexattr','nm_operation_callback(nm_inode_ops(inode),DEV061_REMOVE_SLOT)')+'return 0; }\n'
    declaration=a.native_header.read_text().split('struct inode_operations {',1)[1].split('} ____cacheline_aligned;',1)[0]
    members=re.findall(r'\(\s*\*\s*(\w+)\s*\)',declaration)
    assert members[:3]==['lookup','follow_link','permission'] and members.count('removexattr')==1
    prefix='#define DEV061_REMOVE_SLOT '+str(8*members.index('removexattr'))+'\n'+prefix
    rows=[]
    for abi in ('int','bool'):
        original=(a.oracle_output/abi/'contracts.c').read_text();before=assertions(original);assert len(before)==1794
        setter=function((ROOT/'nomount/nm_setattr.c').read_text(),'nm_prepare_setattr')
        updated=original.replace(function(original,'nm_prepare_setattr'),'static int nm_setattr_derivation_status=-ENODATA;\n'+setter,1)
        for name,btf,lookup in [('il_prepare','il_btf','il_runtime_lookup'),('sn_prepare_dynamic','sn_btf','sn_lookup'),('cold_nm_prepare_setattr','cold_setattr_btf','cold_lookup')]:
            replacement=setter.replace('nm_prepare_setattr(',name+'(',1).replace('calculate_btf_setattr(',btf+'(').replace('kallsyms_lookup_name_by_suffix(',lookup+'(')
            if name=='cold_nm_prepare_setattr':
                replacement=replacement.replace('nm_prepare_permission_abi(', 'cold_nm_prepare_permission_abi(')
                at=replacement.index('{')+1;replacement=replacement[:at]+'\n cold_note("nm_prepare_setattr");'+replacement[at:]
            updated=updated.replace(function(updated,name),replacement,1)
        old=function(updated,'nm_activate_xattr_extra_locked')
        historical=old.replace('nm_activate_xattr_extra_locked(', 'dev061_previous_extra(',1)
        source=updated.replace(old,current,1)
        assert assertions(source)==before
        source=source.replace('int main(int argc,char**argv)', 'static int previous_dev061_main(int argc,char**argv)',1)
        probe=r"""
static int dev061_lock_result;
static int dev061_lock_probe(struct nm_setattr_layout*l,int slot){return dev061_lock_result;}
static int dev061_missing_btf(struct nm_setattr_layout*l,bool*u){*u=true;return -ENODATA;}
"""
        probe+='\n#undef CONFIG_KPM_BASELINES\n'+setter.replace('nm_prepare_setattr(', 'dev061_prepare_result(',1).replace('calculate_function_setattr(', 'dev061_lock_probe(').replace('calculate_btf_setattr(', 'dev061_missing_btf(')+'\n#define CONFIG_KPM_BASELINES 1\n'
        source+='\n'+historical+'\n'+prefix+'\n'+probe+'\n'+TEST+r'''
int main(int argc,char**argv){
 assert(!previous_dev061_main(argc,argv));
 FILE*f=fopen(argv[2],"rb");assert(f);assert(!fseek(f,0,SEEK_END));xf_size=ftell(f);rewind(f);
 xf_original=malloc(xf_size);xf_image=mmap(NULL,xf_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(xf_original&&xf_image!=MAP_FAILED);assert(fread(xf_original,1,xf_size,f)==xf_size);assert(!fclose(f));
 check_dev061();assert(!munmap(xf_image,xf_size));free(xf_original);return 0;
}
'''
        assert assertions(source)[:1794]==before
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve()),str(a.reference_image.resolve()),str(a.image.resolve())],out/'run.log')
        rows.append({'abi':abi,'unchanged_assert_sites':1794,'added_assert_sites':len(assertions(source))-1794,'total_assert_sites':len(assertions(source)),'result':'PASS'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer capability-state injection, actual control/activation/read callbacks; no fabricated target ABI, no device proof','migrations':[],'host':rows},indent=2)+'\n')
    print(rows)
if __name__=='__main__':main()
