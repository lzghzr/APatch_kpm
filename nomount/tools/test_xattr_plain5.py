#!/usr/bin/env python3
"""保留1599条Oracle，回放指定真实Image的plain5写签名，追加边界/冲突。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run
from test_inode_lock import assertions
ROOT = Path(__file__).resolve().parents[2]
TEST = r'''
static void xs_reset(void){
 memcpy(xs_image,xs_original,xs_size);xs_enabled=true;xs_missing=NULL;xs_alias=false;
 xw_reset(0,false);xw_btf_missing=true;nm_setattr_status=0;
 nm_setattr_layout=(struct nm_setattr_layout){160,1,112,0};
}
static int xs_derive(void){return calculate_function_xattr_write(0,&nm_setattr_layout);}
static void check_xattr_plain5(void){
 xs_reset();assert(!xs_derive());
 /* 动态准备真实缺BTF→生产识别器→5参hook；旧无证据夹具仍拒绝。 */
 assert(!nm_activate_xattr_writes_locked()&&!nm_xattr_write_status&&xw_count==1&&xw_hooks[0].count==5);
 assert(!nm_xattr_set_context&&!nm_xattr_set_acl_target&&nm_xattr_write_readonly==xw_readonly);
 unsigned*set=(void*)(xs_image+xs_offsets[0]);unsigned*locked=(void*)(xs_image+xs_offsets[1]);
 unsigned*sec=(void*)(xs_image+xs_offsets[2]);unsigned*ro=(void*)(xs_image+xs_offsets[3]);
 const unsigned set_critical[]={9,10,12,13,14,16,17,18,24,25,26,27,28,29,30,31,32,34,35};
 for(unsigned i=0;i<sizeof(set_critical)/sizeof(*set_critical);i++){
  xs_reset();set[set_critical[i]]=0xd503201fU;assert(xs_derive()<0);
 }
 for(unsigned i=0;i<NM_XATTR_LOCKED_WORDS;i++){
  xs_reset();locked[i]=0;assert(xs_derive()<0);
 }
 for(unsigned i=0;i<NM_XATTR_SECURITY_WORDS;i++){
  xs_reset();sec[i]=0;assert(xs_derive()<0);
 }
 for(unsigned i=0;i<NM_XATTR_RO_WORDS;i++){
  xs_reset();ro[i]=0;assert(xs_derive()<0);
 }
 // 错字段、W截断、错误原生调用、branch绕过、非本地第六参均拒绝。
 xs_reset();set[2]=(set[2]&~31U)|5U;assert(xs_derive()<0); // 序言偷偷保存第六个参数。
 xs_reset();locked[3]=(locked[3]&~31U)|6U;assert(xs_derive()<0);
 xs_reset();set[16]+=8U<<10;assert(xs_derive()<0);
 xs_reset();locked[7]+=8U<<10;assert(xs_derive()<0);
 xs_reset();sec[8]+=8U<<10;assert(xs_derive()<0);
 xs_reset();set[13]&=~(1U<<31);assert(xs_derive()<0);
 xs_reset();locked[16]=il_bl((uintptr_t)&locked[16],(uintptr_t)(xs_image+xs_offsets[2]));assert(xs_derive()<0);
 xs_reset();locked[17]+=1U<<5;assert(xs_derive()<0);
 xs_reset();set[26]=0xaa0603e5U;assert(xs_derive()<0); // x6替代已确认sp来源，纯拒绝变异。
 xs_reset();nm_setattr_layout.lock_offset=168;assert(xs_derive()==-EINVAL);
 xs_reset();nm_setattr_layout.lock_kind=2;assert(xs_derive()==-EOPNOTSUPP);
 xs_reset();nm_setattr_layout.context=1;assert(xs_derive()==-EOPNOTSUPP);
 xs_reset();assert(calculate_function_xattr_write(1,&nm_setattr_layout)==-EOPNOTSUPP);
 assert(calculate_function_xattr_write(2,&nm_setattr_layout)==-EOPNOTSUPP);
 assert(calculate_function_xattr_write(0,NULL)==-EOPNOTSUPP);
 for(unsigned i=0;i<9;i++){
  xs_reset();xs_missing=xs_names[i];assert(xs_derive()<0);
 }
 xs_reset();xs_alias=true;assert(xs_derive()==-EINVAL);
 xs_reset();xs_acl=true;assert(xs_derive()==-EOPNOTSUPP);xs_acl=false;
 xs_reset();xw_query_error=-EINVAL;xw_btf_missing=false;
 unsigned queries=xs_queries;assert(nm_activate_xattr_writes_locked()==-EINVAL&&xs_queries==queries+2&&!xw_count);
 xs_reset();xw_query_error=-ENODATA;xw_btf_missing=false;
 assert(nm_activate_xattr_writes_locked()==-ENODATA&&!xw_count);
 xs_reset();xs_acl=true;assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!xw_count);xs_acl=false;
 xs_reset();nm_setattr_status=-EOPNOTSUPP;
 assert(!nm_activate_xattr_writes_locked()&&nm_xattr_write_status==-EOPNOTSUPP);
 xs_reset();locked[7]+=8U<<10;
 assert(!nm_activate_xattr_writes_locked()&&nm_xattr_write_status==-EOPNOTSUPP); // 拒绝hook，绝不启用修改。
 xs_reset();xw_reset(1,false);xw_btf_missing=true;
 assert(!nm_activate_xattr_writes_locked()&&nm_xattr_write_status==-EOPNOTSUPP);
 xs_reset();xw_reset(2,false);xw_btf_missing=true;
 assert(nm_activate_xattr_writes_locked()==-EOPNOTSUPP&&!xw_count);
 xs_reset();uintptr_t lo=(uintptr_t)(xs_image+xs_start),hi=(uintptr_t)(xs_image+xs_end);
 assert(!nm_xattr_signature_body(lo+1,36,lo,hi));
 assert(!nm_xattr_signature_body(hi-8,36,lo,hi));
 assert(!nm_xattr_signature_body(lo,36,0,hi));
 // 全部窗口的长度先检查，零长度或短一字不得读取。
 uintptr_t helpers[4]={(uintptr_t)(xs_image+xs_offsets[5]),(uintptr_t)(xs_image+xs_offsets[6]),0,0};
 assert(nm_find_xattr_plain5(set,35,&nm_setattr_layout,helpers,(uintptr_t)locked,lo,hi)<0);
 assert(nm_find_xattr_locked_plain5(locked,23,lo,lo,lo,hi)==-EINVAL);
 assert(nm_find_xattr_security_plain5(sec,10)==-EINVAL);
 assert(nm_find_xattr_readonly(ro,7)==-EINVAL);
 size_t page=sysconf(_SC_PAGESIZE);void*g=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(g!=MAP_FAILED&&!mprotect((char*)g+page,page,PROT_NONE));
 unsigned*edge=(void*)((char*)g+page-NM_XATTR_RO_WORDS*4);memcpy(edge,ro,NM_XATTR_RO_WORDS*4);
 assert(!nm_find_xattr_readonly(edge,8));assert(nm_find_xattr_readonly(edge+1,7)==-EINVAL);
 assert(!munmap(g,page*2));
 // 同一份真实证据启用后执行既有路由模型，包含路径/FD错误与内容一致性。
 xs_reset();assert(!nm_activate_xattr_writes_locked()&&!nm_xattr_write_status);
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};security_set_sid(backing,71);security_query(outer_root);
 assert(!nm_materialize_file(parent,(void*)outer_root,&rule,911));
 struct inode*outer=nm_dentry_inode(outer_root);struct nm_inode_info*info=nm_inode_private(outer);
 struct nm_mount_context_head mount={0};void*saved_mnt=info->r_path.mnt;info->r_path.mnt=&mount;
 _Alignas(8)unsigned char fd[768]={0};struct nm_path path={&mount,(void*)outer_root};*(struct nm_path*)nm_file_path(fd)=path;
 xs_reset();assert(!nm_activate_xattr_writes_locked()&&!nm_xattr_write_status);
 xw_source=backing_path.dentry;xw_expected_mount=(void*)&mount;xw_present=false;xw_lsm_error=0;xw_cap_admin=true;
 assert(!xw_set(path.dentry,NULL,"user.test","p",1,1,false));
 assert(xw_set(nm_file_path(fd)->dentry,NULL,"user.test","f",1,1,false)==-EEXIST);
 assert(!xw_set(nm_file_path(fd)->dentry,NULL,"user.test","f",1,2,false)&&xw_value[0]=='f');
 mount.flags=0x40;unsigned calls=xw_native_calls;
 assert(xw_set(path.dentry,NULL,"user.test","r",1,0,false)==-EROFS&&xw_native_calls==calls&&xw_value[0]=='f');
 assert(xw_set(nm_file_path(fd)->dentry,NULL,"user.test","r",1,0,false)==-EROFS&&xw_native_calls==calls);
 mount.flags=0;xw_cap_admin=false;
 assert(xw_set(path.dentry,NULL,"trusted.test","t",1,0,false)==-EPERM&&xw_value[0]=='f');
 assert(xw_set(path.dentry,NULL,"security.capability","t",1,0,false)==-EOPNOTSUPP&&xw_value[0]=='f');
 info->r_path.mnt=saved_mnt;port_iput(outer);
 xs_enabled=false;check_xattr_writes(); // 模型承接ARM原生函数；原有断言全部再次执行。
 puts("plain5: actual lock + permission/security provenance, readonly8, no ACL; refusal mutations and activation PASS");
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('oracle-output','image','symbols','cli-source','reference-image','output'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    syms={n:at for at,t,n in json.loads(a.symbols.read_text())}
    names=['vfs_setxattr','__vfs_setxattr_locked','security_inode_setxattr','__mnt_is_readonly','xattr_permission','down_write','up_write','_stext','_etext']
    assert not any(n=='do_set_acl' or n.startswith(('do_set_acl.','do_set_acl$'))for n in syms)
    pre='''
static unsigned char*xs_image,*xs_original;static size_t xs_size;
static bool xs_enabled,xs_alias,xs_acl;static const char*xs_missing;static unsigned xs_queries;
'''
    pre+='static const unsigned xs_offsets[]={'+','.join(str(syms[n])for n in names)+'};\n'
    pre+='static const char*xs_names[]={'+','.join('"'+n+'"'for n in names)+'};\n'
    pre+=f'static const unsigned xs_start={syms["_stext"]},xs_end={syms["_etext"]};\n'
    pre+='''static uintptr_t xs_lookup(const char*n){xs_queries++;if(!xs_enabled||(xs_missing&&!strcmp(n,xs_missing)))return 0;
 if(xs_alias&&!strcmp(n,"security_inode_setxattr"))return (uintptr_t)(xs_image+xs_offsets[1]);
 if(xs_acl&&!strcmp(n,"do_set_acl"))return (uintptr_t)(xs_image+4096);
 for(unsigned i=0;i<9;i++)if(!strcmp(n,xs_names[i]))return (uintptr_t)(xs_image+xs_offsets[i]);return 0;}
static uintptr_t xs_runtime_lookup(const char*n){
 if(!xs_enabled)return xw_lookup(n);
 if(!strcmp(n,"__mnt_is_readonly"))return (uintptr_t)xw_readonly;
 return xs_lookup(n);}
'''
    offsets=(ROOT/'nomount/nm_offsets.c').read_text()
    helpers='\n'.join(function(offsets,n)for n in ['nm_load','nm_store','nm_move','nm_load_at','nm_move32','nm_add_at','nm_zero64','nm_store_at','nm_rule_entry_save','nm_vfs_frame_save','nm_code_matches'])
    query=(ROOT/'nomount/nm_xattr_signature.c').read_text().replace('kallsyms_lookup_name_by_suffix(', 'xs_lookup(').replace('kallsyms_lookup_name(', 'xs_lookup(')
    activation=function((ROOT/'nomount/nm_xattr_write.c').read_text(),'nm_activate_xattr_writes_locked').replace('kallsyms_lookup_name_by_suffix(', 'xs_runtime_lookup(').replace('hook_wrap(', 'xw_wrap(')
    rows=[]
    for abi in ('int','bool'):
        original=(a.oracle_output/abi/'contracts.c').read_text();before=assertions(original);assert len(before)==1599
        old=function(original,'nm_activate_xattr_writes_locked')
        source=original.replace(old,pre+'\n'+helpers+'\n'+query+'\n#undef CONFIG_KPM_BASELINES\n'+activation+'\n#define CONFIG_KPM_BASELINES 1\n',1)
        assert assertions(source)==before
        source=source.replace('int main(int argc,char**argv)','static int previous_plain5_main(int argc,char**argv)',1)
        source+=TEST+r'''
int main(int argc,char**argv){
 assert(!previous_plain5_main(argc,argv));FILE*f=fopen(argv[2],"rb");assert(f);
 assert(!fseek(f,0,SEEK_END));xs_size=ftell(f);rewind(f);xs_original=malloc(xs_size);
 xs_image=mmap(NULL,xs_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(xs_original&&xs_image!=MAP_FAILED);assert(fread(xs_original,1,xs_size,f)==xs_size);assert(!fclose(f));
 check_xattr_plain5();assert(!munmap(xs_image,xs_size));free(xs_original);return 0;
}
'''
        assert assertions(source)[:1599]==before
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve()),str(a.reference_image.resolve()),str(a.image.resolve())],out/'run.log')
        rows.append({'abi':abi,'original_assert_sites':1599,'added_assert_sites':len(assertions(source))-1599,'total_assert_sites':len(assertions(source)),'result':'PASS'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer actual-image production C replay + ASan/UBSan host native models; not ARM execution/LSM/device proof','windows':dict(zip(names[:4],[36,24,11,8])),'host':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
