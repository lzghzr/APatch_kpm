#!/usr/bin/env python3
"""保留上一链接里程碑919条断言，追加旧/加密链接、readlink与目录身份检查。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
INPUTS={'int':'d7e737f90bc18e52fdaa46ab36f1d7a79168110becf0691d2ad1950ab63d184c','bool':'b2ea67273d192f8085508dd695ff28d9c9371f9f93f821ce57c2e806181b2c93'}
FIXTURE=r'''
static int complete_mode,complete_error,complete_security_error,complete_security_calls,complete_puts,complete_native_calls,complete_user_error;
static char* complete_heap;
static void complete_put(struct inode* i,void* p){assert(i==backing&&p==complete_heap);complete_puts++;free(complete_heap);complete_heap=NULL;}
static const char* complete_follow(struct dentry* d,void**cookie){
 assert(d==(void*)dentry_storage&&cookie&&!*cookie);complete_native_calls++;
 if(complete_error){*cookie=(void*)123;return ERR_PTR(complete_error);}
 complete_heap=malloc(32);assert(complete_heap);strcpy(complete_heap,"../target");*cookie=complete_heap;return complete_heap;
}
static const char* complete_simple(struct dentry* d,void**cookie){assert(d==(void*)dentry_storage&&cookie&&!*cookie);complete_native_calls++;return "../target";}
static void complete_free(struct inode*i,void*p){complete_put(i,p);}
static const char* complete_encrypted_follow(struct dentry*d,void**cookie){return complete_follow(d,cookie);}
static const char* complete_encrypted_get(struct dentry*d,struct inode*i,struct delayed_call*done){return link_page(d,i,done);}
static const char* complete_f2fs_encrypted_get(struct dentry*d,struct inode*i,struct delayed_call*done){return link_page(d,i,done);}
static const char* complete_f2fs_get(struct dentry*d,struct inode*i,struct delayed_call*done){return link_page(d,i,done);}
static int complete_security(struct dentry* d){assert(d==(void*)dentry_storage);complete_security_calls++;return complete_security_error;}
static int complete_generic_readlink(struct dentry* d,char*buffer,int len){
 struct inode*i=nm_dentry_inode(d);const char*text;void*cookie=(void*)123;struct delayed_call done={0};
 if(nm_legacy_links){const struct nm_inode_follow_prefix*ops=nm_inode_ops(i);text=ops->follow_link(d,&cookie);}
 else{const struct nm_inode_link_ops*ops=nm_inode_ops(i);text=ops->get_link(d,i,&done);}
 if(IS_ERR(text))return PTR_ERR(text);
 int copied=strlen(text);if(copied>len)copied=len;
 if(!complete_user_error)memcpy(buffer,text,copied);
 if(nm_legacy_links){void(*put)(struct inode*,void*)=nm_operation_callback(nm_inode_ops(i),nm_link_put_slot);if(put)put(i,cookie);}
 else if(done.fn)done.fn(done.arg);
 return complete_user_error?-EFAULT:copied;
}
static unsigned long complete_lookup(const char* name){
 if(!complete_mode)return symlink_fixture_lookup(name);
 if(!strcmp(name,"vfs_get_link"))return complete_mode==2?0:(uintptr_t)link_vfs_get;
 if(!strcmp(name,"vfs_readlink"))return 0;
 if(!strcmp(name,"generic_readlink"))return (uintptr_t)complete_generic_readlink;
 if(!strcmp(name,"security_inode_readlink"))return (uintptr_t)complete_security;
 if(!strcmp(name,"simple_follow_link"))return (uintptr_t)complete_simple;
 if(!strcmp(name,"page_follow_link_light"))return (uintptr_t)complete_follow;
 if(!strcmp(name,"ext4_encrypted_follow_link"))return (uintptr_t)complete_encrypted_follow;
 if(!strcmp(name,"page_put_link"))return (uintptr_t)complete_put;
 if(!strcmp(name,"kfree_put_link"))return (uintptr_t)complete_free;
 if(!strcmp(name,"ext4_encrypted_get_link"))return (uintptr_t)complete_encrypted_get;
 if(!strcmp(name,"f2fs_encrypted_get_link"))return (uintptr_t)complete_f2fs_encrypted_get;
 if(!strcmp(name,"f2fs_get_link"))return (uintptr_t)complete_f2fs_get;
 return symlink_fixture_lookup(name);
}
static void check_complete_links(void){
 for(complete_mode=1;complete_mode<=2;complete_mode++){
  link_api=1;link_missing=0;security_fixture_reset();target();directory_target();
  struct_offset.iop_getattr=complete_mode==2?offsetof(struct nm_inode_follow_prefix,getattr):offsetof(struct nm_inode_android_link_prefix,getattr);
  struct_offset.permission_abi=0;nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;
  kf_nm_kmalloc=memory_slab_miss;kf_nm_vzalloc=host_alloc;kf_nm_kvfree=memory_vmap_free;kf_nm_is_vmalloc_addr=memory_vmap;kf_nm_vfree_atomic=memory_vmap_free;
  kf_nm_path_get=binding_owned_get;kf_nm_path_put=binding_owned_put;fail_alloc=new_fail=splice_fail=0;
  assert(!nm_prepare_inode_engine()&&nm_inode_engine.symlink_ops);
  assert(!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
  nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;assert(!nm_install_super_proxy((void*)&sb));
  ((struct nm_dentry_head*)dentry_storage)->d_inode=backing;nm_inode_objects(backing)->i_mapping=(void*)9876;
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0120777;security_set_sid(backing,37);
  kf_nm_new_inode=host_new;kf_nm_d_splice_alias=host_splice;kf_nm_vfs_getattr_nosec=host_attr;nm_vfs_getattr_pair=NULL;
  _Alignas(8) unsigned char source_ops[512]={0},outer[256]={0};nm_inode_objects(backing)->i_op=source_ops;
  link_text="../target";unsigned loops=3;
  for(unsigned kind=0;kind<loops;kind++){
   if(complete_mode==2){
    struct nm_inode_follow_prefix*ops=(void*)source_ops;ops->follow_link=kind==2?complete_encrypted_follow:kind?complete_follow:complete_simple;ops->put_link=kind==2?complete_free:kind?complete_put:NULL;
   }else {void*callbacks[]={complete_encrypted_get,complete_f2fs_encrypted_get,complete_f2fs_get};nm_set_operation_callback(source_ops,8,callbacks[kind]);}
   assert(nm_plain_symlink_source(backing));
   struct nomount_rule rule={.r_path=backing_path,.refs=1};int gets=binding_owned_gets,put_count=binding_owned_puts;
   assert(!nm_materialize_symlink(parent,(void*)1234,&rule,0x12345)&&created);struct inode*i=created;
   ((struct nm_dentry_head*)outer)->d_inode=i;
   assert(nm_is_symlink_inode(i)&&nm_inode_mapping(i)==nm_inode_data(i));
   assert(nm_operation_callback(nm_inode_ops(i),nm_link_read_slot)==nm_symlink_readlink);
   if(complete_mode==2){
    assert(((struct nm_inode_info*)nm_inode_private(i))->link_put==(kind==2?complete_free:kind?complete_put:NULL));
    void*cookie=(void*)123;assert(PTR_ERR(nm_symlink_follow_link(NULL,&cookie))==-ECHILD);
    assert(!strcmp(nm_symlink_follow_link((void*)outer,&cookie),"../target"));
    if(kind){assert(cookie==complete_heap);nm_symlink_put_link(i,cookie);assert(!complete_heap);}else assert(!cookie);
    int calls=complete_native_calls;complete_security_error=-EACCES;cookie=(void*)123;
    assert(PTR_ERR(nm_symlink_follow_link((void*)outer,&cookie))==-EACCES&&!cookie&&complete_native_calls==calls);complete_security_error=0;
    if(kind){int puts_before=complete_puts;complete_error=-ENOENT;cookie=(void*)123;
     assert(PTR_ERR(nm_symlink_follow_link((void*)outer,&cookie))==-ENOENT&&!cookie&&complete_puts==puts_before);complete_error=0;}
   }
   char buffer[64];memset(buffer,0xa5,sizeof(buffer));
   int n=nm_symlink_readlink((void*)outer,buffer,4);assert(n==4&&!memcmp(buffer,"../t",4)&&(unsigned char)buffer[4]==0xa5);
   memset(buffer,0xa5,sizeof(buffer));n=nm_symlink_readlink((void*)outer,buffer,64);
   assert(n==9&&!memcmp(buffer,"../target",9)&&(unsigned char)buffer[9]==0xa5);
   complete_user_error=1;assert(nm_symlink_readlink((void*)outer,buffer,64)==-EFAULT&&!complete_heap);complete_user_error=0;
   unsigned char st[256];struct nm_path path={.dentry=(void*)outer};assert(!nm_file_getattr(&path,(void*)st,77,88));
   assert(((struct nm_kstat_prefix*)st)->ino==0x12345&&nm_inode_mode(i)==0120777);
   if(complete_mode==2){
    struct nm_inode_follow_prefix*ops=(void*)source_ops;void*put=ops->put_link;ops->put_link=(void*)link_magic;
    int calls=complete_native_calls;void*cookie=NULL;
    assert(!nm_plain_symlink_source(backing)&&PTR_ERR(nm_symlink_follow_link((void*)outer,&cookie))==-EOPNOTSUPP&&complete_native_calls==calls);ops->put_link=put;
    // 清理使用物化时捕获的配对，当前源表改写不改在途cookie的归属。
    if(kind){assert(!strcmp(nm_symlink_follow_link((void*)outer,&cookie),"../target"));ops->put_link=(void*)link_magic;nm_symlink_put_link(i,cookie);assert(!complete_heap&&!link_magic_calls);ops->put_link=put;}
   }
   host_iput(i);drain();assert(binding_owned_gets==gets+1&&binding_owned_puts==put_count+1&&!complete_heap);
  }
  assert(complete_security_calls>0||complete_mode==1);
  struct nm_backing_directory_actor actor={.filter={.outer=NULL,.node=(void*)1,.uid=1000},.self_number=77,.parent_number=33};
  struct nm_dir_context ctx={0};ctx.actor=(void*)fixture_actor;if(struct_offset.dir_actor_abi)ctx.actor_bool=(void*)fixture_actor;
  // actor用现有准确int/bool夹具；不在RCU中调用输出。
  actor.filter.outer=&ctx;actor.filter.node=NULL;reset_emit();
  assert(!nm_backing_directory_filter(&actor.filter.context,"link",4,8,999,10));assert(emitted_types[0]==10&&emitted_numbers[0]==999);
  struct nm_directory_node node={0};actor.filter.node=&node;reset_emit();
  assert(!nm_backing_directory_filter(&actor.filter.context,"link",4,8,999,10));
  assert(emitted_types[0]==10&&emitted_numbers[0]==nm_name_hash((void*)77,"link",4));
  reset_emit();assert(!nm_backing_directory_filter(&actor.filter.context,"unknown",7,9,888,0));assert(emitted_types[0]==0&&emitted_numbers[0]==nm_name_hash((void*)77,"unknown",7));
  nm_discard_directory_view();assert(!nm_inode_engine.symlink_ops);
 }
 _Alignas(16) u32 code[4]={0x14000002U,0xd503201fU,0xd65f03c0U,0xd65f03c0U};
 nm_link_code_start=(uintptr_t)code;nm_link_code_end=(uintptr_t)(code+4);
 assert(nm_link_callback_matches((uintptr_t)code,(uintptr_t)(code+2)));
 code[0]=0xd503245fU;code[1]=0x14000001U;assert(nm_link_callback_matches((uintptr_t)code,(uintptr_t)(code+2)));
 nm_link_code_end=(uintptr_t)(code+1);assert(!nm_link_callback_matches((uintptr_t)code,(uintptr_t)(code+2)));
 nm_link_code_end=(uintptr_t)(code+4);code[1]=0xd503201fU;assert(!nm_link_callback_matches((uintptr_t)code,(uintptr_t)(code+2)));
 assert(!nm_link_callback_matches(1,(uintptr_t)(code+2)));nm_link_code_start=nm_link_code_end=0;
 assert(!nm_link_callback_matches((uintptr_t)code,(uintptr_t)(code+2)));
 complete_mode=0;
 puts("legacy/modern readlink: plaintext/encrypted cleanup, source security, errno, truncation, lstat and DT_LNK/DT_UNKNOWN identity PASS");
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle-output',type=Path,required=True);p.add_argument('--cli-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 current=(ROOT/'nomount/nm_inode.c').read_text();rows=[]
 for abi,digest in INPUTS.items():
  original=(a.oracle_output/abi/'contracts.c').read_text();assert hashlib.sha256(original.encode()).hexdigest()==digest
  source=original
  for name,guard in [('nm_structs.h','__NM_STRUCTS_H'),('nm_rules.h','__NM_RULES_H')]:
   block=re.search(r'#ifndef '+guard+r'\b.*?#endif',source,re.S);assert block
   text=(ROOT/'nomount'/name).read_text();source=source[:block.start()]+text[text.index('#ifndef '):]+source[block.end():]
  inst=(ROOT/'kpm_utils.h').read_text().split('// instruction\n',1)[1].rsplit('#endif',1)[0]
  at=source.index('#define CONFIG_KPM_BASELINES');source=source[:at]+inst+'\n'+source[at:]
  globals=current[current.index('static uintptr_t nm_plain_link_callbacks'):current.index('static int nm_prepare_inode_functions')]
  source=source.replace('static uintptr_t nm_plain_link_callbacks[4];',globals+'\nstatic unsigned long complete_lookup(const char*);',1)
  extra='\n'.join(function(current,n) for n in ('nm_link_callback_matches','nm_follow_pair_index','nm_symlink_follow_link','nm_symlink_put_link','nm_symlink_readlink'))
  source=source.replace(function(source,'nm_plain_symlink_source'),extra+'\n'+function(current,'nm_plain_symlink_source'),1)
  source=source.replace(function(source,'nm_new_symlink_operations'),function(current,'nm_prepare_link_prefix')+'\n'+function(current,'nm_new_symlink_operations').replace('kallsyms_lookup_name_by_suffix(', 'complete_lookup('),1)
  source=source.replace(function(source,'nm_materialize_backed_inode'),function(current,'nm_materialize_backed_inode'),1)
  file=(ROOT/'nomount/nm_backing_directory.c').read_text();source=source.replace(function(source,'nm_backing_directory_filter'),function(file,'nm_backing_directory_filter'),1)
  before=re.findall(r'\bassert\s*\([^;]+\);',original);assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
  source=source.replace('int main(void){assert(!previous_link_main());','static int previous_complete_main(void){assert(!previous_link_main());',1)
  source+=FIXTURE+'\nint main(void){assert(!previous_complete_main());check_complete_links();return 0;}\n'
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
  run([str((out/'contracts').resolve())],out/'run.log')
  rows.append({'abi':abi,'prior_asserts':len(before),'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',FIXTURE))+1,'result':'PASS'})
 print(json.dumps(rows,indent=2));(a.output/'receipt.json').write_text(json.dumps({'scope':'Developer host callback and VFS stub checks, not native kernel/CFI/encryption proof','results':rows},indent=2)+'\n')
if __name__=='__main__':main()
