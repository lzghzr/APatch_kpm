#!/usr/bin/env python3
"""执行控制命令及 keyring 载荷契约，保留已有子目录 Oracle。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'reference', 'symbols', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    oracle = json.loads((args.oracle_output / 'receipt.json').read_text())
    assert oracle['tool_sha256'] == sha(root / 'nomount/tools/test_backing_subtree.py')
    assert all(sha(root / p) == h for p, h in oracle['sources'].items())
    symbols = {name: kind for _, kind, name in json.loads(args.symbols.read_text())}
    assert all(symbols.get(name) in ('T', 't') for name in ('__mutex_init', 'mutex_lock', 'mutex_unlock', 'register_key_type'))
    values = json.loads(args.reference.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    base = (args.oracle_output / 'backing-subtree.c').read_text()
    assert base.count('int main(void)') == 1
    source = base.replace('int main(void)', 'int subtree_contract_main(void)')
    source += '''
#define __user
static unsigned long control_lookup(const char*);
static bool (*kf_nm_capable)(int);
static void* (*kf_nm_memdup_user)(const void*,size_t);
static void (*kf_nm_kfree)(const void*);
static int compat_copy_to_user(void*,const void*,int);
'''
    source += 'static int nm_exchange_payload' + (root / 'nomount/nm_native.c').read_text().split('static int nm_exchange_payload', 1)[1]
    for name in ('nm_control_lock.c', 'nm_control.c', 'nm_control_key.c'):
        source += (root / 'nomount' / name).read_text().replace('kallsyms_lookup_name_by_suffix', 'control_lookup')
    source += '\nstatic void control_reference(void){\n' + '\n'.join(f'struct_offset.{name}={value};' for name, value in values.items()) + '\n}\n'
    source += r'''
static struct nm_payload control_user;
static int control_authorized=1,control_copy_short,control_dup_error,control_register_error;
static int control_init_calls,control_lock_calls,control_unlock_calls,control_copy_calls,control_dup_calls;
static const char* control_missing;
static void* control_native_table;
static uintptr_t control_address;
static int control_path(const char* name,unsigned int flags,struct nm_path* path){
  if(!strcmp(name,"/A")||!strcmp(name,"/B")||!strcmp(name,"/file")||!strcmp(name,"/file2"))assert(!manager_depth);
  if(!strncmp(name,"/system/app/Package/",20)){assert(!nm_topology_has_directory_ancestor(name,strlen(name)));return -ENOENT;}
  return tree_path(name,flags,path);
}
static void control_init(struct mutex* lock,const char* name,struct lock_class_key* key){assert(lock&&!key&&!manager_depth&&!rcu_depth&&!strcmp(name,"nomount_management"));control_init_calls++;}
static void control_lock(struct mutex* lock){assert(lock==nm_management_mutex&&!manager_depth&&!rcu_depth&&!spin_depth);manager_depth=1;control_lock_calls++;}
static void control_unlock(struct mutex* lock){assert(lock==nm_management_mutex&&manager_depth==1&&!rcu_depth&&!spin_depth);manager_depth=0;control_unlock_calls++;}
static int control_register(struct key_type* type){
  assert(type&&!manager_depth&&!control_native_table);void* table=type;
  assert(!strcmp(((struct nm_key_type_head*)table)->name,"nomount")&&!((struct nm_key_type_head*)table)->def_datalen);
  struct nm_key_callbacks* callbacks=nm_key_callback_table(table);assert(callbacks->preparse==nm_key_preparse&&callbacks->free_preparse==nm_key_free_preparse&&callbacks->instantiate==nm_key_instantiate);
  for(int i=48;i<struct_offset.key_type_size;i++)assert(!((unsigned char*)table)[i]);
  if(control_register_error)return control_register_error;
  ((unsigned char*)table)[struct_offset.key_type_size-1]=0x7f;control_native_table=table;return 0;
}
static unsigned long control_lookup(const char* name){
  if(control_missing&&!strcmp(control_missing,name))return 0;
  if(!strcmp(name,"__mutex_init"))return (uintptr_t)control_init;
  if(!strcmp(name,"mutex_lock"))return (uintptr_t)control_lock;
  if(!strcmp(name,"mutex_unlock"))return (uintptr_t)control_unlock;
  if(!strcmp(name,"register_key_type"))return (uintptr_t)control_register;
  assert(0);return 0;
}
static bool control_capable(int capability){assert(capability==21&&!manager_depth&&!rcu_depth);return control_authorized;}
static void* control_dup(const void* address,size_t size){assert((uintptr_t)address==control_address&&size==sizeof(control_user)&&!manager_depth&&!rcu_depth);control_dup_calls++;if(control_dup_error)return ERR_PTR(control_dup_error);void* p=malloc(size);assert(p);memcpy(p,&control_user,size);return p;}
static void control_free(const void* p){assert(p&&!manager_depth&&!rcu_depth);free((void*)p);}
static int compat_copy_to_user(void* address,const void* data,int size){assert((uintptr_t)address==control_address&&size==sizeof(control_user)&&!manager_depth&&!rcu_depth);control_copy_calls++;memcpy(&control_user,data,size-control_copy_short);return size-control_copy_short;}
static void control_request(u32 command){memset(&control_user,0,sizeof(control_user));control_user.magic=NOMOUNT_MAGIC_SIG;control_user.cmd=command;}
static unsigned int control_append(const char* virtual_path,const char* real,u32 flags,u32 uid){
  unsigned int offset=control_user.data_size;struct nm_rule_hdr h={flags,uid,strlen(virtual_path),real?strlen(real):0};
  assert(offset+sizeof(h)+h.v_len+h.r_len<=sizeof(control_user.buffer));memcpy(control_user.buffer+offset,&h,sizeof(h));offset+=sizeof(h);
  memcpy(control_user.buffer+offset,virtual_path,h.v_len);offset+=h.v_len;if(h.r_len)memcpy(control_user.buffer+offset,real,h.r_len);offset+=h.r_len;control_user.data_size=offset;return offset;
}
static void control_delete(const char* path,u32 uid){unsigned int offset=control_user.data_size;struct nm_del_hdr h={uid,strlen(path)};assert(offset+sizeof(h)+h.v_len<=sizeof(control_user.buffer));memcpy(control_user.buffer+offset,&h,sizeof(h));memcpy(control_user.buffer+offset+sizeof(h),path,h.v_len);control_user.data_size+=sizeof(h)+h.v_len;}
static int control_transport(int width){
  _Alignas(8) unsigned char prep[72]={0};u64 address=width==4?0x12345678:(uintptr_t)&control_user;control_address=address;
  * (struct nm_key_data*)(prep+struct_offset.key_preparse_data)=(struct nm_key_data){&address,width};
  struct nm_key_callbacks* callbacks=nm_key_callback_table(control_native_table);
  int rc=callbacks->preparse((void*)prep);callbacks->free_preparse((void*)prep);drain();flush_rcu();return rc;
}
static int control_send(void){assert(control_transport(8)==-ECANCELED);return control_user.status;}
static unsigned int control_count(void){unsigned int offset=0,count=0;while(offset<control_user.data_size){struct nm_rule_hdr h;assert(control_user.data_size-offset>=sizeof(h));memcpy(&h,control_user.buffer+offset,sizeof(h));assert(offset+sizeof(h)+h.v_len+h.r_len<=control_user.data_size);assert(!(h.flags&NM_FLAG_VIRTUAL_DIR));offset+=sizeof(h)+h.v_len+h.r_len;count++;}return count;}
int main(void){
 assert(!subtree_contract_main());control_reference();
 assert(nm_register_control()==-ENODEV);struct_offset.mutex_no_lockdep=0;assert(nm_prepare_management_mutex()==-EOPNOTSUPP&&!nm_management_mutex);control_reference();
 struct_offset.mutex_size=0;assert(nm_prepare_management_mutex()==-EINVAL&&!nm_management_mutex);control_reference();
 control_missing="mutex_lock";assert(nm_prepare_management_mutex()==-ENOENT&&!nm_management_mutex);control_missing=NULL;
 fail_alloc=1;assert(nm_prepare_management_mutex()==-ENOMEM&&!nm_management_mutex);fail_alloc=0;
 assert(!nm_prepare_management_mutex()&&control_init_calls==1&&nm_prepare_management_mutex()==-EALREADY);
 target();directory_target();control_reference();set_uid(1000);thread.flags=0;
 assert(!nm_prepare_inode_engine()&&!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
 assert(!nm_prepare_backing_inode_engine()&&!nm_prepare_topology_functions());kf_nm_inode_permission2=tree_permission;assert(!nm_prepare_backing_subtrees());
 memset(parent_storage,0,sizeof(parent_storage));nm_inode_objects(parent)->i_sb=(void*)&sb;nm_inode_objects(parent)->i_op=native_iops;*(const void**)((char*)parent+struct_offset.inode_file_ops)=native_fops;
 ((struct nm_inode_owner_prefix*)parent)->i_mode=0040755;((struct nm_dentry_head*)root_dentry)->d_inode=parent;sb.s_op=original_sops;sb.s_dev=456;
 nm_set_operation_callback(original_sops,struct_offset.sop_evict_inode,host_evict);
 kf_nm_kern_path=control_path;kf_nm_path_put=tree_put;kf_nm_vfs_path_lookup=tree_query;kf_nm_new_inode=port_new;kf_nm_iget5_locked=port_iget;kf_nm_unlock_new_inode=port_unlock;kf_nm_set_nlink=port_nlink;
 kf_nm_d_splice_alias=port_splice;kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;kf_nm_d_drop=virtual_drop;
 kf_nm_capable=control_capable;kf_nm_memdup_user=control_dup;kf_nm_kfree=control_free;
 control_missing="register_key_type";assert(nm_register_control()==-ENOENT&&!nm_registered_key_type);control_missing=NULL;
 fail_alloc=1;assert(nm_register_control()==-ENOMEM&&!nm_registered_key_type);fail_alloc=0;
 int freed=frees;control_register_error=-EEXIST;assert(nm_register_control()==-EEXIST&&!nm_registered_key_type&&frees==freed+1);control_register_error=0;
 assert(!nm_register_control()&&nm_registered_key_type==control_native_table&&nm_register_control()==-EALREADY);
 assert(nm_key_instantiate(NULL,NULL)==-EINVAL&&nm_key_preparse(NULL)==-EINVAL);
 control_request(NM_CMD_GET_VERSION);control_authorized=0;int copies=control_copy_calls,dups=control_dup_calls;
 assert(control_transport(8)==-EPERM&&control_copy_calls==copies&&control_dup_calls==dups);control_authorized=1;
 assert(control_transport(3)==-EINVAL&&control_dup_calls==dups);control_dup_error=-EFAULT;assert(control_transport(8)==-EFAULT);control_dup_error=0;
 control_user.magic=0;copies=control_copy_calls;assert(control_transport(8)==-EFAULT&&control_copy_calls==copies);
 control_request(NM_CMD_GET_VERSION);control_copy_short=1;assert(control_transport(8)==-EFAULT);control_copy_short=0;
 control_request(NM_CMD_GET_VERSION);assert(control_transport(4)==-ECANCELED&&!control_user.status&&control_user.data_size==strlen(NM_KPM_VERSION)&&!memcmp(control_user.buffer,NM_KPM_VERSION,control_user.data_size));
 control_request(999);assert(control_send()==-EINVAL);
 control_request(NM_CMD_ADD_RULE);control_user.data_size=sizeof(control_user.buffer)+1;assert(control_send()==-EINVAL&&!nm_topology_leaves);
 control_request(NM_CMD_ADD_RULE);control_user.arg1=1;assert(control_send()==-EINVAL&&!nm_topology_leaves);
 control_request(NM_CMD_ADD_RULE);control_append("/system/app/Package","/A",0,1000);
 control_append("/system/app/Package/fails","/absent",0,1000);control_append("/system/app/Package/sub/deep/inject","/file",0,1000);
 control_append("/system/app/Package/bad","/file",8,1000);unsigned int valid_end=control_append("/system/app/Package/after","/file",0,1000);
 control_user.data_size+=2;assert(control_send()==-ENOENT&&control_user.arg1==valid_end&&records()==5);
 control_request(NM_CMD_DEL_RULE);control_delete("/system/app/Package/absent",1000);control_delete("/system/app/Package/after",1000);
 valid_end=control_user.data_size;assert(control_send()==-ENOENT&&control_user.arg1==valid_end&&records()==4);
 control_request(NM_CMD_ADD_UID);control_user.target_uid=1234;assert(!control_send());control_request(NM_CMD_ADD_UID);control_user.target_uid=1234;assert(control_send()==-EEXIST);
 control_request(NM_CMD_GET_UIDS);assert(!control_send()&&control_user.data_size==4);u32 uid;memcpy(&uid,control_user.buffer,4);assert(uid==1234);
 control_request(NM_CMD_GET_UIDS);control_user.arg1=1;assert(!control_send()&&!control_user.data_size);
 control_request(NM_CMD_DEL_UID);control_user.target_uid=1234;assert(!control_send());control_request(NM_CMD_DEL_UID);control_user.target_uid=1234;assert(control_send()==-ENOENT);
 control_request(NM_CMD_BLOCK_ISOLATED_UIDS);control_user.arg1=1;assert(!control_send()&&nomount_is_uid_blocked(190001));
 control_request(NM_CMD_GET_ISOLATED_STATE);assert(!control_send()&&control_user.data_size==2&&!memcmp(control_user.buffer,"1\n",2));
 control_request(NM_CMD_BLOCK_ISOLATED_UIDS);assert(!control_send()&&!nomount_is_uid_blocked(190001));
 for(int i=0;i<120;i++){char path[64];snprintf(path,sizeof(path),"/system/app/Package/file%d",i);control_request(NM_CMD_ADD_RULE);control_append(path,"/file",0,1000);assert(!control_send());}
 struct nm_payload exported[3];int pages=0;u32 cursor=0,total=0;
 for(;;){control_request(NM_CMD_GET_LIST);control_user.arg1=cursor;assert(!control_send());if(!control_user.data_size)break;assert(control_user.arg1>cursor&&pages<3);cursor=control_user.arg1;total+=control_count();exported[pages++]=control_user;}
 assert(pages==2&&total==122&&cursor==122);
 control_request(NM_CMD_CLEAR_RULES);assert(!control_send()&&!nm_topology_leaves&&!nm_topology_anchors);
 // 列表中深层规则先于来源父目录；恢复顺序不能令自动子目录丢失backing。
 for(int i=0;i<pages;i++){control_user=exported[i];control_user.cmd=NM_CMD_ADD_RULE;control_user.arg1=0;assert(!control_send());}
 struct inode* root=tree_lookup(0,"Package",-1,parent);assert(root);struct inode* sub=tree_lookup(1,"sub",0,root);assert(sub);
 assert(((struct nm_inode_info*)nm_inode_private(sub))->rule->r_path.dentry==tree_dentry[1]);
 struct inode* deep=tree_lookup(2,"deep",1,sub);assert(deep&&((struct nm_inode_info*)nm_inode_private(deep))->rule->r_path.dentry==tree_dentry[2]);
 assert(tree_lookup(3,"inject",2,deep)&&tree_lookup(4,"original",2,deep));
 control_request(NM_CMD_ADD_UID);control_user.target_uid=1234;assert(!control_send());control_request(NM_CMD_CLEAR_UIDS);assert(!control_send()&&!nomount_uids&&nm_topology_leaves);
 control_request(NM_CMD_CLEAR_ALL);assert(!control_send()&&!nm_topology_leaves&&!nm_topology_anchors&&!nomount_uids);
 for(int i=0;i<5;i++)tree_release(i);assert(tree_gets==tree_puts&&tree_anchor_gets==tree_anchor_puts&&!manager_depth&&control_lock_calls==control_unlock_calls);
 nm_proxy_evict_inode(parent);flush_rcu();fixture_vfree((void*)((uintptr_t)sb.s_op - offsetof(struct nm_super_proxy,table)));
 // 宿主夹具结束时释放模拟注册对象；生产成功注册保持驻留。
 fixture_vfree(control_native_table);control_native_table=nm_registered_key_type=NULL;nm_discard_management_mutex();nm_backing_open_permission=NULL;nm_discard_directory_view();
 assert(!q_count&&!rcu_depth&&!manager_depth);puts("keyring transport, command batches, mutex contracts, paging and rule replay: PASS");return 0;}
'''
    c = args.output / 'control.c'; c.write_text(source)
    compiled = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-I' + str(root / 'nomount'),
                               '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'control')], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr); compiled.check_returncode()
    run = subprocess.run([str(args.output / 'control')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr); run.check_returncode()
    files = ['kpm_utils.h'] + [str(p.relative_to(root)) for p in sorted((root / 'nomount').glob('nm*.[ch]'))]
    receipt = {'scope': 'Developer host contracts; not native keyring, lock contention, CFI or device proof',
               'sources': {p: sha(root / p) for p in files}, 'tool_sha256': sha(Path(__file__)),
               'reference_sha256': sha(args.reference), 'oracle_receipt_sha256': sha(args.oracle_output / 'receipt.json'),
               'generated_source_sha256': sha(c), 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n'); print(run.stdout.strip().splitlines()[-1])


if __name__ == '__main__':
    main()
