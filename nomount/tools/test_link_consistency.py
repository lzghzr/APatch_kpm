#!/usr/bin/env python3
"""保留963条断言，追加源readlink资格、路径/FD属性与cookie退役一致性。"""
import argparse,hashlib,json,re
from pathlib import Path
from test_directory_abis import function
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
INPUTS={'int':'22f06bc974867be6cbe39e3ba9f3173b75651fb366638a3d59f8d3cb9c17dd01','bool':'f1a8616fc3526169df911280a920e26ba90101829259f6eda26e9b7ed954b189'}
FIXTURE=r'''
static unsigned consistency_unknown_calls;
static int consistency_unknown_read(struct dentry*d,char*b,int n){consistency_unknown_calls++;return 0;}
static unsigned long consistency_lookup(const char*n){
 if(complete_mode==3){if(!strcmp(n,"vfs_readlink"))return 1;if(!strcmp(n,"generic_readlink"))return 0;}
 return complete_lookup(n);
}
static int consistency_attr(const struct nm_path*p,struct kstat*s,u32 mask,unsigned flags){
 assert(p->dentry==(void*)dentry_storage&&mask==77&&flags==88);
 memset(s,0,256);struct nm_kstat_prefix*out=(void*)s;out->mode=nm_inode_mode(backing);out->size=nm_inode_size(backing);out->ino=999;out->dev=999;out->uid=123;out->gid=456;out->nlink=1;out->attributes=0x800;out->attributes_mask=~0ULL;return 0;
}
static void check_link_consistency(void){
 for(complete_mode=1;complete_mode<=3;complete_mode++){
  link_api=1;link_missing=0;security_fixture_reset();target();directory_target();struct_offset.kstat_inode_first=0;
  struct_offset.iop_getattr=complete_mode==2?144:complete_mode==3?112:128;struct_offset.permission_abi=complete_mode==3?1:0;
  nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;
  kf_nm_kmalloc=memory_slab_miss;kf_nm_vzalloc=host_alloc;kf_nm_kvfree=memory_vmap_free;kf_nm_is_vmalloc_addr=memory_vmap;kf_nm_vfree_atomic=memory_vmap_free;kf_nm_path_get=binding_owned_get;kf_nm_path_put=binding_owned_put;
  assert(!nm_prepare_inode_engine()&&nm_inode_engine.symlink_ops);assert(!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
  nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;sb.s_dev=456;assert(!nm_install_super_proxy((void*)&sb));
  kf_nm_new_inode=host_new;kf_nm_d_splice_alias=port_splice;kf_nm_vfs_getattr_nosec=consistency_attr;nm_vfs_getattr_pair=NULL;
  _Alignas(8) unsigned char source_ops[512]={0},directory[768]={0},fd[512]={0};
  nm_inode_objects(backing)->i_op=source_ops;((struct nm_dentry_head*)dentry_storage)->d_inode=backing;((struct nm_inode_owner_prefix*)backing)->i_mode=0120777;security_set_sid(backing,37);
  nm_set_operation_callback(source_ops,8,complete_mode==2?(void*)complete_encrypted_follow:(void*)complete_encrypted_get);
  if(complete_mode==2)nm_set_operation_callback(source_ops,nm_link_put_slot,complete_free);
  if(nm_link_read_slot>=0)nm_set_operation_callback(source_ops,nm_link_source_read_slot,complete_generic_readlink);
  assert(nm_plain_symlink_source(backing));
  void*allowed_read=nm_operation_callback(source_ops,nm_link_source_read_slot);
  nm_set_operation_callback(source_ops,nm_link_source_read_slot,consistency_unknown_read);assert(!nm_plain_symlink_source(backing));
  struct nm_path input=backing_path;assert(PTR_ERR(nm_take_backing_child_rule(&input,1000))==-EOPNOTSUPP&&input.dentry&&!consistency_unknown_calls);
  nm_set_operation_callback(source_ops,nm_link_source_read_slot,allowed_read);
  struct nm_inode_info dir_info={.r_path={(void*)1,(void*)tree_dentry[0]}};nm_inode_objects(directory)->i_op=nm_inode_engine.directory_ops;nm_inode_objects(directory)->i_sb=(void*)&sb;nm_set_inode_private(directory,&dir_info);*(u64*)(directory+struct_offset.inode_number)=77;
  ((struct nm_dentry_head*)tree_dentry[0])->d_inode=(void*)tree_inode[0];((struct nm_inode_owner_prefix*)tree_inode[0])->i_mode=0040755;nm_inode_objects(tree_inode[0])->i_op=native_iops;
  kf_nm_vfs_path_lookup=link_child_lookup;port_query_dentry(outer_root,"link",root_dentry);
  int puts_before=binding_owned_puts;assert(!nm_lookup_backing_directory((void*)directory,(void*)outer_root,0));struct inode*i=nm_dentry_inode(outer_root);assert(i&&nm_is_symlink_inode(i));
  struct nm_file_inode_ops*objects=(void*)(fd+struct_offset.file_inode_ops);objects->f_inode=i;* (struct nm_path*)nm_file_path(fd)=(struct nm_path){.dentry=(void*)outer_root};
  const char*targets[]={"../relative","/absolute/target","_encoded_no_key"};
  for(unsigned t=0;t<3;t++){
   link_text=consistency_text=targets[t];*(int64_t*)((char*)backing+struct_offset.inode_size)=strlen(targets[t]);
   char buffer[64];memset(buffer,0xa5,sizeof(buffer));int got=complete_generic_readlink((void*)outer_root,buffer,64);
   assert(got==(int)strlen(targets[t])&&!memcmp(buffer,targets[t],got)&&(unsigned char)buffer[got]==0xa5&&!complete_heap);
   unsigned char path_stat[256],fd_stat[256];struct nm_path path={.dentry=(void*)outer_root};
   assert(!nm_file_getattr(&path,(void*)path_stat,77,88));assert(!nm_file_getattr(nm_file_path(fd),(void*)fd_stat,77,88));
   assert(!memcmp(path_stat,fd_stat,256));struct nm_kstat_prefix*st=(void*)path_stat;
   assert(st->mode==0120777&&st->size==strlen(targets[t])&&st->uid==123&&st->gid==456&&st->attributes==0x800&&st->dev==456);
   struct nm_directory_node node={0};struct nm_dir_context ctx={0};ctx.actor=(void*)fixture_actor;
   struct nm_backing_directory_actor actor={.filter={.outer=&ctx,.node=&node,.uid=1000},.self_number=77,.parent_number=33};reset_emit();assert(!nm_backing_directory_filter(&actor.filter.context,"link",4,8,999,10));
   assert(emitted_types[0]==10&&emitted_numbers[0]==st->ino&&st->ino==nm_inode_number(i));
  }
  if(complete_mode==2){
   void*cookie=NULL;assert(!strcmp(nm_symlink_follow_link((void*)outer_root,&cookie),"_encoded_no_key")&&cookie&&complete_heap);
   int held=binding_owned_puts;nm_set_operation_callback(source_ops,nm_link_source_read_slot,consistency_unknown_read);
   nm_symlink_put_link(i,cookie);assert(!complete_heap&&binding_owned_puts==held&&!consistency_unknown_calls);nm_set_operation_callback(source_ops,nm_link_source_read_slot,allowed_read);
  }else{
   const int errors[]={-ENOKEY,-ENOMEM,-ENOENT,-EIO};
   for(unsigned n=0;n<4;n++){link_native_error=errors[n];assert(complete_generic_readlink((void*)outer_root,(void*)fd,4)==errors[n]);}link_native_error=0;
  }
  assert(binding_owned_puts==puts_before+1);host_iput(i);drain();((struct nm_dentry_head*)outer_root)->d_inode=NULL;assert(binding_owned_puts==puts_before+2);
  if(complete_mode==2){
   kf_nm_d_splice_alias=host_splice;struct nomount_rule rule={.r_path=backing_path,.refs=1};
   race_slot=(const void**)(source_ops+nm_link_put_slot);race_value=NULL;
   assert(!nm_materialize_symlink(parent,(void*)1234,&rule,42)&&created);struct nm_inode_info*info=nm_inode_private(created);assert(info->link_put==complete_free);
   ((struct nm_dentry_head*)outer_root)->d_inode=created;void*cookie=NULL;int calls=complete_native_calls;
   assert(PTR_ERR(nm_symlink_follow_link((void*)outer_root,&cookie))==-EOPNOTSUPP&&!cookie&&complete_native_calls==calls);
   host_iput(created);drain();((struct nm_dentry_head*)outer_root)->d_inode=NULL;
  }
  nm_discard_directory_view();assert(!nm_inode_engine.symlink_ops&&!consistency_unknown_calls&&!complete_heap);
 }
 complete_mode=0;puts("source readlink gates; relative/absolute/encoded strings; path/FD metadata and d_ino agreement; held-cookie and allocation interleave PASS");
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle-output',type=Path,required=True);p.add_argument('--cli-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 current=(ROOT/'nomount/nm_inode.c').read_text();rows=[]
 for abi,digest in INPUTS.items():
  original=(a.oracle_output/abi/'contracts.c').read_text();assert hashlib.sha256(original.encode()).hexdigest()==digest;source=original
  block=re.search(r'#ifndef __NM_STRUCTS_H\b.*?#endif',source,re.S);head=(ROOT/'nomount/nm_structs.h').read_text();source=source[:block.start()]+head[head.index('#ifndef '):]+source[block.end():]
  source=source.replace('static struct nm_follow_pair nm_follow_pairs[3];','static struct nm_follow_pair nm_follow_pairs[3];\nstatic int nm_link_source_read_slot=-1;\nstatic bool nm_link_default_readlink;\nstatic unsigned long consistency_lookup(const char*);\nstatic bool nm_plain_symlink_source(struct inode*);\n#ifndef ENOKEY\n#define ENOKEY 126\n#endif',1)
  for n in ('nm_prepare_link_prefix','nm_plain_symlink_source','nm_symlink_follow_link','nm_materialize_backed_inode','nm_new_symlink_operations'):
   new=function(current,n).replace('kallsyms_lookup_name_by_suffix(', 'consistency_lookup(');source=source.replace(function(source,n),new,1)
  # 准备失败终止该次初始化；夹具恢复合法配置后重新准备新能力，不要求生产回滚。
  source=source.replace('struct_offset.inode_ops_size=saved_size;', 'struct_offset.inode_ops_size=saved_size;nm_new_symlink_operations(&extra);nm_discard_operations(extra);',1)
  # 旧兼容夹具补真实内核的generic_readlink槽；保持全部既有assert逐字与顺序。
  source=source.replace('   assert(nm_plain_symlink_source(backing));','   if(nm_link_read_slot>=0)nm_set_operation_callback(source_ops,nm_link_source_read_slot,complete_generic_readlink);\n   assert(nm_plain_symlink_source(backing));',1)
  source=source.replace('static char* complete_heap;','static char* complete_heap;\nstatic const char*consistency_text="../target";',1).replace('strcpy(complete_heap,"../target")','strcpy(complete_heap,consistency_text)',1)
  before=re.findall(r'\bassert\s*\([^;]+\);',original);assert re.findall(r'\bassert\s*\([^;]+\);',source)==before
  source=source.replace('int main(void){assert(!previous_complete_main());','static int previous_consistency_main(void){assert(!previous_complete_main());',1)
  source+=FIXTURE+'\nint main(void){assert(!previous_consistency_main());check_link_consistency();return 0;}\n'
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log');run([str((out/'contracts').resolve())],out/'run.log')
  rows.append({'abi':abi,'prior_asserts':len(before),'fixture_initialization_adaptations':3,'added_assert_sites':len(re.findall(r'\bassert\s*\([^;]+\);',FIXTURE))+1,'result':'PASS'})
 print(json.dumps(rows,indent=2));(a.output/'receipt.json').write_text(json.dumps({'scope':'Developer path/FD callback fixtures, not native syscalls/encryption/CFI/concurrency proof','results':rows},indent=2)+'\n')
if __name__=='__main__':main()
