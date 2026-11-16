#!/usr/bin/env python3
"""DEV-101：身份、不可解析日志、表发布及普通文件系统复制契约。"""
import argparse
from pathlib import Path
from test_nomount_v230 import PRE, compile_run, function

TEST = r'''
int main(void) {
 void* native_ops[4]={(void*)11,(void*)12,(void*)13,(void*)14};
 void* kernfs_ops[4]={(void*)21,(void*)22,(void*)23,(void*)24};
 const char* names[]={"sysfs","cgroup","cgroup2","vendor_kernfs","tmpfs","ext4","erofs","debugfs","tracefs"};
 fixture_kernfs_sops=kernfs_ops;
 for(unsigned i=0;i<9;i++) {
  struct nm_filesystem_type_head type={names[i]};
  struct nm_super_head sb={.s_type=&type,.s_op=i<4?kernfs_ops:native_ops};
  unsigned prior=allocations,old_published=published;
  const void* original=sb.s_op;
  int rc=nm_install_super_proxy((void*)&sb);
  if(i<4)assert(rc==-EOPNOTSUPP&&sb.s_op==original&&allocations==prior&&published==old_published);
  else {
   assert(!rc&&allocations==prior+1&&published==old_published+1);
   struct nm_super_proxy* proxy=last_alloc;
   assert(proxy->original==original);
   void** copy=(void*)proxy->table;
   assert(copy[0]==nm_proxy_drop_inode&&copy[1]==nm_proxy_evict_inode);
   assert(copy[2]==native_ops[2]&&copy[3]==native_ops[3]);free(last_alloc);
  }
 }
 // Names are not an identity source, including absent and misleading names.
 struct nm_filesystem_type_head type={NULL};
 struct nm_super_head sb={.s_type=&type,.s_op=kernfs_ops};
 assert(nm_check_super_identity((void*)&sb,kernfs_ops)==-EOPNOTSUPP);
 type.name="sysfs";assert(!nm_check_super_identity((void*)&sb,native_ops));
 unsigned prior=allocations,old_published=published;
 sb.s_type=NULL;assert(nm_install_super_proxy((void*)&sb)==-EINVAL);
 sb.s_type=&type;sb.s_op=NULL;assert(nm_install_super_proxy((void*)&sb)==-EINVAL);
 sb.s_op=native_ops;fixture_kernfs_sops=NULL;
 assert(nm_install_super_proxy((void*)&sb)==-EOPNOTSUPP&&sb.s_op==native_ops);
 assert(allocations==prior&&published==old_published);
 // A later successful resolution may proceed; failure does not poison global state.
 fixture_kernfs_sops=kernfs_ops;assert(!nm_install_super_proxy((void*)&sb));free(last_alloc);
 puts("PASS identity: 9 filesystem fixtures, OEM/name independence, unavailable/type/op errors, retry and full table preservation");
 return 0;
}
'''

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    source=PRE+function('nomount/nm_inode.c','nm_check_super_identity')+function('nomount/nm_inode.c','nm_install_super_proxy')+TEST
    compile_run(source,args.output/'identity')
    log=(args.output/'identity.run.log').read_text()
    for message in ('kernfs s_op identity must be preserved','missing s_type or s_op','kernfs_sops unresolved; current rule rejected'):
        assert message in log,message
