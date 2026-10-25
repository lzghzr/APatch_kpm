#!/usr/bin/env python3
"""保留1659处Oracle，追加控制注册路径的可达性与memdup_user错误透传。"""
import argparse
import json
from pathlib import Path
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
static void check_registered_components(void);
'''
TEST=r'''
static unsigned reach_lookup_calls,reach_hash_calls;
static typeof(kf_nm_vfs_path_lookup) reach_original_lookup;
static typeof(kf_nm_d_hash_and_lookup) reach_original_hash;
static int reach_lookup(struct dentry*d,struct vfsmount*m,const char*n,unsigned f,struct nm_path*p){
 reach_lookup_calls++;return reach_original_lookup(d,m,n,f,p);
}
static struct dentry*reach_hash(struct dentry*d,struct nm_qstr*n){
 reach_hash_calls++;return reach_original_hash(d,n);
}
static void check_registered_components(void){
 bool reads=nm_xattr_reads_ready,writes=nm_xattr_writes_ready;
 nm_xattr_reads_ready=nm_xattr_writes_ready=true;
 reach_original_lookup=kf_nm_vfs_path_lookup;reach_original_hash=kf_nm_d_hash_and_lookup;
 kf_nm_vfs_path_lookup=reach_lookup;kf_nm_d_hash_and_lookup=reach_hash;
 const char*paths[]={"/system/.","/system/foo/..","/system//x"};
 for(unsigned i=0;i<3;i++){
  assert(nm_rule_path_valid(paths[i],strlen(paths[i])));
  assert(nm_topology_path_valid(paths[i],strlen(paths[i]))==-EINVAL);
  struct nm_topology_leaf*leaves=nm_topology_leaves;unsigned lookup=reach_lookup_calls,hash=reach_hash_calls;
  control_request(NM_CMD_ADD_RULE);control_append(paths[i],"/file",0,1000);
  int rc=control_send();
  assert(rc==-EINVAL&&control_user.status==-EINVAL&&nm_topology_leaves==leaves);
  assert(reach_lookup_calls==lookup&&reach_hash_calls==hash);
  printf("virtual %s: EINVAL; backing child lookup delta=0, topology lookup delta=0\n",paths[i]);
 }
 assert(nm_topology_path_valid("/system/x",9)==0);
 // 真实错误契约仅为ERR_PTR；不构造NULL返回。
 unsigned dups=control_dup_calls,copies=control_copy_calls;
 control_request(NM_CMD_GET_VERSION);control_dup_error=-ENOMEM;
 assert(control_transport(8)==-ENOMEM&&control_dup_calls==dups+1&&control_copy_calls==copies);
 control_dup_error=-EFAULT;
 assert(control_transport(8)==-EFAULT&&control_dup_calls==dups+2&&control_copy_calls==copies);
 control_dup_error=0;
 kf_nm_vfs_path_lookup=reach_original_lookup;kf_nm_d_hash_and_lookup=reach_original_hash;
 nm_xattr_reads_ready=reads;nm_xattr_writes_ready=writes;
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('oracle-output','cli-source','reference-image','image','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for abi in ('int','bool'):
  original=(a.oracle_output/abi/'contracts.c').read_text();before=assertions(original);assert len(before)==1659
  source=original.replace(function(original,'nm_exchange_payload'),function((ROOT/'nomount/nm_native.c').read_text(),'nm_exchange_payload'),1)
  source=source.replace(function(source,'nm_xattr_signature_frame'),function((ROOT/'nomount/nm_xattr_signature.c').read_text(),'nm_xattr_signature_frame'),1)
  assert assertions(source)==before
  marker='static int oracle_main(void){';assert source.count(marker)==1;source=source.replace(marker,PRE+marker,1)
  marker='assert(!nm_register_control()&&nm_registered_key_type==control_native_table&&nm_register_control()==-EALREADY);'
  assert source.count(marker)==1;source=source.replace(marker,marker+'check_registered_components();',1)
  source+=TEST
  assert assertions(source)[:1659]==before
  out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
  run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
  run([str((out/'contracts').resolve()),str(a.reference_image.resolve()),str(a.image.resolve())],out/'run.log')
  rows.append({'abi':abi,'original_assert_sites':1659,'added_assert_sites':len(assertions(source))-1659,'total_assert_sites':len(assertions(source)),'result':'PASS'})
 (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer production registration chain and host native stubs; not native pathwalk/device proof','host':rows},indent=2)+'\n');print(rows)
if __name__=='__main__':main()
