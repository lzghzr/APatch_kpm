#!/usr/bin/env python3
"""DEV-054：保留1764条Oracle，重放物化交错及de1da148真实历史缺陷。"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
HISTORY = 'de1da1488399164580e0c9d3a5d21a10591bae64'
PRE = r'''
static void* dev054_ops;
static bool dev054_qualification_change,dev054_get_change,dev054_new_change;
static bool dev054_qualify(struct inode*i){
 bool ok=nm_plain_symlink_source(i);
 if(dev054_qualification_change){dev054_qualification_change=false;nm_set_operation_callback(dev054_ops,nm_link_put_slot,NULL);}
 return ok;
}
static int dev054_get(struct inode*i,void**data,u32*length){
 int rc=security_fixture_get(i,data,length);
 if(dev054_get_change){dev054_get_change=false;nm_set_operation_callback(dev054_ops,nm_link_put_slot,NULL);}
 return rc;
}
static struct inode*dev054_new(struct super_block*sb){
 struct inode*i=host_new(sb);
 if(dev054_new_change){dev054_new_change=false;nm_set_operation_callback(dev054_ops,8,complete_follow);nm_set_operation_callback(dev054_ops,nm_link_put_slot,complete_put);}
 return i;
}
'''
TEST = r'''
static void dev054_pair(void){
 nm_set_operation_callback(dev054_ops,8,complete_encrypted_follow);
 nm_set_operation_callback(dev054_ops,nm_link_put_slot,complete_free);
 nm_set_operation_callback(dev054_ops,nm_link_source_read_slot,complete_generic_readlink);
}
static void check_dev054(bool history){
 complete_mode=2;link_api=1;link_missing=0;security_fixture_reset();target();directory_target();
 struct_offset.iop_getattr=144;struct_offset.permission_abi=0;
 nm_inode_engine=(struct nm_inode_engine){0};nm_owned_dentry_ops=NULL;nm_virtual_directory_fops=NULL;
 kf_nm_kmalloc=memory_slab_miss;kf_nm_vzalloc=host_alloc;kf_nm_kvfree=memory_vmap_free;kf_nm_is_vmalloc_addr=memory_vmap;kf_nm_vfree_atomic=memory_vmap_free;
 kf_nm_path_get=binding_owned_get;kf_nm_path_put=binding_owned_put;
 fail_alloc=new_fail=splice_fail=0;complete_error=complete_security_error=0;race_slot=NULL;
 assert(!nm_prepare_inode_engine()&&nm_inode_engine.symlink_ops);
 assert(!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
 nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_op=original_sops;assert(!nm_install_super_proxy((void*)&sb));
 kf_nm_new_inode=dev054_new;kf_nm_d_splice_alias=host_splice;kf_nm_security_inode_getsecctx=dev054_get;
 _Alignas(8)unsigned char source_ops[512]={0},outer[256]={0};dev054_ops=source_ops;
 nm_inode_objects(backing)->i_op=source_ops;((struct nm_dentry_head*)dentry_storage)->d_inode=backing;
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0120777;security_set_sid(backing,37);dev054_pair();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};
 if(history){
  // 原历史函数，未改写其晚到的数组访问；同一真实宿主分配钩子置空put。
  race_slot=(const void**)(source_ops+nm_link_put_slot);race_value=NULL;
  (void)dev054_historical_materialize(parent,(void*)1234,&rule,42,true);
  fputs("historical negative-index path unexpectedly returned\n",stderr);abort();
 }
 int gets=binding_owned_gets,puts_before=binding_owned_puts,allocs=alloc_calls,contexts=security_gets;
 int native=complete_native_calls,cleanup=complete_puts;
 nm_set_operation_callback(source_ops,nm_link_put_slot,NULL);
 assert(nm_follow_pair_index(backing)==-1);
 assert(PTR_ERR(nm_materialize_symlink(parent,(void*)1234,&rule,42))==-EOPNOTSUPP);
 assert(alloc_calls==allocs&&security_gets==contexts&&binding_owned_gets==gets&&binding_owned_puts==puts_before);
 // 资格判断返回以后、捕获索引以前发生换槽：执行原函数的具名依赖适配副本。
 dev054_pair();dev054_qualification_change=true;
 assert(PTR_ERR(dev054_capture_interleave(parent,(void*)1234,&rule,42,true))==-EOPNOTSUPP);
 assert(!dev054_qualification_change&&nm_follow_pair_index(backing)==-1);
 assert(alloc_calls==allocs&&security_gets==contexts&&binding_owned_gets==gets&&binding_owned_puts==puts_before);
 // 三个可睡眠入口：getsecctx、info分配、new_inode；改变后不得调用源follow。
 for(unsigned point=0;point<3;point++){
  dev054_pair();gets=binding_owned_gets;puts_before=binding_owned_puts;native=complete_native_calls;
  if(point==0)dev054_get_change=true;
  if(point==1){race_slot=(const void**)(source_ops+nm_link_put_slot);race_value=NULL;}
  if(point==2)dev054_new_change=true; // 换成另一组合法page配对，不仅测未知配对。
  assert(!nm_materialize_symlink(parent,(void*)1234,&rule,43)&&created);
  struct inode*i=created;struct nm_inode_info*info=nm_inode_private(i);((struct nm_dentry_head*)outer)->d_inode=i;
  assert(info->link_put==complete_free&&info->r_path.dentry==backing_path.dentry&&nm_dentry_inode(info->r_path.dentry)==backing);
  assert(point==2?nm_follow_pair_index(backing)==1:nm_follow_pair_index(backing)==-1);
  void*cookie=(void*)123;
  assert(PTR_ERR(nm_symlink_follow_link((void*)outer,&cookie))==-EOPNOTSUPP&&!cookie&&complete_native_calls==native);
  assert(!dev054_get_change&&!dev054_new_change&&!race_slot&&!complete_heap&&complete_puts==cleanup);
  assert(binding_owned_gets==gets+1&&binding_owned_puts==puts_before&&security_gets==security_releases);
  host_iput(i);drain();((struct nm_dentry_head*)outer)->d_inode=NULL;
  assert(!created&&binding_owned_puts==puts_before+1);
 }
 // 成功cookie使用捕获的put和同一源inode，路径引用保留到evict。
 dev054_pair();gets=binding_owned_gets;puts_before=binding_owned_puts;cleanup=complete_puts;
 assert(!nm_materialize_symlink(parent,(void*)1234,&rule,44)&&created);
 struct inode*i=created;struct nm_inode_info*info=nm_inode_private(i);((struct nm_dentry_head*)outer)->d_inode=i;
 void*cookie=NULL;assert(!strcmp(nm_symlink_follow_link((void*)outer,&cookie),consistency_text)&&cookie==complete_heap&&cookie);
 assert(info->link_put==complete_free&&nm_dentry_inode(info->r_path.dentry)==backing);
 assert(binding_owned_gets==gets+1&&binding_owned_puts==puts_before);
 nm_set_operation_callback(source_ops,nm_link_put_slot,NULL);
 nm_symlink_put_link(i,cookie);
 assert(!complete_heap&&complete_puts==cleanup+1&&binding_owned_puts==puts_before);
 dev054_pair();native=complete_native_calls;cleanup=complete_puts;complete_error=-ENOENT;cookie=(void*)123;
 assert(PTR_ERR(nm_symlink_follow_link((void*)outer,&cookie))==-ENOENT&&!cookie&&complete_native_calls==native+1);
 assert(complete_puts==cleanup&&!complete_heap&&binding_owned_puts==puts_before);complete_error=0;
 host_iput(i);drain();((struct nm_dentry_head*)outer)->d_inode=NULL;
 assert(!created&&binding_owned_puts==puts_before+1&&security_gets==security_releases);
 // pair=0是合法simple/NULL，不能把非正数统统拒绝。
 nm_set_operation_callback(source_ops,8,complete_simple);nm_set_operation_callback(source_ops,nm_link_put_slot,NULL);
 assert(nm_follow_pair_index(backing)==0);
 gets=binding_owned_gets;puts_before=binding_owned_puts;
 assert(!nm_materialize_symlink(parent,(void*)1234,&rule,45)&&created);
 i=created;((struct nm_dentry_head*)outer)->d_inode=i;cookie=(void*)123;
 assert(!strcmp(nm_symlink_follow_link((void*)outer,&cookie),"../target")&&!cookie);
 host_iput(i);drain();assert(binding_owned_gets==gets+1&&binding_owned_puts==puts_before+1);
 assert(complete_puts==cleanup&&!complete_heap);((struct nm_dentry_head*)outer)->d_inode=NULL;
 nm_inode_objects(backing)->i_op=native_iops;
 nm_discard_directory_view();complete_mode=0;dev054_ops=NULL;
 puts("DEV-054 capture interleavings, negative rejection, changed-pair refusal and cookie/path balance PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('oracle-output', 'cli-source', 'reference-image', 'image', 'output'):
        p.add_argument('--' + n, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    current = (ROOT / 'nomount/nm_inode.c').read_text()
    old = subprocess.check_output(['git', 'show', HISTORY + ':nomount/nm_inode.c'], cwd=ROOT, text=True)
    historical = function(old, 'nm_materialize_backed_inode').replace('nm_materialize_backed_inode(', 'dev054_historical_materialize(', 1)
    interleave = function(current, 'nm_materialize_backed_inode').replace('nm_materialize_backed_inode(', 'dev054_capture_interleave(', 1).replace('nm_plain_symlink_source(', 'dev054_qualify(')
    rows = []
    for abi in ('int', 'bool'):
        source = original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = assertions(original)
        assert len(before) == 1764
        for n in ('nm_follow_pair_index', 'nm_plain_symlink_source', 'nm_materialize_backed_inode', 'nm_symlink_follow_link', 'nm_symlink_put_link'):
            source = source.replace(function(source, n), function(current, n), 1)
        assert assertions(source) == before
        source = source.replace('int main(int argc,char**argv)', 'static int previous_dev054_main(int argc,char**argv)', 1)
        source += '\n' + PRE + '\n' + historical + '\n' + interleave + '\n' + TEST
        source += '\nint main(int argc,char**argv){bool history=argc==4&&!strcmp(argv[3],"history");assert(!previous_dev054_main(history?3:argc,argv));check_dev054(history);return 0;}\n'
        assert assertions(source)[:1764] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        binary = out / 'contracts'
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', '-g', str(out / 'contracts.c'), str(a.cli_source), '-o', str(binary)], out / 'compile.log')
        command = [str(binary.resolve()), str(a.reference_image.resolve()), str(a.image.resolve())]
        run(command, out / 'run.log')
        env = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        result = subprocess.run(command + ['history'], capture_output=True, text=True, env=env)
        evidence = result.stdout + result.stderr
        (out / 'historical.log').write_text(evidence)
        assert result.returncode != 0 and re.search(r'index -1 out of bounds', evidence), evidence[-3000:]
        rows.append({'abi': abi, 'original_assert_sites': 1764, 'added_assert_sites': len(assertions(source)) - 1764, 'total_assert_sites': len(assertions(source)), 'result': 'PASS', 'historical_commit': HISTORY, 'historical_returncode': result.returncode, 'historical_ubsan': 'index -1 out of bounds'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer controlled interleavings and actual historical C-function replay; no kernel/device race proof', 'migrations': [], 'production_change': False, 'fix_already_present': 'aaa45a89410c690312561f128bd03bc80f80eb6e', 'rows': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
