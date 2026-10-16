#!/usr/bin/env python3
"""执行实际KPM入口的加载事件和失败清理；宿主结果不证明开机时序。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ORACLE_COMMIT = 'f70894744b10d7aab212d18a9262e905eacef7d9'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads((args.oracle_output / 'receipt.json').read_text())
    original = (args.oracle_output / 'contracts.c').read_text()
    assert sha(original.encode()) == receipt['generated_source_sha256']
    for path, digest in receipt['sources'].items():
        assert sha(subprocess.check_output(['git', 'show', ORACLE_COMMIT + ':' + path], cwd=root)) == digest
        assert sha((root / path).read_bytes()) == digest
    assert sha(subprocess.check_output(['git', 'show', ORACLE_COMMIT + ':nomount/tools/test_mount_abis.py'], cwd=root)) == receipt['tool_sha256']
    args.output.mkdir(parents=True, exist_ok=False)
    assert original.count('int main(void)') == 1
    source = original.replace('int main(void)', 'static int previous_contract_main(void)')
    assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
    assert re.findall(r'\bassert\s*\([^;]+\);', source) == assertions
    source += r'''
static int entry_prepare_error,entry_btf_error,entry_prepare_calls,entry_btf_calls,entry_copy_short;
static int nm_prepare_backing_queries(void){
 entry_prepare_calls++;if(entry_prepare_error)return entry_prepare_error;
 int rc=nm_prepare_inode_engine();if(!rc)rc=nm_prepare_directory_engine();
 if(!rc)rc=nm_prepare_virtual_directory_engine();if(!rc)rc=nm_prepare_backing_inode_engine();
 if(!rc)rc=nm_prepare_topology_functions();if(!rc)rc=nm_prepare_backing_subtrees();return rc;
}
static int calculate_btf_control_layout(void){entry_btf_calls++;return entry_btf_error;}
'''
    constructor = (root / 'nomount/nm_control_entry.c').read_text()
    constructor = constructor[constructor.index('int nm_prepare_control_engine'):]
    source += constructor
    source += '#undef CONFIG_KPM_BASELINES\n#define nm_prepare_control_engine nm_prepare_dynamic_control_engine\n'
    source += constructor
    source += '#undef nm_prepare_control_engine\n#define CONFIG_KPM_BASELINES 1\n'
    source += r'''
static int entry_copy(void* out,const void* data,int size){assert(out&&size>0);memcpy(out,data,size-entry_copy_short);return size-entry_copy_short;}
#define compat_copy_to_user entry_copy
#define KPM_NAME(...)
#define KPM_VERSION(...)
#define KPM_LICENSE(...)
#define KPM_AUTHOR(...)
#define KPM_DESCRIPTION(...)
#define KPM_INFO(...)
#define KPM_INIT(...)
#define KPM_CTL0(...)
#define KPM_EXIT(...)
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
'''
    entry = (root / 'nomount/nomount.c').read_text().replace('#include <kpmodule.h>', '').replace('#include "nm_control_entry.c"', '')
    source += entry
    # 编译同一入口的动态模式，覆盖BTF错误经入口传播；不模拟真实BTF就绪时间。
    source += '#undef CONFIG_KPM_BASELINES\n#undef NM_OFFSET_MODE\n'
    source += '#define nm_prepare_control_engine nm_prepare_dynamic_control_engine\n#define nm_initialized nm_dynamic_initialized\n'
    source += '#define nomount_init nomount_dynamic_init\n#define nomount_ctl0 nomount_dynamic_ctl0\n#define nomount_exit nomount_dynamic_exit\n'
    source += entry
    source += '#undef nm_prepare_control_engine\n#undef nm_initialized\n#undef nomount_init\n#undef nomount_ctl0\n#undef nomount_exit\n'
    source += r'''
static void entry_clean(void){assert(!nm_management_mutex&&!nm_registered_key_type&&!nm_owned_dentry_ops&&!nm_virtual_directory_fops&&!nm_inode_engine.inode_ops&&!nm_inode_engine.file_ops&&!nm_topology_ready&&!nm_initialized&&!nm_dynamic_initialized);}
static void fixture_end_registration(void){
 fixture_vfree(control_native_table);control_native_table=nm_registered_key_type=NULL;
 nm_discard_management_mutex();nm_discard_directory_view();nm_topology_ready=false;nm_initialized=nm_dynamic_initialized=false;
}
int main(void){
 assert(!previous_contract_main());
 const char* events[]={"pre-kernel-init","post-kernel-init",NULL};
 for(unsigned int e=0;e<sizeof(events)/sizeof(events[0]);e++){
  target();directory_target();control_reference();
  char out[128]={0};assert(nomount_ctl0(NULL,out,sizeof(out))==-ENODEV);
  int calls=entry_prepare_calls;assert(nomount_init("unexpected",events[e],NULL)==-EINVAL&&entry_prepare_calls==calls);
  entry_prepare_error=-ENOENT;assert(nomount_init(NULL,events[e],NULL)==-ENOENT&&entry_prepare_calls==calls+1);
  assert(!nomount_exit(NULL));entry_clean();entry_prepare_error=0;
  int btf_calls=entry_btf_calls;entry_btf_error=-ENODATA;
  assert(nomount_dynamic_init(NULL,events[e],NULL)==-ENODATA&&entry_btf_calls==btf_calls+1);
  assert(!nomount_dynamic_exit(NULL));entry_clean();entry_btf_error=0;
  control_register_error=-EEXIST;assert(nomount_init(NULL,events[e],NULL)==-EEXIST);
  assert(!nomount_exit(NULL));entry_clean();control_register_error=0;
  for(int n=1;n<=7;n++){fail_alloc=n;assert(nomount_init(NULL,events[e],NULL)==-ENOMEM);fail_alloc=0;assert(!nomount_exit(NULL));entry_clean();}
  assert(!nomount_init("",events[e],NULL)&&nm_initialized&&nm_registered_key_type&&nm_management_mutex);
  assert(!nomount_ctl0("status",out,sizeof(out))&&!strcmp(out,"NoMount " NM_KPM_VERSION "; offsets=static; lifetime=reboot"));
  assert(nomount_ctl0("unknown",out,sizeof(out))==-EINVAL&&nomount_ctl0("status",NULL,sizeof(out))==-EINVAL&&nomount_ctl0(NULL,out,1)==-EINVAL);
  entry_copy_short=1;assert(nomount_ctl0("status",out,sizeof(out))==-EFAULT);entry_copy_short=0;
  int freed=frees;assert(!nomount_exit(NULL)&&frees==freed&&nm_registered_key_type&&nm_management_mutex&&nm_inode_engine.inode_ops);
  fixture_end_registration();entry_clean();
  assert(!nomount_dynamic_init(NULL,events[e],NULL)&&nm_dynamic_initialized&&nm_registered_key_type);
  assert(!nomount_dynamic_ctl0("status",out,sizeof(out))&&!strcmp(out,"NoMount " NM_KPM_VERSION "; offsets=dynamic; lifetime=reboot"));
  fixture_end_registration();entry_clean();
 }
 assert(!manager_depth&&!rcu_depth&&!q_count);
 puts("pre/post/runtime events, dependency/BTF/registration errors, allocation cleanup, status and resident exit: PASS");return 0;
}
'''
    c = args.output / 'events.c'
    c.write_text(source)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'events')]
    built = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    run = subprocess.run([str(args.output / 'events')], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    files = ['nomount/nomount.c', 'nomount/nm_control_entry.c', 'nomount/tools/test_load_events.py']
    result = {'scope': 'Developer host entry/constructor stubs; not native pre-init readiness or device proof',
              'oracle_commit': ORACLE_COMMIT, 'oracle_receipt_sha256': sha((args.oracle_output / 'receipt.json').read_bytes()),
              'assertions_preserved': len(assertions), 'generated_source_sha256': sha(source.encode()),
              'sources': {p: sha((root / p).read_bytes()) for p in files}, 'result': run.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(run.stdout)


if __name__ == '__main__':
    main()
