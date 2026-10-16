#!/usr/bin/env python3
"""执行 KPM 生命周期与静态配置替换；原生准备由宿主调用契约夹具代替。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'baselines', 'config', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    oracle = json.loads((args.oracle_output / 'receipt.json').read_text())
    assert oracle['tool_sha256'] == sha(root / 'nomount/tools/test_control.py')
    assert all(sha(root / p) == h for p, h in oracle['sources'].items())
    args.output.mkdir(parents=True, exist_ok=False)
    base = (args.oracle_output / 'control.c').read_text()
    assert base.count('int main(void)') == 1
    source = base.replace('int main(void)', 'int control_contract_main(void)')
    source += r'''
static int entry_prepare_error,entry_btf_error,entry_btf_calls,entry_copy_short,entry_prepare_calls;
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
    entry = (root / 'nomount/nomount.c').read_text()
    source += entry.replace('#include <kpmodule.h>', '').replace('#include "nm_control_entry.c"', '')
    source += r'''
static void entry_clean(void){assert(!nm_management_mutex&&!nm_registered_key_type&&!nm_owned_dentry_ops&&!nm_virtual_directory_fops&&!nm_inode_engine.inode_ops&&!nm_inode_engine.file_ops&&!nm_topology_ready&&!nm_initialized);}
int main(void){
 assert(!control_contract_main());target();directory_target();control_reference();
 char out[128]={0};assert(nomount_ctl0(NULL,out,sizeof(out))==-ENODEV);
 int calls=entry_prepare_calls;assert(nomount_init("unexpected","post-kernel-init",NULL)==-EINVAL&&entry_prepare_calls==calls);
 assert(nomount_init(NULL,"pre-kernel-init",NULL)==-EAGAIN&&entry_prepare_calls==calls);
 entry_prepare_error=-ENOENT;assert(nomount_init(NULL,"post-kernel-init",NULL)==-ENOENT);assert(!nomount_exit(NULL));entry_clean();entry_prepare_error=0;
 // 执行真实联合构造器的动态布局失败路径；BTF查询接口由夹具代替。
 entry_btf_error=-ENODATA;assert(nm_prepare_dynamic_control_engine()==-ENODATA&&entry_btf_calls==1);entry_clean();entry_btf_error=0;
 control_register_error=-EEXIST;assert(nomount_init(NULL,"post-kernel-init",NULL)==-EEXIST);assert(!nomount_exit(NULL));entry_clean();control_register_error=0;
 for(int n=1;n<=7;n++){fail_alloc=n;assert(nomount_init(NULL,"post-kernel-init",NULL)==-ENOMEM);fail_alloc=0;assert(!nomount_exit(NULL));entry_clean();}
 assert(!nomount_init("","post-kernel-init",NULL)&&nm_initialized&&nm_registered_key_type&&nm_management_mutex);
 assert(!nomount_ctl0("status",out,sizeof(out))&&!strcmp(out,"NoMount " NM_KPM_VERSION "; offsets=static; lifetime=reboot"));
 assert(nomount_ctl0("unknown",out,sizeof(out))==-EINVAL&&nomount_ctl0("status",NULL,sizeof(out))==-EINVAL&&nomount_ctl0(NULL,out,1)==-EINVAL);
 entry_copy_short=1;assert(nomount_ctl0("status",out,sizeof(out))==-EFAULT);entry_copy_short=0;
 int freed=frees;assert(!nomount_exit(NULL)&&frees==freed&&nm_registered_key_type&&nm_management_mutex&&nm_inode_engine.inode_ops);
 // 宿主运行结束释放模拟注册与未安装视图；生产exit只作驻留诊断。
 fixture_vfree(control_native_table);control_native_table=nm_registered_key_type=NULL;nm_discard_management_mutex();nm_discard_directory_view();nm_initialized=false;
 assert(!manager_depth&&!rcu_depth&&!q_count);puts("KPM phase, constructor failures, seven allocation failures, status and resident exit: PASS");return 0;}
'''
    c = args.output / 'entry.c'; c.write_text(source)
    compile_result = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-I' + str(root / 'nomount'),
                                     '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'entry')], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compile_result.stdout + compile_result.stderr); compile_result.check_returncode()
    run = subprocess.run([str(args.output / 'entry')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr); run.check_returncode()
    spec = importlib.util.spec_from_file_location('offset_tool', root / 'patch_offsets.py')
    tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
    fields = tool.source_fields(root / 'nomount/nm_offsets.c')
    values = json.loads(args.config.read_text())['offsets']; assert set(fields) == set(values) and len(fields) == 38
    binaries = []
    for base in sorted(args.baselines.glob('*_baselines*.kpm')):
        before = base.read_bytes(); offset, size, abi = tool.sections(before)
        layout = tool.read_layout(Path(str(base) + '.json'), before, offset, size, abi)
        assert layout['fields'] == fields and size == 76 and set(tool.table_values(before, offset, size, fields).values()) == {-1}
        patched = args.output / ('target-' + base.name)
        commands = [[sys.executable, str(root / 'patch_offsets.py'), 'patch', str(base), '--offsets', str(args.config), '--output', str(patched)],
                    [sys.executable, str(root / 'patch_offsets.py'), 'dump', str(patched), '--output', str(args.output / (base.name + '.bin'))],
                    [sys.executable, str(root / 'patch_offsets.py'), 'patch', str(base), '--blob', str(args.output / (base.name + '.bin')), '--output', str(args.output / ('blob-' + base.name))],
                    [sys.executable, str(root / 'patch_offsets.py'), 'patch', str(patched), '--offsets', str(Path(str(base) + '.json')), '--output', str(args.output / ('restored-' + base.name))]]
        for number, command in enumerate(commands):
            result = subprocess.run(command, text=True, capture_output=True)
            (args.output / (base.name + f'-{number}.log')).write_text(result.stdout + result.stderr); result.check_returncode()
        after = patched.read_bytes(); assert len(after) == len(before) and after[:offset] == before[:offset] and after[offset+size:] == before[offset+size:]
        encoded = tool.encode_offsets(args.config, fields); assert after[offset:offset+size] == encoded
        assert (args.output / ('blob-' + base.name)).read_bytes() == after
        assert (args.output / ('restored-' + base.name)).read_bytes() == before
        binaries.append({'base': base.name, 'base_sha256': sha(base), 'derived_sha256': sha(patched), 'table_offset': offset, 'table_size': size})
    assert len(binaries) == 2
    files = ['nomount/nomount.c', 'nomount/Makefile', 'nomount/configs/boot_los23.2.json', 'patch_offsets.py']
    receipt = {'scope': 'Developer host lifecycle and binary roundtrip; not native startup, CFI or device proof',
               'sources': {p: sha(root / p) for p in files}, 'tool_sha256': sha(Path(__file__)),
               'oracle_receipt_sha256': sha(args.oracle_output / 'receipt.json'), 'binaries': binaries, 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n'); print(run.stdout.strip().splitlines()[-1]); print('Static JSON/blob roundtrip and configuration-only mutation: PASS')


if __name__ == '__main__':
    main()
