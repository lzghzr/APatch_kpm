#!/usr/bin/env python3
"""DEV-057：保留1171处断言，提取真实入口prepare链，冷启动permission_abi=-1。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function as static_function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    # 联合入口还包括非static导出；宿主副本只改变其链接可见性。
    source = re.sub(r'(?m)^int ('+re.escape(name)+r'\()', r'static int \1', source)
    return static_function(source, name)


DIGESTS = {'int': 'fe404dedf8a68476ec53a837655c9ff5ce6b102909374b3e165f7621f1d42bf9',
           'bool': '260b6469d61269b7dcac353ef9f8956bd1c489b3558c2cf99769b1c6f80c8d1b'}
CHAIN = [
    ('nomount.c', 'nomount_init'),
    ('nm_control_entry.c', 'nm_prepare_control_engine'),
    ('nm_backing_entry.c', 'nm_prepare_backing_queries'),
    ('nm_topology_entry.c', 'nm_prepare_path_rules'),
    ('nm_directory_entry.c', 'nm_prepare_directory_view'),
    ('nm_inode_entry.c', 'nm_prepare_materialization'),
    ('nm_inode.c', 'nm_prepare_inode_engine'),
    ('nm_setattr.c', 'nm_prepare_setattr'),
    ('nm_offsets.c', 'nm_prepare_permission_abi'),
    ('nm_backing_inode.c', 'nm_prepare_backing_inode_engine'),
    ('nm_backing_inode.c', 'nm_prepare_backing_inode_functions'),
]
PRE = r'''
#ifndef nm_log_info
#define nm_log_info(...) ((void)0)
#endif
static bool cold_initialized;
static unsigned cold_count,cold_queries,cold_fallbacks,cold_setattr_queries;
static int cold_mode,cold_error,cold_first_permission;
static const char*cold_trace[64];
static void cold_note(const char*n){assert(cold_count<64);cold_trace[cold_count++]=n;}
/* 只替代宿主无法执行的叶子布局/原生环境查询；中间prepare函数体直接提取生产代码。 */
static int cold_offsets(void){return 0;}
static int cold_rule_layout(void){return 0;}
static int cold_file_layout(void){return nm_validate_file_offsets((const void*)&struct_offset);}
static int cold_native(void){return 0;}
static int cold_file_functions(void){return 0;}
static int cold_control_layout(void){return nm_validate_control_layout();}
static int cold_permission_btf(bool*unavailable){
 if(!cold_queries)cold_first_permission=struct_offset.permission_abi;cold_queries++;
 *unavailable=cold_mode==0;
 if(cold_error)return cold_error;
 if(!cold_mode)return -ENODATA;
 struct_offset.permission_abi=0;return 0;
}
static int cold_permission_anchor(void){cold_fallbacks++;struct_offset.permission_abi=0;return 0;}
static int cold_setattr_btf(struct nm_setattr_layout*l,bool*unavailable){
 (void)l;cold_setattr_queries++;assert(struct_offset.permission_abi==0);*unavailable=true;return -ENODATA;
}
'''
TEST = r'''
static void cold_reset(void){
 nm_discard_directory_view();target();directory_target();control_reference();
 struct_offset.permission_abi=-1;nm_topology_ready=false;nm_backing_open_permission=NULL;
 cold_initialized=false;cold_count=cold_queries=cold_fallbacks=cold_setattr_queries=0;
 cold_mode=cold_error=0;cold_first_permission=999;
 fail_alloc=0;control_missing=NULL;control_register_error=0;missing=NULL;link_missing=0;
}
static void check_cold_prepare_chain(void){
 const char*expected[]={"nomount_init","nm_prepare_control_engine","nm_prepare_backing_queries","nm_prepare_path_rules",
  "nm_prepare_directory_view","nm_prepare_materialization","nm_prepare_inode_engine","nm_prepare_setattr","nm_prepare_permission_abi"};
 const char*events[]={"post-fs-data","post-kernel-init",NULL};
 for(unsigned event=0;event<3;event++)for(int btf=0;btf<2;btf++){
  cold_reset();cold_mode=btf;
  assert(struct_offset.permission_abi==-1);
  int rc=cold_nomount_init(NULL,events[event],NULL);
  if(rc){fprintf(stderr,"cold init rc=%d permission=%d trace:",rc,struct_offset.permission_abi);for(unsigned n=0;n<cold_count;n++)fprintf(stderr," %s",cold_trace[n]);fputc('\n',stderr);}
  assert(!rc&&cold_initialized&&nm_registered_key_type);
  assert(cold_count>=sizeof(expected)/sizeof(expected[0]));
  for(unsigned n=0;n<sizeof(expected)/sizeof(expected[0]);n++)assert(!strcmp(cold_trace[n],expected[n]));
  assert(cold_first_permission==-1&&struct_offset.permission_abi==0&&cold_queries==2);
  assert(cold_setattr_queries==1&&cold_fallbacks==(btf?0:2)&&nm_setattr_status==-EOPNOTSUPP);
  int second;assert(nm_setattr_slots(&second)==112&&second==120);
  assert(nm_operation_callback(nm_inode_engine.inode_ops,112)==nm_setattr);
  assert(nm_operation_callback(nm_inode_engine.directory_ops,112)==nm_setattr);
  printf("cold chain event=%s query=%s: unset permission -> 0 -> slots=112/120 -> registered PASS\n",events[event]?events[event]:"runtime",btf?"BTF stub":"anchor stub");
  fixture_end_registration();cold_initialized=false;
 }
 const int errors[]={-ENOENT,-EINVAL,-EOPNOTSUPP};
 for(unsigned e=0;e<sizeof(errors)/sizeof(errors[0]);e++){
  cold_reset();cold_mode=1;cold_error=errors[e];
  assert(cold_nomount_init(NULL,"post-fs-data",NULL)==errors[e]);
  assert(cold_first_permission==-1&&struct_offset.permission_abi==-1&&cold_queries==1&&!cold_fallbacks&&!cold_setattr_queries);
  assert(!nm_registered_key_type&&!nm_management_mutex&&!nm_inode_engine.inode_ops&&!nm_inode_engine.file_ops&&!cold_initialized);
 }
 /* 独立调用同样显式准备自己的依赖，不要求先调用backing阶段。 */
 cold_reset();assert(!cold_nm_prepare_setattr()&&cold_first_permission==-1&&struct_offset.permission_abi==0&&cold_queries==1);
 cold_reset();assert(nm_prepare_setattr()==-EOPNOTSUPP&&struct_offset.permission_abi==-1);
 assert(!manager_depth&&!rcu_depth&&!q_count);puts("DEV-057 cold actual prepare chain, standalone dependency and error short-circuit PASS");
}
int main(void){assert(!previous_prepare_chain_main());check_cold_prepare_chain();return 0;}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    permission = function((ROOT / 'nomount/nm_offsets.c').read_text(), 'nm_prepare_permission_abi')
    setter = function((ROOT / 'nomount/nm_setattr.c').read_text(), 'nm_prepare_setattr')
    names = {name: 'cold_'+name for _, name in CHAIN}
    names.update({'nm_initialized': 'cold_initialized', 'calculate_offsets': 'cold_offsets',
                  'nm_prepare_rule_layout': 'cold_rule_layout', 'nm_prepare_file_layout': 'cold_file_layout',
                  'nm_prepare_native': 'cold_native', 'nm_prepare_control_layout': 'cold_control_layout',
                  'nm_prepare_file_functions': 'cold_file_functions',
                  'calculate_btf_backing_inode_abi': 'cold_permission_btf',
                  'calculate_function_permission_abi': 'cold_permission_anchor',
                  'calculate_btf_setattr': 'cold_setattr_btf', 'kallsyms_lookup_name_by_suffix': 'cold_lookup'})
    clones = []
    # 反序声明使真实调用者见到完整被调用者；每个函数仅改宿主命名与插入追踪。
    for file, name in reversed(CHAIN):
        code = function((ROOT / 'nomount' / file).read_text(), name)
        code = re.sub(r'\b('+'|'.join(names)+r')\b', lambda m: names[m[0]], code)
        at = code.index('{')+1
        code = code[:at]+f'\n  cold_note("{name}");'+code[at:]
        clones.append(code)
    prototypes = '\n'.join(code.split('{', 1)[0].strip()+';' for code in clones)
    lookup = '''static unsigned long cold_lookup(const char*n){return !strcmp(n,"inode_permission")||!strcmp(n,"inode_permission2")?mount_function_lookup(n):kallsyms_lookup_name_by_suffix(n);}\n'''
    cold = PRE+lookup+prototypes+'\n#undef CONFIG_KPM_BASELINES\n'+'\n'.join(clones)+'\n#define CONFIG_KPM_BASELINES 1\n'
    rows = []
    for abi, digest in DIGESTS.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1171
        source = original.replace(function(original, 'nm_prepare_setattr'), permission+'\n'+setter, 1)
        dynamic = setter.replace('nm_prepare_setattr(', 'sn_prepare_dynamic(', 1).replace('calculate_btf_setattr(', 'sn_btf(').replace('kallsyms_lookup_name_by_suffix(', 'sn_lookup(')
        source = source.replace(function(source, 'sn_prepare_dynamic'), dynamic, 1)
        assert re.findall(r'\bassert\s*\([^;]+\);', source) == before
        entry = 'int main(void){assert(!previous_compound_main());check_setattr_compound();return 0;}'
        assert source.count(entry) == 1
        source = source.replace(entry, entry.replace('int main(', 'static int previous_prepare_chain_main('), 1)+cold+TEST
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert after[:len(before)] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn',
             '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'),
             str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before),
                     'total_assert_sites': len(after), 'result': 'PASS'})
    receipt = {'scope': 'Developer host actual prepare function bodies; leaf layout/native/BTF queries mocked, not real device loading',
               'chain': [f'nomount/{file}:{name}' for file, name in CHAIN], 'host': rows}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
