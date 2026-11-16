#!/usr/bin/env python3
"""规则失败范围回归：原样执行规则 Oracle，追加真实拓扑/控制函数及重定位 shell。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from test_nomount_v230 import function

ROOT = Path(__file__).resolve().parents[2]


def execute(command, log, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    log.write_text(result.stdout + result.stderr)
    result.check_returncode()
    return result.stdout


C_PRE = r'''
static struct nm_super_head fixture_target_super = {.s_magic=0xEF53UL};
static struct super_block *nm_inode_superblock(struct inode *inode) {
  (void)inode; return (void*)&fixture_target_super;
}
#define nm_log_error(...) fprintf(stderr,__VA_ARGS__)
static struct { void *materialize_directory, *lookup_backing; } nm_inode_engine = {(void*)1,(void*)1};
static struct nm_directory_node *native_node;
static void (*kf_nm_d_drop)(struct dentry*);
static void (*kf_nm_dput)(struct dentry*);
static int nm_prepare_topology_abi(void) { return 0; }
static bool nm_is_directory_inode(struct inode *inode) { (void)inode; return false; }
static struct nm_directory_node *nm_inode_directory_node(struct inode *inode) {
  assert(inode == (struct inode*)&dir_inode); return native_node;
}
static int nm_install_directory(struct inode *inode, struct nm_directory_node *node) {
  assert(inode == (struct inode*)&dir_inode);
  if (native_node) assert(native_node == node);
  else { native_node=node; nm_directory_node_get(node); }
  return 0;
}
static struct dentry *cached_child(struct dentry *parent, struct nm_qstr *name) {
  assert(parent==(void*)&dir_dentry && name->len); return NULL;
}
static void shrink_parent(struct dentry *parent) { assert(parent==(void*)&dir_dentry); }
static int alias_path(const char *name,unsigned flags,struct nm_path *path) {
  return host_path(!strcmp(name,"/data/alias") ? "/data/dir" : name,flags,path);
}
'''
C_CONTROL = r'''
static void *nm_management_mutex=(void*)1;
static void nm_management_lock(void) {}
static void nm_management_unlock(void) {}
static int fail_stage, api_calls;
// Exercise the new publication dependency without replacing xattr's three existing stages.
static int nm_activate_mutation_guards_locked(void) { return fail_stage==4 ? -EOPNOTSUPP : 0; }
static int nm_activate_xattr_reads_locked(void) { api_calls++; return fail_stage==1 ? -EOPNOTSUPP : 0; }
static int nm_activate_xattr_writes_locked(void) { api_calls++; return fail_stage==2 ? -EOPNOTSUPP : 0; }
static int nm_activate_xattr_extra_locked(void) { api_calls++; return fail_stage==3 ? -ENOENT : 0; }
'''
C_TEST = r'''
static int add_request(const char *virtual, bool whiteout) {
  struct nm_payload payload={.magic=NOMOUNT_MAGIC_SIG,.cmd=NM_CMD_ADD_RULE};
  const char *real=whiteout ? "" : "/data/file";
  struct nm_rule_hdr h={.flags=whiteout ? NM_FLAG_WHITEOUT : 0,.v_len=strlen(virtual),.r_len=strlen(real)};
  memcpy(payload.buffer,&h,sizeof(h));
  memcpy(payload.buffer+sizeof(h),virtual,h.v_len);
  memcpy(payload.buffer+sizeof(h)+h.v_len,real,h.r_len);
  payload.data_size=sizeof(h)+h.v_len+h.r_len;
  return nm_execute_payload(&payload);
}
static bool has_path(const char *path) { return nm_topology_find(path,strlen(path)) != NULL; }
static void clear_tree(void) {
  struct nm_topology_updates updates={0};
  assert(!nm_topology_clear_locked(&updates)); nm_finish_topology_updates(&updates);
  nm_directory_node_put(native_node); native_node=NULL; flush_callbacks();
  assert(!nm_topology_leaves && !nm_topology_anchors && !path_refs && allocated==released && !depth);
}
int main(void) {
  assert(!rules_oracle_main());
  nm_topology_ready=true; kf_nm_d_hash_and_lookup=cached_child; kf_nm_shrink_dcache_parent=shrink_parent;
  kf_nm_kern_path=alias_path;
  for (fail_stage=1;fail_stage<=3;fail_stage++) {
    api_calls=0;
    assert(!add_request("/data/dir/hidden",true) && !api_calls && has_path("/data/dir/hidden"));
    assert(!add_request("/data/dir/hidden",true) && !api_calls); // 替换仍是原生父目录负项。
    assert(add_request("/data/alias/hidden",true)==-EEXIST && !api_calls);
    assert(has_path("/data/dir/hidden") && !has_path("/data/alias/hidden"));
    assert(add_request("/data/dir/ordinary",false)<0 && api_calls==fail_stage);
    assert(!has_path("/data/dir/ordinary") && has_path("/data/dir/hidden"));
    api_calls=0;
    assert(add_request("/data/dir/new/sub/hidden",true)<0 && api_calls==fail_stage);
    assert(!has_path("/data/dir/new") && !has_path("/data/dir/new/sub"));
    assert(!has_path("/data/dir/new/sub/hidden") && has_path("/data/dir/hidden"));
    clear_tree();
  }
  // 已有管理目录下的白化不能借纯 WHITEOUT 标志绕过能力准备。
  fail_stage=0; api_calls=0;
  struct nomount_rule *directory=nm_alloc_rule("/data/dir",9,0,0);
  assert(!IS_ERR(directory)); struct nm_topology_updates updates={0};
  assert(!nm_topology_add_prepared_locked("/data/dir/view",14,directory,&updates,nm_control_prepare_inodes));
  assert(api_calls==3); fail_stage=2; api_calls=0;
  assert(add_request("/data/dir/view/hidden",true)==-EOPNOTSUPP && api_calls==2);
  assert(has_path("/data/dir/view") && !has_path("/data/dir/view/hidden"));
  clear_tree();
  // 入口齐全时，新增虚拟父链/普通文件仍正常发布。
  fail_stage=0; api_calls=0;
  assert(!add_request("/data/dir/new/hidden",true) && api_calls==3);
  assert(!add_request("/data/dir/new/file",false) && api_calls==6);
  clear_tree();
  // 同一控制批次中的失败也不撤销前后已经成功的独立规则。
  struct nm_payload batch={.magic=NOMOUNT_MAGIC_SIG,.cmd=NM_CMD_ADD_RULE};
  const char *names[]={"/data/dir/first","/data/dir/fails","/data/dir/last"};
  for(unsigned i=0;i<3;i++) {
    const char *real=i==1 ? "/data/file" : "";
    struct nm_rule_hdr h={.flags=i==1 ? 0 : NM_FLAG_WHITEOUT,.v_len=strlen(names[i]),.r_len=strlen(real)};
    char *cursor=batch.buffer+batch.data_size;
    memcpy(cursor,&h,sizeof(h)); memcpy(cursor+sizeof(h),names[i],h.v_len);
    memcpy(cursor+sizeof(h)+h.v_len,real,h.r_len);
    batch.data_size+=sizeof(h)+h.v_len+h.r_len;
  }
  fail_stage=2;api_calls=0;
  assert(nm_execute_payload(&batch)==-EOPNOTSUPP && api_calls==2 && batch.arg1==batch.data_size);
  assert(has_path(names[0]) && !has_path(names[1]) && has_path(names[2]));
  clear_tree();
  // 独立拓扑调用者保留原入口，控制层才承担首次接线。
  struct nomount_rule *ordinary=nm_alloc_rule("/data/file",10,0,0);
  assert(!IS_ERR(ordinary)); api_calls=0; fail_stage=1;
  assert(!nm_topology_add_locked("/data/dir/legacy",16,ordinary,&updates) && !api_calls);
  clear_tree();
  // 新的 mutation 依赖不可用时，失败仍局限于需要虚拟 inode 的规则。
  fail_stage=0; api_calls=0;
  assert(!add_request("/data/dir/retained",false));
  fail_stage=4;
  assert(!add_request("/data/dir/hidden",true));
  assert(add_request("/data/dir/newfile",false)==-EOPNOTSUPP);
  assert(add_request("/data/dir/newparent/hidden",true)==-EOPNOTSUPP);
  assert(has_path("/data/dir/retained")&&has_path("/data/dir/hidden"));
  assert(!has_path("/data/dir/newfile")&&!has_path("/data/dir/newparent"));
  clear_tree();
  puts("publication scope: native whiteout, replacement, gated backing/virtual parents, rollback and legacy caller PASS");
  return 0;
}
'''

CLI = r'''#!PYTHON
import json,os,sys
from pathlib import Path
a=sys.argv[1:]; base=Path(os.environ['CASE_BASE']); mode=os.environ['CASE_MODE']
with (base/'calls.jsonl').open('a') as f: f.write(json.dumps(a)+'\n')
state=base/'active.json'; active=json.loads(state.read_text()) if state.exists() else []
if a==['version']: print('22 (KPM fixture)')
elif a==['uid','block_isolated']: print('0')
elif a==['rule','clear']:
 if mode=='clear_error':sys.exit(1)
 state.write_text('[]')
elif a[:2]==['uid','add'] and mode=='uid_error':sys.exit(1)
elif a[:2]==['module','load']:
 if mode in ('add_error','scan_error') and 'b_bad' in a[2]:sys.exit(1)
 active.append(a[2:]); state.write_text(json.dumps(active))
elif a==['rule','list']:
 if mode=='list_error':sys.exit(1)
 print(json.dumps(active))
'''


def shell_case(output, mode):
    base = output / mode
    module = base / 'data/adb/modules/nomount'
    module.mkdir(parents=True)
    for path in (ROOT / 'nomount/module').glob('*.sh'):
        body = path.read_text().replace('/data/adb', str(base / 'data/adb'))
        body = body.replace('/proc/sys/kernel/random/boot_id', str(base / 'boot_id'))
        body = body.replace('"/$partition"', '"' + str(base) + '/$partition"')
        body = body.replace('"/system/$partition"', '"' + str(base) + '/system/$partition"')
        (module / path.name).write_text(body)
    (module / 'bin').mkdir()
    cli = module / 'bin/nm'
    cli.write_text(CLI.replace('#!PYTHON', '#!' + sys.executable, 1))
    cli.chmod(0o755)
    (base / 'system').mkdir()
    (base / 'boot_id').write_text('current-boot\n')
    for name in ('a_good', 'b_bad', 'c_good'):
        file = base / 'data/adb/modules' / name / ('system/etc/' + name + '.conf')
        file.parent.mkdir(parents=True)
        file.write_text(name)
    data = base / 'data/adb/nomount'
    data.mkdir()
    (data / '.exclusion_list.json').write_text('[{"uid":"10001"}]')
    environment = dict(os.environ, CASE_BASE=str(base), CASE_MODE=mode)
    result = subprocess.run(['/bin/sh', str(module / 'metamount.sh')], env=environment, capture_output=True, text=True)
    (base / 'run.log').write_text(result.stdout + result.stderr)
    calls = [json.loads(line) for line in (base / 'calls.jsonl').read_text().splitlines()]
    active = json.loads((base / 'active.json').read_text()) if (base / 'active.json').exists() else []
    adds = [call for call in calls if call[:2] == ['module', 'load']]
    assert calls.count(['rule', 'clear']) == 1  # 启动清理；后续故障不再全清，也不重试清理。
    if mode in ('uid_error', 'clear_error'):
        assert result.returncode == 1 and not adds and not (data / '.booting').exists()
    else:
        assert result.returncode == (1 if mode in ('add_error', 'scan_error') else 0)
        assert any('a_good' in str(row) for row in active) and any('c_good' in str(row) for row in active)
        assert any('b_bad' in str(row) for row in active) == (mode not in ('add_error', 'scan_error'))
        assert calls.index(['uid', 'add', '10001']) < calls.index(adds[0])
        assert (data / '.booting').exists()  # 部分成功也保留开机保护，直到实际完成回执。
        execute(['/bin/sh', str(module / 'boot-completed.sh')], base / 'completed.log', env=environment)
        assert not (data / '.booting').exists()
    return {'mode': mode, 'returncode': result.returncode, 'active_batches': len(active)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--symbols', type=Path, required=True, help='规则 Oracle 使用的目标符号 JSON')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    execute([sys.executable, '-B', str(ROOT / 'nomount/tools/test_rules.py'), '--symbols', str(args.symbols.resolve()),
             '--output', str(output / 'rules-oracle')], output / 'rules-oracle.log')
    original = (output / 'rules-oracle/rules.c').read_text()
    assert original.count('int main(void)') == 1
    source = original.replace('int main(void)', 'static int rules_oracle_main(void)', 1)
    nodes = (ROOT / 'nomount/nm_directory_nodes.c').read_text()
    source += '\n' + nodes[:nodes.index('// 调用者在原生 RCU')]
    source += C_PRE + function('nomount/nm_inode.c', 'nm_check_inode_allocation')
    source += '\n' + (ROOT / 'nomount/nm_topology.c').read_text()
    source += C_CONTROL + '\n' + (ROOT / 'nomount/nm_control.c').read_text() + C_TEST
    (output / 'publication.c').write_text(source)
    execute(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter',
             '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', '-g', str(output / 'publication.c'),
             '-o', str(output / 'publication')], output / 'compile.log')
    result = execute([str(output / 'publication')], output / 'publication.log')
    cases = [shell_case(output, mode) for mode in ('ready', 'add_error', 'list_error', 'scan_error', 'uid_error', 'clear_error')]
    receipt = {'scope': 'Developer host API stubs and relocated shell; not native concurrency/device proof',
               'production': ['nm_rules.c', 'nm_topology.c', 'nm_control.c', 'module/metamount.sh'],
               'c_result': result, 'shell': cases}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
