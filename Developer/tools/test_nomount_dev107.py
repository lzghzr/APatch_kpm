#!/usr/bin/env python3
"""DEV-107: replay the production module CLI against production KPM topology/control."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import test_nomount_failure_scope as scope
import test_nomount_module_cli as cli

ROOT = Path(__file__).resolve().parents[2]

C_TEST = r'''
static int request_rule(bool add, const char *path, unsigned flags, unsigned uid,
                        unsigned end, unsigned deny, unsigned deny_end) {
  struct nm_payload p={.magic=NOMOUNT_MAGIC_SIG,.cmd=add?NM_CMD_ADD_RULE:NM_CMD_DEL_RULE};
  const char *backing=(flags&(NM_FLAG_WHITEOUT|NM_FLAG_VIRTUAL_DIR))?"":
                      (flags&(NM_FLAG_IS_DIR|NM_FLAG_OPAQUE))?"/data/dir":"/data/file";
  unsigned header;
  if(add) {
    struct nm_rule_hdr h={.flags=flags,.uid=uid,.uid_end=end,.deny_start=deny,.deny_end=deny_end,
                         .v_len=strlen(path),.r_len=strlen(backing)};
    header=sizeof(h);memcpy(p.buffer,&h,header);
    memcpy(p.buffer+header+strlen(path),backing,strlen(backing));
    p.data_size=header+strlen(path)+strlen(backing);
  } else {
    struct nm_del_hdr h={.uid=uid,.uid_end=end,.deny_start=deny,.deny_end=deny_end,.v_len=strlen(path)};
    header=sizeof(h);memcpy(p.buffer,&h,header);p.data_size=header+strlen(path);
  }
  memcpy(p.buffer+header,path,strlen(path));
  int rc=nm_execute_payload(&p);
  if(rc)fprintf(stderr,"%s %s: %d\n",add?"ADD":"DEL",path,rc);
  return rc;
}
static void add_at(const char *p,unsigned flags,unsigned uid) {
  assert(!request_rule(true,p,flags,uid,uid,0,0));
}
static void del_at(const char *p,unsigned uid) {
  assert(!request_rule(false,p,0,uid,uid,0,0));
}
static struct nm_topology_leaf *entry_at(const char *p) {
  struct nm_topology_leaf *e=nm_topology_find(p,strlen(p));assert(e);return e;
}
static unsigned topology_count(void) {
  unsigned n=0;for(struct nm_topology_leaf *e=nm_topology_leaves;e;e=e->next)n++;return n;
}
static int system_path(const char *p,unsigned f,struct nm_path *out) {
  return alias_path(!strcmp(p,"/system")?"/data/dir":p,f,out);
}
static struct dentry *cache_error(struct dentry *p,struct nm_qstr *n) {
  (void)p;(void)n;return ERR_PTR(-EIO);
}
static void cli_roundtrip(void) {
  kf_nm_kern_path=system_path;
  add_at("/system/unrelated",NM_FLAG_WHITEOUT,0);
  unsigned before=topology_count();
  /* CLI_REPLAY */
  assert(has_path("/system/unrelated"));
#ifdef EXPECT_BASELINE
  assert(topology_count()>before && has_path("/system/etc/both"));
  assert(!has_path("/system/etc/both/value"));
  puts("PASS baseline: real CLI unload succeeds but downgraded parent remains");
#else
  assert(topology_count()==before && !has_path("/system/etc/both"));
  puts("PASS real CLI: .replace/.remove, whiteout, UID exclusion; baseline restored");
#endif
  clear_tree();kf_nm_kern_path=alias_path;
}
int main(void) {
  assert(!original_scope_main());fail_stage=0;
  cli_roundtrip();
#ifdef EXPECT_BASELINE
  return 0;
#endif
  const char *parent="/data/dir/parent",*child="/data/dir/parent/child";
  // Explicit backed and opaque parents survive their own DEL until the last child disappears.
  for(unsigned flags=NM_FLAG_IS_DIR;flags<=NM_FLAG_OPAQUE;flags+=NM_FLAG_OPAQUE-NM_FLAG_IS_DIR) {
    add_at(parent,flags,0);add_at(child,0,0);
    struct nm_directory_node *held=entry_at(parent)->leaf->this_dir;nm_directory_node_get(held);
    del_at(parent,0);assert(has_path(child));
    assert(entry_at(parent)->leaf->rules->rules[0]->flags&NM_FLAG_VIRTUAL_DIR);
    del_at(child,0);assert(!has_path(parent)&&!held->owner&&!held->children);
    flush_callbacks();assert(held->refs==1);nm_directory_node_put(held);clear_tree();
  }
  // Sibling rules, including another UID, prevent pruning until they are actually removed.
  add_at(parent,NM_FLAG_OPAQUE,0);add_at(child,0,0);
  add_at("/data/dir/parent/sibling",NM_FLAG_WHITEOUT,500);
  del_at(parent,0);del_at(child,0);assert(has_path(parent));
  del_at("/data/dir/parent/sibling",500);assert(!has_path(parent));clear_tree();
  // The parent can have several virtual scopes; a non-virtual scope must stop pruning.
  for(unsigned all_virtual=0;all_virtual<2;all_virtual++) {
    add_at(parent,NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);
    add_at(parent,all_virtual?NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR:NM_FLAG_IS_DIR,500);
    add_at(child,0,0);add_at(child,0,600);
    del_at(child,0);assert(has_path(parent)&&has_path(child));
    del_at(child,600);assert(has_path(parent)==!all_virtual);
    if(!all_virtual)assert(entry_at(parent)->leaf->rules->count==2);
    clear_tree();
  }
  // A real backing ancestor remains while a downgraded nested directory is pruned.
  add_at(parent,NM_FLAG_IS_DIR,0);add_at(child,NM_FLAG_OPAQUE,0);
  add_at("/data/dir/parent/child/x",0,0);del_at(child,0);
  del_at("/data/dir/parent/child/x",0);
  assert(has_path(parent)&&!has_path(child));clear_tree();
  // Several downgraded ancestors disappear together once the final leaf is removed.
  add_at(parent,NM_FLAG_OPAQUE,0);add_at(child,NM_FLAG_OPAQUE,0);
  add_at("/data/dir/parent/child/x",0,0);del_at(parent,0);del_at(child,0);
  del_at("/data/dir/parent/child/x",0);
  assert(!has_path(parent)&&!has_path(child));clear_tree();
  // Pre-publication allocation and cache lookup errors retain the complete old tree.
  for(unsigned cache=0;cache<2;cache++) {
    add_at("/data/dir/unrelated",NM_FLAG_WHITEOUT,0);
    add_at(parent,NM_FLAG_OPAQUE,0);add_at(child,0,0);del_at(parent,0);
    if(cache)kf_nm_d_hash_and_lookup=cache_error;else fail_next=1;
    assert(request_rule(false,child,0,0,0,0,0)==(cache?-EIO:-ENOMEM));
    assert(has_path(parent)&&has_path(child)&&has_path("/data/dir/unrelated"));
    kf_nm_d_hash_and_lookup=cached_child;del_at(child,0);
    assert(!has_path(parent)&&has_path("/data/dir/unrelated"));clear_tree();
  }
  assert(request_rule(false,"/data/dir/missing",0,0,0,0,0)==-ENOENT);
  clear_tree();
  puts("PASS DEV-107: parent-first DEL, held nodes, sibling/scoped rules, backing ancestor, failure atomicity, refs");
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline-topology', type=Path)
    parser.add_argument('--probe-load-gap', choices=('marker-order', 'excluded-parent'),
                        help='Reproduce a separately recorded load gap; expected failure is not a fix result')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    scope.execute([sys.executable, '-B', str(ROOT/'Developer/tools/test_nomount_failure_scope.py'),
                   '--symbols', str(args.symbols.resolve()), '--output', str(out/'oracle')], out/'oracle.log')
    source = (out/'oracle/publication.c').read_text()
    if args.baseline_topology:
        current = (ROOT/'nomount/nm_topology.c').read_text()
        assert source.count(current) == 1
        source = source.replace(current, args.baseline_topology.read_text(), 1)
    assert source.count('int main(void)') == 1
    source = source.replace('int main(void)', 'static int original_scope_main(void)', 1)
    cli_dir = out/'cli'
    cli_dir.mkdir()
    cli.build(cli_dir)
    module = cli_dir/'module'
    fixtures = {
        None: ('both/.remove', 'both/.replace', 'both/value', 'opaque/.replace', 'opaque/value',
               'hidden/.remove', 'empty/.replace', 'ordinary'),
        'marker-order': ('both/.remove', 'both/.replace', 'both/value', 'both/hidden/.remove'),
        'excluded-parent': ('opaque/.replace', 'opaque/hidden/.remove', 'opaque/value'),
    }
    for name in fixtures[args.probe_load_gap]:
        path = module/'system/etc'/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture')
    replay = []
    rows_by_command = {}
    failures = 0
    for command in (('load',) if args.probe_load_gap else ('load', 'unload')):
        capture = cli_dir/(command+'.bin')
        scope.execute([str(cli_dir/'cli'), 'module', command, str(module), '--uid-excluded', '100-200'],
                      cli_dir/(command+'.log'), env=dict(os.environ, CAPTURE=str(capture)))
        rows = cli.records(capture)
        rows_by_command[command] = rows
        for row in rows:
            expected = 0
            if args.probe_load_gap == 'marker-order' and row['v'] == '/system/etc/both/hidden':
                expected = -20  # ENOTDIR: the ancestor is still a WHITEOUT.
            if args.probe_load_gap == 'excluded-parent' and row['v'] == '/system/etc/opaque':
                expected = -17  # EEXIST: the automatic ancestor has a different deny range.
            failures += bool(expected)
            replay.append('assert(request_rule(%s,%s,%d,%d,%d,%d,%d)==%d);' % (
                'true' if command == 'load' else 'false', json.dumps(row['v']), row['flags'],
                row['uid'], row['uid_end'], row['deny'], row['deny_end'], expected))
    # Only native backing lookup is a fixture; target paths, flags, scopes and DEL order are unchanged.
    if args.probe_load_gap:
        assert failures == 1
        source += C_TEST[:C_TEST.index('static void cli_roundtrip')]
        source += 'int main(void) { assert(!original_scope_main()); fail_stage=0; kf_nm_kern_path=system_path;\n'
        source += '\n'.join(replay) + '\nclear_tree(); puts("CONFIRMED separate load gap"); return 0; }\n'
    else:
        deleted = [r['v'] for r in rows_by_command['unload']]
        assert deleted.index('/system/etc/both') < deleted.index('/system/etc/both/value')
        source += C_TEST.replace('/* CLI_REPLAY */', '\n'.join(replay))
    (out/'dev107.c').write_text(source)
    options = ['-DEXPECT_BASELINE'] if args.baseline_topology else []
    scope.execute(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-Wno-unused-parameter', '-I', str(ROOT/'nomount'), '-fsanitize=address,undefined',
                   '-g', *options, str(out/'dev107.c'), '-o', str(out/'dev107')], out/'compile.log')
    result = scope.execute([str(out/'dev107')], out/'run.log')
    receipt = {'scope': 'Developer production CLI + KPM topology/control with native API stubs; not device/concurrency proof',
               'baseline': bool(args.baseline_topology), 'load_gap_probe': args.probe_load_gap,
               'cli_records': rows_by_command, 'result': result}
    (out/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
    print(result)


if __name__ == '__main__':
    main()
