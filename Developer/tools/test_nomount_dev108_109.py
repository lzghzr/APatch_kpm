#!/usr/bin/env python3
"""DEV-108/109: production CLI batches and automatic-parent promotion, host API fixtures."""
import argparse
import json
import os
from pathlib import Path
import struct
import sys

import test_nomount_failure_scope as scope
import test_nomount_module_cli as cli
from test_nomount_dev107 import C_TEST as PREVIOUS_TEST

ROOT = Path(__file__).resolve().parents[2]

C_TEST = r'''
static struct nomount_rule *selected(const char *p,unsigned uid) {
  nm_rcu_read_lock();struct nomount_rule *r=nm_select_rule(entry_at(p)->leaf,uid);
  if(r)nm_rule_get(r);nm_rcu_read_unlock();return r;
}
static void promotion_tests(void) {
  const char *p="/data/dir/parent",*c="/data/dir/parent/hidden";
  _Static_assert(sizeof(struct nomount_rule)==56,"private rule remains 56 bytes on this 64-bit fixture");
  _Static_assert(offsetof(struct nomount_rule,paths)==56,"backing string offset unchanged");
  for(unsigned scoped=0;scoped<3;scoped++) {
    assert(!request_rule(true,c,NM_FLAG_WHITEOUT,0,0,100,200));
    struct nomount_rule *old=selected(p,0);assert(old&&old->automatic_parent&&!old->deny_start);
    if(scoped) {
      unsigned end=scoped==1?700:800;
      assert(!request_rule(true,p,NM_FLAG_OPAQUE,700,end,0,0));
      assert(!entry_at(p)->automatic); // The implicit default survives explicit UID insertion.
      struct nomount_rule *still=selected(p,0);assert(still==old);nm_rule_put(still);
    }
    assert(!request_rule(true,p,NM_FLAG_OPAQUE,0,0,100,200));
    struct nomount_rule *r=selected(p,0);
    assert(r&&!r->automatic_parent&&(r->flags&NM_FLAG_OPAQUE)&&r->deny_start==100&&r->deny_end==200);
    assert(!selected(p,150));nm_rule_put(r);
    assert(old->automatic_parent&&!old->deny_start&&!old->r_path.dentry);nm_rule_put(old);
    if(scoped) {
      r=selected(p,700);assert(r&&r->target_uid==700&&!r->automatic_parent);nm_rule_put(r);
      assert(request_rule(true,p,NM_FLAG_OPAQUE,700,scoped==1?700:800,700,700)==-EEXIST);
      if(scoped==2)assert(request_rule(true,p,NM_FLAG_OPAQUE,750,900,0,0)==-EEXIST);
    }
    assert(request_rule(true,p,NM_FLAG_OPAQUE,0,0,300,400)==-EEXIST);
    assert(has_path(c));clear_tree();
  }
  // Explicit virtual or downgraded directories remain real policy, not automatic scaffolding.
  for(unsigned downgraded=0;downgraded<2;downgraded++) {
    add_at(p,downgraded?NM_FLAG_OPAQUE:NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR,0);
    add_at(c,NM_FLAG_WHITEOUT,0);
    if(downgraded)del_at(p,0);
    assert(request_rule(true,p,NM_FLAG_OPAQUE,0,0,100,200)==-EEXIST);
    assert(has_path(c));clear_tree();
  }
  // The old automatic rule and its references survive a failed prepared replacement.
  for(unsigned cache=0;cache<2;cache++) {
    add_at(c,NM_FLAG_WHITEOUT,0);
    struct nm_topology_leaf *entry=entry_at(p);
    struct nomount_rule *old=selected(p,0);
    struct nomount_rule *replacement=nm_alloc_scoped_rule("/data/dir",9,NM_FLAG_OPAQUE,0,0,100,200);
    assert(!IS_ERR(replacement));struct nm_topology_updates updates={0};
    if(cache)kf_nm_d_hash_and_lookup=cache_error;else fail_next=1;
    assert(nm_topology_replace(entry,replacement,&updates)==(cache?-EIO:-ENOMEM));
    nm_finish_topology_updates(&updates);nm_rule_put(replacement);
    struct nomount_rule *retained=selected(p,0);assert(retained==old&&old->automatic_parent);
    nm_rule_put(retained);nm_rule_put(old);kf_nm_d_hash_and_lookup=cached_child;clear_tree();
  }
  puts("PASS DEV-109: default/single UID/range, implicit origin survives other scope, explicit conflicts, immutable failure paths");
}
int main(void) {
  assert(!original_scope_main());fail_stage=0;
  promotion_tests();kf_nm_kern_path=system_path;
  /* BATCH_CASES */
  puts("PASS DEV-108/109: production CLI batches, parent-first markers, final selection and complete unload");
  return 0;
}
'''


def batches(path):
    """Keep the CLI's batch boundaries; map only native backing lookup to the host fixture."""
    data = path.read_bytes()
    off = 0
    result = []
    while off < len(data):
        cmd, size = struct.unpack_from('<II', data, off)
        off += 8
        end = off + size
        body = b''
        while off < end:
            if cmd == 2:
                flags, uid, uid_end, deny, deny_end, vlen, rlen = struct.unpack_from('<IIIIIHH', data, off)
                off += 24
                virtual = data[off:off+vlen]
                off += vlen+rlen
                real = b'' if flags & 6 else b'/data/dir' if flags & 9 else b'/data/file'
                body += struct.pack('<IIIIIHH', flags, uid, uid_end, deny, deny_end, vlen, len(real))+virtual+real
            else:
                assert cmd == 3
                vlen = struct.unpack_from('<H', data, off+16)[0]
                body += data[off:off+18+vlen]
                off += 18+vlen
        assert off == end and len(body) <= 4068
        result.append((cmd, body))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    scope.execute([sys.executable, '-B', str(ROOT/'Developer/tools/test_nomount_failure_scope.py'),
                   '--symbols', str(args.symbols.resolve()), '--output', str(out/'oracle')], out/'oracle.log')
    source = (out/'oracle/publication.c').read_text().replace('int main(void)', 'static int original_scope_main(void)', 1)
    source += PREVIOUS_TEST[:PREVIOUS_TEST.index('static void cli_roundtrip')]
    cli_dir = out/'cli'
    cli_dir.mkdir()
    # An explicit .replace must not depend on a redundant xattr lookup succeeding.
    marker = 'static ssize_t fixture_getxattr(const char*p,const char*n,void*v,size_t z){'
    assert marker in cli.PRE
    cli.PRE = cli.PRE.replace(marker, marker+'\n if(getenv("XATTR_ERROR")&&strrchr(p,\'/\')&&!strcmp(strrchr(p,\'/\'),"/both")){errno=EIO;return -1;}')
    cli.build(cli_dir)
    module = cli_dir/'module'
    names = ('both/.remove', 'both/.replace', 'both/value', 'both/hidden/.remove',
             'both/nested/.replace', 'both/nested/hidden/.remove', 'both/nested/value',
             'opaque/.replace', 'opaque/hidden/.remove', 'opaque/value',
             'removed/.remove', 'removed/ignored/file', 'empty/.replace', 'empty/.remove',
             'char-whiteout', 'ordinary')
    # Markers are created after child files, so readdir order cannot supply the dependency guarantee.
    for name in reversed(names):
        p = module/'system/etc'/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('fixture')
    for i in range(180):
        (module/f'system/etc/both/nested/{i:03}').write_text('fixture')
    (module/'system/etc/alias').symlink_to('both', target_is_directory=True)
    cases = []
    code = []
    for label, options, uid in (('default', [], 0), ('excluded', ['--uid-excluded', '100-200'], 0),
                                ('single', ['--uid', '700'], 700), ('range', ['--uid-range', '700-800'], 700)):
        code += ['{ add_at("/system/unrelated",NM_FLAG_WHITEOUT,0); unsigned before=topology_count();']
        for command in ('load', 'unload'):
            capture = cli_dir/(label+'-'+command+'.bin')
            scope.execute([str(cli_dir/'cli'), 'module', command, str(module), *options],
                          cli_dir/(label+'-'+command+'.log'), env=dict(os.environ, CAPTURE=str(capture), XATTR_ERROR='1'))
            rows = cli.records(capture)
            if command == 'load':
                by_path = {r['v']:r for r in rows}
                order = [r['v'] for r in rows]
                assert by_path['/system/etc/both']['flags'] == 8
                assert by_path['/system/etc/removed']['flags'] == 4
                assert not any('/removed/' in v for v in by_path)
                for child in ('/system/etc/both/hidden', '/system/etc/both/nested', '/system/etc/both/nested/hidden'):
                    assert order.index('/system/etc/both') < order.index(child)
                loaded = {r['v'] for r in rows}
            else:
                assert len(rows) == len(loaded) and {r['v'] for r in rows} == loaded
            wire = batches(capture)
            cases.append({'case':label+'-'+command, 'records':len(rows), 'batches':len(wire)})
            for cmd, body in wire:
                code += ['{ static const unsigned char bytes[]={'+','.join(map(str,body))+'};',
                         'struct nm_payload p={.magic=NOMOUNT_MAGIC_SIG,.cmd=%d,.data_size=sizeof(bytes)};'%cmd,
                         'memcpy(p.buffer,bytes,sizeof(bytes));int rc=nm_execute_payload(&p);',
                         'if(rc)fprintf(stderr,"batch status %d offset %u\\n",rc,p.arg1); assert(!rc); }']
            if command == 'load':
                code += ['struct nomount_rule *r=selected("/system/etc/both",%d);'%uid,
                         'assert(r&&(r->flags&NM_FLAG_OPAQUE)&&!r->automatic_parent);nm_rule_put(r);',
                         'r=selected("/system/etc/both/hidden",%d);assert(r&&(r->flags&NM_FLAG_WHITEOUT));nm_rule_put(r);'%uid]
                if label == 'excluded':
                    code += ['assert(!selected("/system/etc/both",150));']
        code += ['assert(topology_count()==before&&has_path("/system/unrelated"));clear_tree(); }']
    source += C_TEST.replace('/* BATCH_CASES */', '\n'.join(code))
    (out/'combined.c').write_text(source)
    scope.execute(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-Wno-unused-parameter', '-I', str(ROOT/'nomount'), '-fsanitize=address,undefined',
                   '-g', str(out/'combined.c'), '-o', str(out/'combined')], out/'compile.log')
    result = scope.execute([str(out/'combined')], out/'run.log')
    receipt = {'scope':'Developer host production CLI batches + KPM control/topology; native APIs stubbed',
               'cases':cases,'result':result,'oracle_assertions':'original rules and failure-scope tests unchanged'}
    (out/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
    print(result)


if __name__ == '__main__':
    main()
