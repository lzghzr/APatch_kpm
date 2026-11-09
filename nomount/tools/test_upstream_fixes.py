#!/usr/bin/env python3
"""回放冻结 Oracle，验证特殊权限位、opaque 与 WebUI 失败传播。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from build_zip import adapt_rule_paths, adapt_webui
from test_directory_abis import function
from test_v22_module import EXTRA
from test_webui_counts import NODE_TEST

ROOT = Path(__file__).resolve().parents[2]


def assertions(source):
    return re.findall(r'\bassert\s*\([^;]+\);', source)


def run(command, log):
    result = subprocess.run(command, capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    result.check_returncode()


C_TEST = r'''
static int privilege_attr_error;
static int privilege_getattr(const struct nm_path* path, struct kstat* stat) {
 if(privilege_attr_error)return privilege_attr_error;
 memset(stat,0,128);
 if(struct_offset.kstat_inode_first)((struct nm_kstat_inode_first*)stat)->mode=nm_inode_mode(nm_dentry_inode(path->dentry));
 else ((struct nm_kstat_prefix*)stat)->mode=nm_inode_mode(nm_dentry_inode(path->dentry));
 return 0;
}
static int privilege_notify(struct dentry* d,void* attr,struct inode** delegated){
 assert(d==backing_path.dentry&&attr==sa_attr&&!delegated&&sa_locks>sa_unlocks);
 if(sa_notify_error)return sa_notify_error;
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0107775;
 return 0;
}
static void check_privilege_modes(void){
 target();directory_target();
 _Alignas(128) unsigned char outer[4096]={0},source[4096]={0};
 const unsigned types[]={0100000,0040000,0120000};
 for(unsigned type=0;type<3;type++)for(unsigned bits=0;bits<=07777;bits++){
  struct nm_inode_owner_prefix* real=(void*)source;real->i_mode=types[type]|bits;real->i_uid=123;real->i_gid=456;
  nm_copy_backing_inode_attributes(outer,source,999);
  assert(nm_inode_mode(outer)==(types[type]|(bits&~06000U)));
  assert(real->i_mode==(types[type]|bits));
  assert(((struct nm_inode_owner_prefix*)outer)->i_uid==123&&((struct nm_inode_owner_prefix*)outer)->i_gid==456);
 }
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0107775;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,901));
 struct inode* inode=nm_dentry_inode(outer_root);
 assert(nm_inode_mode(inode)==0101775&&nm_inode_mode(backing)==0107775);
 assert(nm_inode_matches_binding(inode,&backing_path,NULL,0,71));
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0101775;
 assert(nm_inode_matches_binding(inode,&backing_path,NULL,0,71));
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0101774;
 assert(!nm_inode_matches_binding(inode,&backing_path,NULL,0,71));
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0107775;
 nm_vfs_getattr_pair=privilege_getattr;privilege_attr_error=0;
 _Alignas(8) unsigned char stat[128];
 for(unsigned layout=0;layout<2;layout++){
  struct_offset.kstat_inode_first=layout;
  assert(!nm_getattr_from_backing(inode,&backing_path,(void*)stat,0,0));
  assert((layout?((struct nm_kstat_inode_first*)stat)->mode:((struct nm_kstat_prefix*)stat)->mode)==0101775);
  privilege_attr_error=-EACCES;memset(stat,0xa5,sizeof(stat));
  assert(nm_getattr_from_backing(inode,&backing_path,(void*)stat,0,0)==-EACCES&&stat[0]==0xa5&&stat[127]==0xa5);
  privilege_attr_error=0;
 }
 nm_vfs_getattr_pair=NULL;sa_ready(0);nm_notify_plain=privilege_notify;
 struct nm_iattr_head attr={1};sa_attr=&attr;
 assert(!nm_setattr((void*)outer_root,&attr)&&nm_inode_mode(inode)==0101775&&nm_inode_mode(backing)==0107775);
 assert(sa_locks==sa_unlocks&&sa_locks==1);
 ((struct nm_inode_owner_prefix*)inode)->i_mode=0100755;sa_notify_error=-EPERM;
 assert(nm_setattr((void*)outer_root,&attr)==-EPERM&&nm_inode_mode(inode)==0100755&&nm_inode_mode(backing)==0107775);
 port_iput(inode);drain();nm_discard_directory_view();
 puts("virtual mode: all permission combinations, unchanged source, materialization, cache, both kstat layouts and setattr PASS");
}
'''

SHELL_EXTRA = r'''
    for empty in (False, True):
        work, mod, data, log, env = fixture('xattr-opaque-' + str(empty))
        files(work, data)
        base = work / 'data/adb/modules/example/system/etc/opaque dir'
        base.mkdir()
        if not empty:
            (base / 'new file.txt').write_text('content')
        getfattr = work / 'commands/getfattr'
        getfattr.write_text('#!/bin/sh\ncase "$*" in *"opaque dir"*) printf \'trusted.overlay.opaque="y"\\n\';; esac\n')
        getfattr.chmod(0o755)
        run(mod, 'metamount.sh', env)
        commands = calls(log)
        whites = [x for c in commands if c[:3] == ['rule','add','--whiteout'] for x in c[3:]]
        opaques = [x for c in commands if c[:3] == ['rule','add','--opaque'] for x in c[3:]]
        assert ('/system/etc/opaque dir' in whites) == empty
        assert ('/system/etc/opaque dir' in opaques) != empty
        assert ('/system/etc' not in opaques)
        cases.append('xattr opaque directory preserves content or whiteouts empty directory: ' + str(empty))
    work, mod, data, log, env = fixture('opaque-content-find-error')
    files(work, data)
    find = work / 'commands/find'
    find.write_text('#!/bin/sh\ncase "$*" in *-mindepth*) exit 37;; esac\nexec /usr/bin/find "$@"\n')
    find.chmod(0o755)
    run(mod, 'metamount.sh', env, 1)
    assert calls(log)[-1] == ['rule','clear']
    assert not (data / '.booting').exists()
    cases.append('opaque content enumeration failure propagates and clears boot batch')
'''

NODE_ACTIONS = r'''
const child = require('node:child_process');
const path = require('node:path');
(async () => {
 const root = process.argv[4], modules = path.join(root,'modules');
 const source = revised.replace('const MOD_DIR = "/data/adb/modules";',`const MOD_DIR = ${JSON.stringify(modules)};`)
  .replace('const NM_BIN = "/data/adb/modules/nomount/bin/nm";',`const NM_BIN = ${JSON.stringify(path.join(root,'bin/nm'))};`)
  .replace(/const TARGET_PARTITIONS = "[^"]+";/,'const TARGET_PARTITIONS = "tmp";');
 const ctx = sandbox(source,[],[]).ctx;
 let mode='ok', scripts=[];
 ctx.fixtureExec = async script => {
  scripts.push(script);
  const r=child.spawnSync('/bin/sh',['-c',script],{encoding:'utf8',env:{...process.env,PATH:path.join(root,'bin')+':'+process.env.PATH,NM_ACTION_MODE:mode,NM_ACTION_LOG:path.join(root,'calls')}});
  return {errno:r.status,stdout:r.stdout,stderr:r.stderr};
 };
 vm.runInContext('exec=fixtureExec;',ctx);
 await ctx.loadModule('example');await ctx.unloadModule('example');
 assert(scripts[0].includes("-type d -o -name"));
 const calls=fs.readFileSync(path.join(root,'calls'),'utf8').trim().split('\n').map(x=>JSON.parse(x));
 assert(calls.some(x=>x[0]==='rule'&&x[1]==='add'&&x[2]==='--opaque'));
 assert(calls.some(x=>x[0]==='rule'&&x[1]==='del'));
 cases.push('actual generated add/del shell succeeds with NUL-safe paths');
 for(const failure of ['add','opaque','del','find']) {
  mode=failure;
  await assert.rejects(failure==='del'?ctx.unloadModule('example'):ctx.loadModule('example'));
  cases.push('actual shell failure reported: '+failure);
 }
 mode='ok';await assert.rejects(ctx.loadModule('missing'));
 await ctx.loadModule('empty');cases.push('missing module rejected; no injectable partitions succeeds');
 ctx.fixtureExec=async()=>({errno:0,stdout:'',stderr:''});vm.runInContext('exec=fixtureExec;',ctx);
 await assert.rejects(ctx.loadModule('example'));cases.push('missing completion marker rejected');
 ctx.fixtureExec=async()=>({errno:1,stdout:'',stderr:'nm_rule_status=0\n'});vm.runInContext('exec=fixtureExec;',ctx);
 await assert.rejects(ctx.unloadModule('example'));cases.push('bridge failure rejected even with success marker');
 process.stdout.write(JSON.stringify({cases,result:'PASS'})+'\n');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'reference-image', 'image', 'legacy-image', 'cli-source', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for abi in ('int', 'bool'):
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        old = assertions(original)
        assert len(old) == 1891
        source = original
        for file, names in {'nm_offsets.c': ['nm_set_stat_identity', 'nm_copy_backing_inode_attributes'],
                            'nm_inode.c': ['nm_inode_matches_binding'], 'nm_setattr.c': ['nm_setattr_context']}.items():
            current = (ROOT / 'nomount' / file).read_text()
            for name in names:
                before = function(source, name)
                assert source.count(before) == 1
                source = source.replace(before, function(current, name), 1)
        helper = function((ROOT / 'nomount/nm_offsets.c').read_text(), 'nm_virtual_mode')
        at = source.index(function(source, 'nm_set_stat_identity'))
        source = source[:at] + helper + '\n' + source[at:]
        assert assertions(source) == old
        source = source.replace('int main(int argc,char**argv)', 'static int previous_upstream_main(int argc,char**argv)', 1)
        source += C_TEST + '\nint main(int argc,char**argv){assert(!previous_upstream_main(argc,argv));check_privilege_modes();return 0;}\n'
        assert assertions(source)[:len(old)] == old
        out = args.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn',
             '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', '-g',
             str(out / 'contracts.c'), str(args.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str(args.reference_image.resolve()), str(args.image.resolve()),
             str(args.legacy_image.resolve())], out / 'run.log')
        rows.append({'abi': abi, 'preserved_assert_sites': len(old), 'added_assert_sites': len(assertions(source)) - len(old)})

    original_path = ROOT / 'nomount/tools/test_zip_module.py'
    original = original_path.read_text()
    source = original.replace("print('0.1.0');sys.exit(0)", "print('22');sys.exit(0)", 1)
    before = "        shutil.copyfile(root / 'nomount/upstream/nomount/module/rule-paths.sh', mod / 'rule-paths.sh')"
    assert source.count(before) == 1
    source = source.replace(before, "        (mod / 'rule-paths.sh').write_text(adapt_rule_paths((root / 'nomount/upstream/nomount/module/rule-paths.sh').read_text()))", 1)
    assert assertions(source) == assertions(original)
    marker = "    for p in (root / 'nomount/module').glob('*.sh'):"
    assert source.count(marker) == 1
    source = source.replace(marker, EXTRA + SHELL_EXTRA + marker, 1)
    generated = args.output / 'module-tests.py'
    generated.write_text(source)
    # 保存外层参数，随后由冻结测试自己的 argparse 消费输出目录。
    code = "import sys;a=sys.argv[1:];sys.path.insert(0,a[2]);from build_zip import adapt_rule_paths;sys.argv=['test_zip_module.py','--output',a[0]];exec(compile(open(a[1]).read(),a[3],'exec'),{'__name__':'__main__','__file__':a[3],'adapt_rule_paths':adapt_rule_paths})"
    run([sys.executable, '-B', '-c', code, str(args.output / 'module-cases'), str(generated),
         str(ROOT / 'nomount/tools'), str(original_path)], args.output / 'module.log')

    upstream = (ROOT / 'nomount/upstream/nomount/module/webroot/index.js').read_text()
    original_js, revised_js = args.output / 'original.js', args.output / 'revised.js'
    original_js.write_text(upstream)
    revised_js.write_text(adapt_webui(upstream))
    run(['node', '--check', str(revised_js)], args.output / 'syntax.log')
    counts = args.output / 'counts.cjs'
    counts.write_text(NODE_TEST)
    run(['node', str(counts), str(original_js), str(revised_js)], args.output / 'counts.log')
    action_root = args.output / 'webui'
    (action_root / 'modules/example/tmp/opaque dir').mkdir(parents=True)
    (action_root / 'modules/example/tmp/opaque dir/new file').write_text('content')
    (action_root / 'modules/empty').mkdir()
    (action_root / 'modules/nomount').mkdir()
    (action_root / 'modules/nomount/rule-paths.sh').write_text(adapt_rule_paths((ROOT / 'nomount/upstream/nomount/module/rule-paths.sh').read_text()))
    bindir = action_root / 'bin'
    bindir.mkdir()
    (bindir / 'nm').write_text('#!' + sys.executable + '\nimport os,sys,json\na=sys.argv[1:]\nwith open(os.environ["NM_ACTION_LOG"],"a") as f:f.write(json.dumps(a)+"\\n")\nm=os.environ["NM_ACTION_MODE"]\nsys.exit(7 if ((m=="add" and a[:2]==["rule","add"]) or (m=="opaque" and a[:3]==["rule","add","--opaque"]) or (m=="del" and a[:2]==["rule","del"])) else 0)\n')
    (bindir / 'getfattr').write_text('#!/bin/sh\ncase "$*" in *"opaque dir"*) printf \'trusted.overlay.opaque="y"\\n\';; esac\n')
    (bindir / 'find').write_text('#!/bin/sh\n[ "$NM_ACTION_MODE" != find ] || exit 31\nexec /usr/bin/find "$@"\n')
    for file in bindir.iterdir():
        file.chmod(0o755)
    runner = args.output / 'actions.cjs'
    runner.write_text(NODE_TEST.split('(async () => {', 1)[0] + NODE_ACTIONS)
    run(['node', str(runner), str(original_js), str(revised_js), str(action_root.resolve())], args.output / 'actions.log')
    receipt = {'scope': 'Developer host callbacks and relocated generated shell/JS; Android syscall/LSM/CFI/device coverage pending',
               'oracle_migrations': [], 'host': rows,
               'module': json.loads((args.output / 'module-cases/receipt.json').read_text()),
               'webui_counts': json.loads((args.output / 'counts.log').read_text()),
               'webui_actions': json.loads((args.output / 'actions.log').read_text())}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'host': rows, 'module_cases': len(receipt['module']['cases']), 'webui': receipt['webui_actions']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
