#!/usr/bin/env python3
"""保留冻结宿主Oracle，分别执行准确int/bool目录回调及加载入口。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = 'f70894744b10d7aab212d18a9262e905eacef7d9'
ORACLE_SHA256 = '5435e63f77b3b8f5be34f34992d48887b44b58f76a77e306ddfc36e78d6981b8'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def function(source, name):
    match = re.search(r'(?m)^static [^\n]*\b' + name + r'\([^;]*?\)\s*\{', source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    original = (args.oracle_output / 'events.c').read_text()
    receipt = json.loads((args.oracle_output / 'receipt.json').read_text())
    assert sha(original.encode()) == receipt['generated_source_sha256'] == ORACLE_SHA256
    args.output.mkdir(parents=True, exist_ok=False)

    def old(name):
        return subprocess.check_output(['git', 'show', BASE + ':nomount/' + name], cwd=root).decode()

    def new(name):
        return (root / 'nomount' / name).read_text()

    source = original.replace(old('nm_structs.h'), new('nm_structs.h'))
    start = source.index('struct struct_offset {')
    end = source.index('static int nm_prepare_inode_layout(void)')
    source = source[:start] + new('nm_offsets.c').split('#ifndef CONFIG_KPM_BASELINES', 1)[0].replace('section(".data.re_offsets"), ', '') + source[end:]
    replacements = {'nm_directory_nodes.c': ['nm_emit_children'],
                    'nm_directory.c': ['nm_directory_filter', 'nm_directory_iterate'],
                    'nm_backing_directory.c': ['nm_backing_directory_filter', 'nm_backing_directory_iterate'],
                    'nm_virtual_directory.c': ['nm_virtual_directory_iterate']}
    for file, names in replacements.items():
        for name in names:
            before, after = function(old(file), name), function(new(file), name)
            if name.endswith('_filter'):
                after += '\n' + function(new(file), name + '_bool')
            assert source.count(before) == 1, name
            source = source.replace(before, after)
    source = source.replace('#define NM_KPM_VERSION "0.3.0"', '#define NM_KPM_VERSION "0.4.0"')
    assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
    results = []
    for abi in (0, 1):
        variant = source.replace('static void directory_target(void) {',
                                 'static void directory_target(void) {\nstruct_offset.dir_actor_abi=' + str(abi) + ';')
        if abi:
            actor = function(variant, 'fixture_actor')
            variant = variant.replace(actor, actor.replace('fixture_actor(', 'fixture_actor_int(') + '''
static bool fixture_actor(struct nm_dir_context* ctx,const char* name,int length,int64_t pos,u64 number,unsigned int type) {
 return fixture_actor_int(ctx,name,length,pos,number,type)==0;
}
''')
            variant = variant.replace('.actor=fixture_actor', '.actor_bool=fixture_actor')
            # 三个原生枚举夹具独立遵守bool契约，不经生产归一化助手。
            for name, context in [('fixture_iterate', 'ctx'), ('bridge_iterate', 'context'), ('port_iterate', 'context')]:
                before = function(variant, name)
                after = before.replace(context + '->actor(', '!' + context + '->actor_bool(')
                assert after != before, name
                variant = variant.replace(before, after)
        assert re.findall(r'\bassert\s*\([^;]+\);', variant) == assertions
        variant = variant.replace('int main(void){', 'static int previous_events_main(void){')
        variant += '''
int main(void){
 assert(sizeof(struct nm_dir_context)==16 && offsetof(struct nm_dir_context,pos)==8);
 assert(!previous_events_main());target();directory_target();
 struct_offset.dir_actor_abi=-1;assert(nm_validate_directory_offsets((const void*)&struct_offset)==-ENOENT);
 struct_offset.dir_actor_abi=2;assert(nm_validate_directory_offsets((const void*)&struct_offset)==-EOPNOTSUPP);
 struct nm_dir_context invalid={0};assert(nm_dir_emit(&invalid,"x",1,0,0,8)==-EOPNOTSUPP);
 return 0;
}
'''
        path = args.output / ('bool' if abi else 'int')
        path.mkdir()
        c = path / 'contracts.c'
        c.write_text(variant)
        command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(path / 'contracts')]
        built = subprocess.run(command, capture_output=True, text=True)
        (path / 'compile.log').write_text(built.stdout + built.stderr)
        built.check_returncode()
        run = subprocess.run([str(path / 'contracts')], capture_output=True, text=True)
        (path / 'run.log').write_text(run.stdout + run.stderr)
        run.check_returncode()
        results.append({'abi': abi, 'generated_source_sha256': sha(variant.encode()), 'result': run.stdout})
    result = {'scope': 'Developer host native API stubs; not native concurrency, CFI or device proof',
              'oracle_commit': BASE, 'oracle_generated_sha256': ORACLE_SHA256,
              'assertions_preserved_per_abi': len(assertions), 'variants': results,
              'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in (root / 'nomount').glob('nm*.[ch]')},
              'tool_sha256': sha(Path(__file__).read_bytes())}
    (args.output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print('int/bool native, virtual and backing directories; full Oracle and entry events: PASS;', len(assertions), 'preserved assertions each')


if __name__ == '__main__':
    main()
