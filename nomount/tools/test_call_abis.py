#!/usr/bin/env python3
"""保留控制 Oracle 断言，适配新增配置输入，再验证两套实际调用 ABI。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = 'c35ecd34ecb6a06c1d54ebda6e6a0e900065f16a'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def function(source, name):
    match = re.search(r'(?m)^static [^\n]*\b' + name + r'\([^;]*?\)\s*\{', source)
    assert match, name
    depth, end = 1, match.end()
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--target-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads((args.oracle_output / 'receipt.json').read_text())
    original = (args.oracle_output / 'control.c').read_text()
    assert sha(original.encode()) == receipt['generated_source_sha256']
    for path, digest in receipt['sources'].items():
        assert sha(subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=root)) == digest
    args.output.mkdir(parents=True, exist_ok=False)

    def old(name):
        return subprocess.check_output(['git', 'show', BASE + ':nomount/' + name], cwd=root).decode()

    def new(name):
        return (root / 'nomount' / name).read_text()

    source = original
    assert source.count(old('nm_structs.h')) == 1
    source = source.replace(old('nm_structs.h'), new('nm_structs.h'))
    start = source.index('struct struct_offset {')
    end = source.index('static int nm_prepare_inode_layout(void)')
    source = source[:start] + new('nm_offsets.c').split('#ifndef CONFIG_KPM_BASELINES', 1)[0] + source[end:]
    source = source.replace('section(".data.re_offsets"), ', '')
    names = {
        'nm_inode.c': ('nm_prepare_inode_functions', 'nm_getattr_from_backing', 'nm_prepare_inode_engine'),
        'nm_virtual_directory.c': ('nm_prepare_virtual_directory_engine',),
    }
    for path, functions in names.items():
        for name in functions:
            before, after = function(old(path), name), function(new(path), name)
            if name == 'nm_prepare_inode_functions':
                before = before.replace('kallsyms_lookup_name_by_suffix', 'inode_fixture_lookup')
                after = after.replace('kallsyms_lookup_name_by_suffix', 'inode_fixture_lookup')
            assert source.count(before) == 1, name
            source = source.replace(before, after)
    declaration = 'static int kfunc_def(nm_vfs_getattr_nosec)(const struct nm_path*, struct kstat*, u32, unsigned int);'
    assert source.count(declaration) == 1
    source = source.replace(declaration, declaration + '''
static int (*nm_vfs_getattr_pair)(const struct nm_path*, struct kstat*);
static int pair_attr(const struct nm_path*,struct kstat*);
static u32 pair_hash(const char*,unsigned int);''')
    for path, before, after in [
        ('nm_inode.c', 'nm_file_getattr', 'nm_file_getattr_mount'),
        ('nm_virtual_directory.c', 'nm_virtual_directory_getattr', 'nm_virtual_directory_getattr_mount'),
    ]:
        anchor = function(old(path), before)
        assert source.count(anchor) == 1
        source = source.replace(anchor, anchor + '\n' + function(new(path), after))
    before = old('nm_rules.c')
    start = before.index('static int kfunc_def(nm_kern_path)')
    end = before.index('// 仅适用于 head-first')
    after = new('nm_rules.c')
    prefix = after[after.index('static int kfunc_def(nm_kern_path)'):after.index('// 仅适用于 head-first')]
    assert source.count(before[start:end]) == 1
    source = source.replace(before[start:end], prefix)
    assert source.count('return (uintptr_t)fixture_hash;') == 1
    source = source.replace('return (uintptr_t)fixture_hash;',
                            'return (uintptr_t)(struct_offset.name_hash_args==2 ? (void*)pair_hash : (void*)fixture_hash);')
    source = source.replace('return (uintptr_t)host_attr;',
                            'return (uintptr_t)(struct_offset.getattr_function_args==2 ? (void*)pair_attr : (void*)host_attr);')
    # 这些替换仅更新生产调用；原有 Oracle 的 assert 表达式逐项保持。
    source = source.replace('kfunc(nm_full_name_hash)((const void*)(uintptr_t)NOMOUNT_MAGIC_SIG,',
                            'nm_name_hash((const void*)(uintptr_t)NOMOUNT_MAGIC_SIG,')
    source = source.replace('kfunc(nm_full_name_hash)((const void*)(uintptr_t)nm_inode_number(parent),',
                            'nm_name_hash((const void*)(uintptr_t)nm_inode_number(parent),')
    source = source.replace('#define NM_KPM_VERSION "0.1.0"', '#define NM_KPM_VERSION "0.2.0"')
    assert source.count('static void target(void) {') == 1
    source = source.replace('static void target(void) {', '''static void target(void) {
struct_offset.getattr_callback_args=4;struct_offset.getattr_function_args=4;
struct_offset.kstat_inode_first=0;struct_offset.name_hash_args=3;''')
    old_assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
    assert re.findall(r'\bassert\s*\([^;]+\);', source) == old_assertions
    source = source.replace('int main(void)', 'static int oracle_main(void)', 1)
    config = json.loads(args.target_config.read_text())['offsets']
    assert len(config) == 42
    target = '\n'.join(f'struct_offset.{key}={value};' for key, value in config.items())
    source += '''
static int pair_attrs;
static int pair_attr(const struct nm_path* path,struct kstat* stat) {
 assert(path->mnt==(void*)11 && path->dentry==(void*)12);
 memset(stat,0xa5,128);pair_attrs++;return attr_error;
}
static u32 pair_hash(const char* name,unsigned int length) {
 assert(!memcmp(name,"pair",4) && length==4);return 0x12345;
}
static void abi_target(void) {
''' + target + '''
}
static void check_abis(void) {
 abi_target();struct struct_offset o=struct_offset;
 assert(!nm_validate_inode_offsets(&o));assert(!nm_validate_file_offsets(&o));
 assert(!nm_validate_directory_offsets(&o));assert(!nm_validate_control_layout());
 int16_t* abi[]={&o.getattr_callback_args,&o.getattr_function_args,&o.kstat_inode_first};
 for(unsigned i=0;i<3;i++){int16_t save=*abi[i];*abi[i]=-1;assert(nm_validate_inode_offsets(&o)==-ENOENT);*abi[i]=save;}
 o.getattr_callback_args=5;assert(nm_validate_inode_offsets(&o)==-EOPNOTSUPP);o=struct_offset;
 o.getattr_function_args=3;assert(nm_validate_inode_offsets(&o)==-EOPNOTSUPP);o=struct_offset;
 o.kstat_inode_first=2;assert(nm_validate_inode_offsets(&o)==-EOPNOTSUPP);
 struct_offset.name_hash_args=-1;assert(nm_prepare_rule_functions()==-ENOENT);
 struct_offset.name_hash_args=4;assert(nm_prepare_rule_functions()==-EOPNOTSUPP);abi_target();
 assert(!nm_prepare_rule_functions());assert(nm_full_name_hash_pair==pair_hash);
 assert(nm_name_hash((void*)99,"pair",4)==0x12345);nm_full_name_hash_pair=NULL;
 assert(!nm_prepare_inode_engine());
 assert(nm_operation_callback(nm_inode_engine.inode_ops,struct_offset.iop_getattr)==nm_file_getattr_mount);
 assert(nm_vfs_getattr_pair==pair_attr);
 nm_discard_operations(nm_inode_engine.inode_ops);nm_discard_operations(nm_inode_engine.file_ops);
 nm_inode_engine.inode_ops=NULL;nm_inode_engine.file_ops=NULL;
 memset(parent_storage,0,sizeof(parent_storage));
 nm_inode_objects(parent)->i_sb=(void*)&sb;sb.s_dev=789;
 *(u64*)(parent_storage+struct_offset.inode_number)=987;
 struct nm_path path={(void*)11,(void*)12};_Alignas(8) unsigned char stat[128];
 nm_vfs_getattr_pair=pair_attr;attr_error=0;
 assert(!nm_getattr_from_backing(parent,&path,(void*)stat,0xffffffff,0xffffffff));
 assert(((struct nm_kstat_inode_first*)stat)->ino==987 && ((struct nm_kstat_inode_first*)stat)->dev==789);
 assert(stat[12]==0xa5 && stat[127]==0xa5 && pair_attrs==1);
 attr_error=-EIO;assert(nm_getattr_from_backing(parent,&path,(void*)stat,0,0)==-EIO);attr_error=0;
 static _Alignas(8) unsigned char callbacks[512],dentry[128];
 struct nm_inode_info info={0};struct nomount_rule rule={0};info.rule=&rule;rule.r_path=path;
 nm_inode_engine.inode_ops=callbacks;nm_publish_inode_ops(parent,callbacks,NULL);nm_set_inode_private(parent,&info);
 ((struct nm_dentry_head*)dentry)->d_inode=parent;
 assert(!nm_file_getattr_mount((void*)11,(void*)dentry,(void*)stat));
 nm_inode_engine.inode_ops=NULL;nm_inode_engine.directory_ops=callbacks;
 assert(!nm_virtual_directory_getattr_mount((void*)11,(void*)dentry,(void*)stat));
 nm_inode_engine.directory_ops=NULL;nm_vfs_getattr_pair=NULL;
 puts("explicit ABI rejection, pair hash, native pair getattr, mount callbacks and kstat byte boundaries: PASS");
}
int main(void){int rc=oracle_main();assert(!rc);check_abis();return 0;}
'''
    (args.output / 'contracts.c').write_text(source)
    command = ['clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'),
               '-fsanitize=address,undefined', '-g', str(args.output / 'contracts.c'), '-o', str(args.output / 'contracts')]
    compiled = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    ran = subprocess.run([str(args.output / 'contracts')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(ran.stdout + ran.stderr)
    ran.check_returncode()
    result = {'scope': 'Developer host ABI and unchanged control assertions; native interfaces stubbed; no device proof',
              'oracle_commit': BASE, 'oracle_generated_source_sha256': sha(original.encode()),
              'oracle_assertions_preserved': len(old_assertions), 'fixture_input_change': 'explicit 4.19 ABI values for new fields',
              'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in (root / 'nomount').glob('nm*.[ch]')},
              'tool_sha256': sha(Path(__file__).read_bytes()), 'config_sha256': sha(args.target_config.read_bytes()),
              'generated_source_sha256': sha(source.encode()), 'result': ran.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(ran.stdout)


if __name__ == '__main__':
    main()
