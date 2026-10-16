#!/usr/bin/env python3
"""保留0.2.0控制断言，追加源挂载权限与getattr上下文用例。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = 'c5c49e98164e0129e29b4bd3ba05c8affcd0b352'


def function(source, name):
    match = re.search(r'(?m)^static [^\n]*\b' + name + r'\([^;]*?\)\s*\{', source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


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
        assert sha(subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=root)) == digest
    args.output.mkdir(parents=True, exist_ok=False)

    def old(name):
        return subprocess.check_output(['git', 'show', BASE + ':nomount/' + name], cwd=root).decode()

    def new(name):
        return (root / 'nomount' / name).read_text()

    source = original.replace(old('nm_structs.h'), new('nm_structs.h'))
    start = source.index('struct struct_offset {')
    end = source.index('static int nm_prepare_inode_layout(void)')
    source = source[:start] + new('nm_offsets.c').split('#ifndef CONFIG_KPM_BASELINES', 1)[0].replace('section(".data.re_offsets"), ', '') + source[end:]
    anchor = function(old('nm_inode.c'), 'nm_file_getattr_mount')
    assert source.count(anchor) == 1
    callbacks = '\n'.join(function(new('nm_inode.c'), n) for n in ('nm_file_getattr_userns', 'nm_file_getattr_idmap', 'nm_file_getattr_callback'))
    source = source.replace(anchor, anchor + '\n' + callbacks)
    replacements = {'nm_inode.c': ['nm_prepare_inode_engine'],
                    'nm_virtual_directory.c': ['nm_prepare_virtual_directory_functions', 'nm_prepare_virtual_directory_engine'],
                    'nm_backing_subtree.c': ['nm_check_backing_directory_search', 'nm_prepare_backing_subtrees']}
    for path, names in replacements.items():
        for name in names:
            before, after = function(old(path), name), function(new(path), name)
            if name == 'nm_prepare_virtual_directory_functions':
                before = before.replace('kallsyms_lookup_name_by_suffix', 'virtual_function_lookup')
                after = after.replace('kallsyms_lookup_name_by_suffix', 'virtual_function_lookup')
            assert source.count(before) == 1, name
            source = source.replace(before, after)
    declaration = 'static void kfunc_def(nm_generic_fillattr)(struct inode*, struct kstat*);'
    source = source.replace(declaration, declaration + '\nstatic void (*nm_fillattr_userns)(struct user_namespace*, struct inode*, struct kstat*);\nstatic void (*nm_fillattr_idmap)(struct mnt_idmap*, u32, struct inode*, struct kstat*);')
    before = function(old('nm_virtual_directory.c'), 'nm_virtual_directory_getattr')
    after = '\n'.join(function(new('nm_virtual_directory.c'), n) for n in ['nm_virtual_directory_getattr_context', 'nm_virtual_directory_getattr', 'nm_virtual_directory_getattr_userns', 'nm_virtual_directory_getattr_idmap'])
    assert source.count(before) == 1
    source = source.replace(before, after)
    before = old('nm_backing_inode.c').split('// 成功接收 path 引用')[0].split('static int kfunc_def', 1)[1]
    before = 'static int kfunc_def' + before.replace('kallsyms_lookup_name_by_suffix', 'inode_native_lookup')
    after = new('nm_backing_inode.c').split('// 成功接收 path 引用')[0].split('static int kfunc_def', 1)[1]
    after = 'static int kfunc_def' + after.replace('kallsyms_lookup_name_by_suffix', 'mount_function_lookup')
    assert source.count(before) == 1
    source = source.replace(before, 'static uintptr_t mount_function_lookup(const char*);\n' + after)
    # 为新增必需字段填写已冻结旧目标的准确输入；所有旧assert表达式保持。
    for marker in ('static void target(void) {', 'static void abi_target(void) {'):
        assert source.count(marker) == 1, marker
        source = source.replace(marker, marker + '\nstruct_offset.permission_abi=0;struct_offset.fillattr_abi=2;struct_offset.getattr_context_kind=0;')
    source = source.replace('#define NM_KPM_VERSION "0.2.0"', '#define NM_KPM_VERSION "0.3.0"')
    before_asserts = re.findall(r'\bassert\s*\([^;]+\);', original)
    assert re.findall(r'\bassert\s*\([^;]+\);', source) == before_asserts
    source = source.replace('int main(void){int rc=oracle_main();', 'static int previous_main(void){int rc=oracle_main();')
    source += r'''
static int permission_mask,permission_error,namespace_calls,plain_calls;
static struct inode* permission_inode;
static struct user_namespace* source_namespace;
static struct user_namespace* callback_namespace;
static int plain_permission(struct inode* inode,int mask){permission_inode=inode;permission_mask=mask;plain_calls++;return permission_error;}
static int namespace_permission(struct user_namespace* ns,struct inode* inode,int mask){assert(ns==source_namespace);namespace_calls++;return plain_permission(inode,mask);}
static uintptr_t mount_function_lookup(const char* name){
 if(!strcmp(name,"inode_permission"))return (uintptr_t)(struct_offset.permission_abi==1?(void*)plain_permission:(void*)namespace_permission);
 return inode_native_lookup(name);
}
static void namespace_fillattr(struct user_namespace* ns,struct inode* inode,struct kstat* stat){assert(ns==callback_namespace);permission_inode=inode;namespace_calls++;memset(stat,0x5a,64);}
static void check_mounts(void){
 target();directory_target();control_reference();
 struct nm_mount_context_head mount={0};source_namespace=(void*)0x1000;callback_namespace=(void*)0x2000;mount.context.userns=source_namespace;
 static _Alignas(8) unsigned char inode[1024],dentry[256],ops[512],stat[128];
 ((struct nm_dentry_head*)dentry)->d_inode=(void*)inode;struct nm_path path={&mount,dentry};
 struct_offset.permission_abi=-1;assert(nm_prepare_backing_inode_functions()==-ENOENT);
 struct_offset.permission_abi=7;assert(nm_prepare_backing_inode_functions()==-EOPNOTSUPP);
 struct_offset.permission_abi=1;assert(!nm_prepare_backing_inode_functions()&&!kf_nm_inode_permission2&&nm_permission_ready());
 assert(!nm_backing_read_permission(&path)&&plain_calls==1&&permission_mask==0x24&&permission_inode==(void*)inode);
 struct nm_inode_info info={0};struct nomount_rule rule={0};info.rule=&rule;rule.r_path=path;nm_set_inode_private(inode,&info);
 assert(!nm_check_backing_directory_search((void*)inode)&&permission_mask==1);
 nm_inode_engine.lookup_backing=nm_lookup_backing_directory;nm_inode_engine.inherit_directory=NULL;nm_inode_engine.check_directory_search=NULL;
 assert(!nm_prepare_backing_subtrees()&&nm_inode_engine.inherit_directory&&nm_inode_engine.check_directory_search);
 struct_offset.permission_abi=2;assert(nm_prepare_backing_inode_functions()==-EOPNOTSUPP);
 struct_offset.getattr_context_kind=1;assert(!nm_prepare_backing_inode_functions());
 assert(!nm_backing_read_permission(&path)&&namespace_calls==1&&permission_mask==0x24);
 permission_error=-EACCES;assert(nm_check_backing_directory_search((void*)inode)==-EACCES);permission_error=0;
 mount.context.userns=NULL;assert(nm_backing_read_permission(&path)==-EINVAL);mount.context.userns=source_namespace;
 struct_offset.getattr_callback_args=5;struct_offset.fillattr_abi=3;
 assert(!nm_validate_inode_offsets((const void*)&struct_offset));
 nm_inode_engine.directory_ops=ops;nm_publish_inode_ops(inode,ops,NULL);info.rule=NULL;nm_fillattr_userns=namespace_fillattr;
 int calls=namespace_calls;assert(!nm_virtual_directory_getattr_userns(callback_namespace,&path,(void*)stat,0x55,0));
 assert(namespace_calls==calls+1&&permission_inode==(void*)inode&&stat[0]==0x5a);
 assert(nm_virtual_directory_getattr_userns(NULL,&path,(void*)stat,0x55,0)==-EINVAL);
 assert(nm_file_getattr_callback()==nm_file_getattr_userns);
 nm_inode_engine=(struct nm_inode_engine){0};kf_nm_inode_permission2=NULL;nm_inode_permission_plain=NULL;nm_inode_permission_userns=NULL;
 puts("mount/plain permissions, complete subtree preparation, namespace selection, errors and typed getattr: PASS");
}
int main(void){assert(!previous_main());check_mounts();return 0;}
'''
    c = args.output / 'contracts.c'; c.write_text(source)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'contracts')]
    built = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr); built.check_returncode()
    run = subprocess.run([str(args.output / 'contracts')], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr); run.check_returncode()
    result = {'scope': 'Developer unchanged Oracle and native ABI stubs; no kernel concurrency or device proof', 'oracle_commit': BASE, 'oracle_generated_sha256': sha(original.encode()), 'assertions_preserved': len(before_asserts), 'generated_source_sha256': sha(source.encode()), 'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in (root / 'nomount').glob('nm*.[ch]')}, 'tool_sha256': sha(Path(__file__).read_bytes()), 'result': run.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n');print(run.stdout)


if __name__ == '__main__':
    main()
