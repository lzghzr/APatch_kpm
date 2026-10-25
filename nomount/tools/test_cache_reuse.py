#!/usr/bin/env python3
"""执行当前生产正项回源复用，保留1545条Oracle，仅迁移M1-O1/O2。"""
import argparse
import json
from pathlib import Path
import re

from test_directory_abis import function
from test_file_control import run
from test_inode_lock import assertions

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = {
    'assert(nm_is_file_inode(first_file)&&!nm_dentry_revalidate((void*)outer_child,0));':
        'assert(nm_is_file_inode(first_file)&&nm_dentry_revalidate((void*)outer_child,0)==1);',
    'assert(nm_is_directory_inode(sub_inode)&&!nm_dentry_revalidate((void*)outer_sub,0));':
        'assert(nm_is_directory_inode(sub_inode)&&nm_dentry_revalidate((void*)outer_sub,0)==1);',
}
TEST = r'''
static const char*reuse_path="/system/app/Package/base.apk";
static int reuse_action;
static struct dentry*reuse_dentry;
static int (*reuse_native_query)(struct dentry*,struct vfsmount*,const char*,unsigned,struct nm_path*);
static void reuse_add(const char*path,bool whiteout){
 struct nm_topology_updates u={0};struct nomount_rule*r=whiteout?nm_alloc_rule(NULL,0,NM_FLAG_WHITEOUT,1000):port_rule("/file",1000);
 assert(!IS_ERR(r));manager_depth=1;int rc=nm_topology_add_locked(path,strlen(path),r,&u);manager_depth=0;
 assert(!rc);nm_finish_topology_updates(&u);
}
static void reuse_del(const char*path){
 struct nm_topology_updates u={0};manager_depth=1;int rc=nm_topology_remove_locked(path,strlen(path),1000,&u);manager_depth=0;
 assert(!rc);nm_finish_topology_updates(&u);
}
static int reuse_query(struct dentry*d,struct vfsmount*m,const char*n,unsigned f,struct nm_path*p){
 int rc=reuse_native_query(d,m,n,f,p),action=reuse_action;reuse_action=0;
 if(action==1)reuse_add(reuse_path,false);
 if(action==2)((struct nm_dentry_head*)reuse_dentry)->d_name.name="other.apk";
 if(action==3)set_uid(2000);
 if(action==4)((struct nm_dentry_head*)reuse_dentry)->d_parent=outer_again;
 return rc;
}
static void check_file_reuse(struct inode*parent_inode,struct inode*i,struct dentry*d){
 struct nm_inode_info*info=nm_inode_private(i);struct nm_inode_info saved=*info;
 assert(info->inherited_child&&info->initialized&&!info->init_error&&sizeof(*info)==64&&sizeof(struct nomount_rule)==56);
 int q=path_queries,g=security_gets,rel=security_releases,n=security_notifies,alloc=alloc_calls;
 for(int k=0;k<5;k++)assert(nm_dentry_revalidate(d,0)==1);
 assert(path_queries==q+5&&security_gets==g+5&&security_releases==rel+5&&security_notifies==n&&alloc_calls==alloc);
 assert(nm_dentry_inode(d)==i&&nm_inode_private(i)==info&&!memcmp(info,&saved,sizeof(saved)));
 file_exists=0;q=path_queries;assert(!nm_dentry_revalidate(d,0)&&path_queries==q+1);file_exists=1;
 replaced_file=1;assert(!nm_dentry_revalidate(d,0)&&info->r_path.dentry==source_file_dentry);replaced_file=0;
 void*mount=info->r_path.mnt;info->r_path.mnt=(void*)0x456;assert(!nm_dentry_revalidate(d,0));info->r_path.mnt=mount;
 void*map=nm_inode_mapping(source_file_inode);nm_inode_objects(source_file_inode)->i_mapping=(void*)0x12345;
 assert(!nm_dentry_revalidate(d,0));nm_inode_objects(source_file_inode)->i_mapping=map;
 struct nm_inode_owner_prefix*owner=(void*)source_file_inode;u16 mode=owner->i_mode;u32 uid=owner->i_uid,gid=owner->i_gid;
 owner->i_mode^=0100;assert(!nm_dentry_revalidate(d,0));owner->i_mode=mode;
 owner->i_mode=0120777;assert(!nm_dentry_revalidate(d,0));owner->i_mode=mode;
 owner->i_uid++;assert(!nm_dentry_revalidate(d,0));owner->i_uid=uid;
 owner->i_gid++;assert(!nm_dentry_revalidate(d,0));owner->i_gid=gid;
 struct nm_inode_size_times*t=(void*)(source_file_inode+struct_offset.inode_size);struct nm_inode_size_times times=*t;
 t->i_size++;assert(!nm_dentry_revalidate(d,0));*t=times;
 t->i_mtime.seconds++;assert(!nm_dentry_revalidate(d,0));*t=times;
 t->i_atime.nanoseconds++;assert(!nm_dentry_revalidate(d,0));*t=times;
 t->i_ctime.seconds++;assert(!nm_dentry_revalidate(d,0));*t=times;
 u64*b=(void*)(source_file_inode+struct_offset.inode_blocks);(*b)++;assert(!nm_dentry_revalidate(d,0));(*b)--;
 u32 sid=security_sid_value((void*)source_file_inode);security_set_sid((void*)source_file_inode,sid+1);
 assert(!nm_dentry_revalidate(d,0)&&info->secid==saved.secid);security_set_sid((void*)source_file_inode,sid);
 security_get_error=-EIO;q=path_queries;assert(nm_dentry_revalidate(d,0)==-EIO&&path_queries==q+1);security_get_error=0;
 security_empty=1;assert(nm_dentry_revalidate(d,0)==-EOPNOTSUPP);security_empty=0;
 path_denied=-EACCES;assert(nm_dentry_revalidate(d,0)==-EACCES);path_denied=0;
 bool init=info->initialized;info->initialized=false;q=path_queries;assert(!nm_dentry_revalidate(d,0)&&path_queries==q);info->initialized=init;
 info->init_error=-EIO;assert(!nm_dentry_revalidate(d,0));info->init_error=0;
 bool inherited=info->inherited_child;info->inherited_child=false;assert(!nm_dentry_revalidate(d,0));info->inherited_child=inherited;
 int (*validator)(struct inode*,struct inode*,const struct nm_qstr*)=nm_inode_engine.revalidate_backing;
 nm_inode_engine.revalidate_backing=NULL;assert(!nm_dentry_revalidate(d,0));nm_inode_engine.revalidate_backing=validator;
 q=path_queries;assert(nm_dentry_revalidate(d,0x40)==-ECHILD&&path_queries==q);
 struct nm_inode_info*pi=nm_inode_private(parent_inode);u16 flags=pi->flags;pi->flags|=NM_FLAG_OPAQUE;
 assert(!nm_dentry_revalidate(d,0));pi->flags=flags;
 assert(!nm_uid_add(1000));q=path_queries;assert(!nm_dentry_revalidate(d,0)&&path_queries==q);assert(!nm_uid_del(1000));flush_rcu();
 /* 显式规则新增优先；删除后，原显式对象即便来源相同也不能变成继承缓存。 */
 reuse_add(reuse_path,false);assert(!nm_dentry_revalidate(d,0));
 _Alignas(8) unsigned char explicit_dentry[256]={0};port_query_dentry(explicit_dentry,"base.apk",outer_root);
 assert(!nm_directory_lookup(parent_inode,(void*)explicit_dentry,0));struct inode*explicit_inode=nm_dentry_inode(explicit_dentry);
 assert(explicit_inode&&!((struct nm_inode_info*)nm_inode_private(explicit_inode))->inherited_child);
 reuse_del(reuse_path);assert(!nm_dentry_revalidate((void*)explicit_dentry,0));port_iput(explicit_inode);
 assert(nm_dentry_revalidate(d,0)==1);
 reuse_add(reuse_path,true);assert(!nm_dentry_revalidate(d,0));reuse_del(reuse_path);
 /* 可睡眠回源阶段改变规则、名字或调用者；第二次检查必须拒绝旧结论。 */
 reuse_native_query=kf_nm_vfs_path_lookup;kf_nm_vfs_path_lookup=reuse_query;reuse_dentry=d;
 reuse_action=1;assert(!nm_dentry_revalidate(d,0)&&!reuse_action);reuse_del(reuse_path);
 reuse_action=2;assert(!nm_dentry_revalidate(d,0));((struct nm_dentry_head*)d)->d_name.name="base.apk";
 reuse_action=3;assert(!nm_dentry_revalidate(d,0));set_uid(1000);
 reuse_action=4;assert(!nm_dentry_revalidate(d,0));((struct nm_dentry_head*)d)->d_parent=outer_root;
 kf_nm_vfs_path_lookup=reuse_native_query;
 assert(nm_dentry_revalidate(d,0)==1&&!memcmp(info,&saved,sizeof(saved)));
 /* 模拟原生最后iput后重查：没有私有cache索引依赖旧对象/node地址。 */
 _Alignas(8) unsigned char reclaimed[256]={0};u64 number=nm_inode_number(i);
 for(int k=0;k<2;k++){
  port_query_dentry(reclaimed,"base.apk",outer_root);assert(!nm_directory_lookup(parent_inode,(void*)reclaimed,0));
  struct inode*rebuilt=nm_dentry_inode(reclaimed);assert(rebuilt&&nm_inode_number(rebuilt)==number&&nm_dentry_revalidate((void*)reclaimed,0)==1);
  port_iput(rebuilt);((struct nm_dentry_head*)reclaimed)->d_inode=NULL;
 }
 assert(!memcmp(info,&saved,sizeof(saved))&&security_gets==security_releases);
 printf("cache file: strict lookups=5; materialization/notify=0; disappearance/replacement/rules/binding/attributes/races checked\n");
}
static void check_directory_reuse(struct inode*parent_inode,struct inode*i,struct dentry*d){
 (void)parent_inode;struct nm_inode_info*info=nm_inode_private(i);void*node=info->dir_node;
 assert(info->inherited_child&&node);int q=path_queries,n=security_notifies,a=alloc_calls,unlocked=cache_unlocks;
 for(int k=0;k<5;k++)assert(nm_dentry_revalidate(d,0)==1);
 assert(path_queries==q+5&&security_notifies==n&&alloc_calls==a&&cache_unlocks==unlocked&&info->dir_node==node&&nm_dentry_inode(d)==i);
 u32*links=(void*)(source_sub_inode+struct_offset.inode_nlink);(*links)++;assert(!nm_dentry_revalidate(d,0));(*links)--;
 const char*deep="/system/app/Package/sub/deep/inject";reuse_add(deep,false);
 assert(!nm_dentry_revalidate(d,0)&&info->dir_node==node);reuse_del(deep);
 assert(nm_dentry_revalidate(d,0)==1&&info->dir_node==node);
 puts("cache directory: inode/info/node/security reused; deep ADD invalidates old inherited view");
}
'''


def declaration(source, name):
    m = re.search(r'^struct ' + name + r' \{.*?^\};', source, re.M | re.S)
    assert m, name
    return m.group()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for n in ('oracle-output', 'cli-source', 'reference-image', 'image', 'output'):
        parser.add_argument('--' + n, type=Path, required=True)
    a = parser.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for abi in ('int', 'bool'):
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = assertions(original)
        assert len(before) == 1545
        source = original
        for filename, name in [('nm_rules.h', 'nomount_rule'), ('nm_rules.h', 'nm_inode_info'), ('nm_inode.c', 'nm_inode_engine')]:
            source = source.replace(declaration(source, name), declaration((ROOT / 'nomount' / filename).read_text(), name), 1)
        for filename, names in {'nm_inode.c': ['nm_bind_inode_path'],
                                'nm_backing_inode.c': ['nm_lookup_backing_directory', 'nm_prepare_backing_inode_engine'],
                                'nm_directory.c': ['nm_dentry_validate']}.items():
            text = (ROOT / 'nomount' / filename).read_text()
            for name in names:
                new = function(text, name)
                if name == 'nm_dentry_validate':
                    new = '\n'.join(function(text, n) for n in ('nm_inherited_name', 'nm_inherited_view', 'nm_revalidate_inherited')) + '\n' + new
                if name == 'nm_prepare_backing_inode_engine':
                    new = function(text, 'nm_revalidate_backing_child') + '\n' + new
                source = source.replace(function(source, name), new, 1)
        after = [MIGRATIONS.get(t, t) for t in before]
        for old, new in MIGRATIONS.items():
            assert source.count(old) == 1
            source = source.replace(old, new, 1)
        assert assertions(source) == after
        # Only append calls and a test family; the two authorized expression migrations above are exhaustive.
        source = source.replace('int backing_inode_contract_main(void)',
                                'static void check_file_reuse(struct inode*,struct inode*,struct dentry*);\nstatic void check_directory_reuse(struct inode*,struct inode*,struct dentry*);\nint backing_inode_contract_main(void)', 1)
        file_case, dir_case = MIGRATIONS.values()
        source = source.replace(file_case, file_case + 'check_file_reuse(root_inode,first_file,(void*)outer_child);', 1)
        source = source.replace(dir_case, dir_case + 'check_directory_reuse(root_inode,sub_inode,(void*)outer_sub);', 1)
        source = source.replace('int main(int argc,char**argv)', 'static int previous_cache_main(int argc,char**argv)', 1)
        source += TEST + '\nint main(int argc,char**argv){assert(!previous_cache_main(argc,argv));return 0;}\n'
        assert assertions(source)[:1545] == after
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'), str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str(a.reference_image.resolve()), str(a.image.resolve())], out / 'run.log')
        rows.append({'abi': abi, 'baseline_sites': 1545, 'unchanged_expressions': 1543, 'authorized_migrations': 2,
                     'added_assert_sites': len(assertions(source)) - 1545, 'total_assert_sites': len(assertions(source)), 'host_returncode': 0})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer ASan/UBSan native stubs and controlled interleavings, not actual VFS cache or concurrency proof; independent Oracle review pending',
        'authorization': '7c4e160a505f71dc9afc6ea56683a71c4145d5fa', 'migrations': MIGRATIONS, 'rows': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
