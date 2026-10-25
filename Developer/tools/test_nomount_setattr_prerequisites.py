#!/usr/bin/env python3
"""Developer 离线前置取证：保留1033断言，观察存活别名，不实现setattr。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'nomount/tools'))
from test_directory_abis import function
from test_file_control import run
sys.path.insert(0, str(ROOT / 're_kernel/tools'))
from test_btf import index_btf

ORACLES = {
    'int': 'c0cec16eaf2378c071cdfbd94f4748e5ae3f6651e52187172ebbb24b22959c49',
    'bool': 'd4cb16e55685150a67ab31aa57e2623d3172208e3da153c3a2b201c581d47565',
}
GUARDS = {
    'nm_offsets.c': ['nm_copy_backing_inode_attributes'],
    'nm_inode.c': ['nm_inode_matches_binding', 'nm_getattr_from_backing'],
    'nm_virtual_directory.c': ['nm_materialize_virtual_directory', 'nm_cached_directory_test',
                               'nm_virtual_directory_getattr_context'],
    'nm_directory.c': ['nm_dentry_validate'],
}
TEST = r'''
/* 观察夹具中的源状态变化；不模拟chmod/LSM/freeze/内核锁或真实fdget。 */
static void check_live_attribute_aliases(void) {
 security_fixture_reset();security_target();
 kf_nm_dget_parent=virtual_parent;kf_nm_dput=virtual_put;kf_nm_d_drop=virtual_drop;
 kf_nm_vfs_getattr_nosec=port_stat;nm_vfs_getattr_pair=NULL;attr_error=0;
 ((struct nm_dentry_head*)root_dentry)->d_inode=parent;
 struct nm_inode_owner_prefix* source=(void*)backing;
 source->i_mode=0040755;source->i_uid=1000;source->i_gid=1000;security_set_sid(backing,71);
 struct nm_directory_node* a=nm_new_directory_node();
 struct nm_directory_node* b=nm_new_directory_node();assert(a&&b&&a!=b);
 struct nomount_rule rule={.r_path=backing_path,.flags=NM_FLAG_IS_DIR,.refs=1};
 security_query(outer_root);assert(!nm_materialize_virtual_directory(parent,(void*)outer_root,&rule,a,901));
 security_query(outer_again);assert(!nm_materialize_virtual_directory(parent,(void*)outer_again,&rule,b,902));
 struct inode* first=nm_dentry_inode(outer_root);struct inode* second=nm_dentry_inode(outer_again);
 assert(first&&second&&first!=second&&nm_inode_mode(first)==0040755&&nm_inode_mode(second)==0040755);
 assert(nm_inode_private(first)!=nm_inode_private(second)&&a->refs==2&&b->refs==2);
 struct nm_inode_info* ai=nm_inode_private(first);struct nm_inode_info* bi=nm_inode_private(second);
 assert(ai->r_path.dentry==bi->r_path.dentry&&ai->r_path.mnt==bi->r_path.mnt);
 _Alignas(8) unsigned char held[768]={0};
 *(struct nm_path*)nm_file_path(held)=(struct nm_path){.mnt=(void*)1,.dentry=(void*)outer_root};
 ((struct nm_file_inode_ops*)(held+struct_offset.file_inode_ops))->f_inode=first;
 source->i_mode=0040700;source->i_uid=2000;source->i_gid=3000;
 assert(!nm_cached_directory_test(first,ai)&&!nm_cached_directory_test(second,bi));
 assert(nm_inode_mode(first)==0040755&&nm_inode_mode(second)==0040755);
 assert(((struct nm_inode_owner_prefix*)first)->i_uid==1000&&((struct nm_inode_owner_prefix*)second)->i_gid==1000);
 _Alignas(8) unsigned char stat[256];
 struct nm_path path={.mnt=(void*)1,.dentry=(void*)outer_root};
 assert(!nm_virtual_directory_getattr_context(NULL,&path,(void*)stat,77,88));
 assert(((struct nm_kstat_prefix*)stat)->mode==0040700&&((struct nm_kstat_prefix*)stat)->ino==901);
 assert(!nm_virtual_directory_getattr_context(NULL,nm_file_path(held),(void*)stat,77,88));
 assert(((struct nm_kstat_prefix*)stat)->mode==0040700&&nm_inode_mode(first)==0040755);
 int before=virtual_drops;
 assert(!nm_dentry_revalidate((void*)outer_root,0)&&virtual_drops==before+1);
 assert(((struct nm_file_inode_ops*)(held+struct_offset.file_inode_ops))->f_inode==first);
 assert(nm_dentry_inode(nm_file_path(held)->dentry)==first&&nm_inode_mode(first)==0040755);
 /* 源改标签也没有自动改写已发布inode；不是LSM权限执行测试。 */
 security_set_sid(backing,72);
 assert(nm_inode_secid(first)==71&&nm_inode_secid(second)==71&&nm_inode_secid(backing)==72);
 security_query(outer_child);assert(!nm_materialize_virtual_directory(parent,(void*)outer_child,&rule,a,901));
 struct inode* fresh=nm_dentry_inode(outer_child);
 assert(fresh!=first&&fresh!=second&&nm_inode_mode(fresh)==0040700&&nm_inode_secid(fresh)==72);
 assert(((struct nm_inode_owner_prefix*)fresh)->i_uid==2000&&((struct nm_inode_owner_prefix*)fresh)->i_gid==3000);
 assert(nm_inode_mode(first)==0040755&&nm_inode_mode(second)==0040755&&a->refs==3);
 port_iput(first);port_iput(second);port_iput(fresh);
 assert(a->refs==1&&b->refs==1);nm_directory_node_put(a);nm_directory_node_put(b);flush_rcu();
 assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth&&security_gets==security_releases);
 for(int i=0;i<32;i++)assert(!cache[i].inode);
 puts("live alias counterexample: fresh getattr/new inode, stale held inode after revalidate; source mode/owner/SID observation PASS");
}
int main(void){assert(!prior_setattr_prerequisite_main());check_live_attribute_aliases();return 0;}
'''


def tokens(text):
    """Only comments differ in the inherited inode-copy helper."""
    return re.sub(r'\s+', '', re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S))


def btf_evidence(path):
    data = path.read_bytes()
    records, strings = index_btf(data)

    def name(offset):
        at = strings + offset
        return data[at:data.index(0, at)].decode()

    def head(type_id):
        n, info, value = struct.unpack_from('<III', data, records[type_id])
        return name(n), (info >> 24) & 31, info & 65535, value

    def describe(type_id, depth=0):
        if not type_id:
            return 'void'
        assert depth < 32
        n, kind, _, value = head(type_id)
        if kind == 2:
            return describe(value, depth + 1) + '*'
        if kind in (8, 9, 10, 11, 18):
            return describe(value, depth + 1)
        return n or f'kind{kind}'

    locks, funcs = [], []
    wanted = {'down_write', 'up_write', 'mnt_want_write', 'mnt_drop_write', 'notify_change', 'notify_change2'}
    for type_id in range(1, len(records)):
        n, kind, count, value = head(type_id)
        at = records[type_id]
        if kind == 4 and n == 'inode':
            for m in range(count):
                member, typ, off = struct.unpack_from('<III', data, at + 12 + m * 12)
                if name(member) in ('i_rwsem', 'i_mutex'):
                    # This is offline evidence, not a new accepted production layout.
                    assert not (struct.unpack_from('<I', data, at + 4)[0] >> 31) and off % 8 == 0
                    locks.append({'member': name(member), 'byte_offset': off // 8, 'type': describe(typ)})
        if kind == 12 and n in wanted:
            _, proto_kind, argc, ret = head(value)
            assert proto_kind == 13
            params = [struct.unpack_from('<II', data, records[value] + 12 + i * 8) for i in range(argc)]
            funcs.append({'name': n, 'return': describe(ret), 'params': [describe(t) for _, t in params]})
    return {'blob': str(path), 'inode_locks': locks, 'functions': funcs,
            'scope': 'BTF declarations only; not symbol availability, CFI callability or locking/freeze order'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--btf', type=Path, nargs='+', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for abi, digest in ORACLES.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest, abi
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1033
        for file, names in GUARDS.items():
            current = (ROOT / 'nomount' / file).read_text()
            for n in names:
                assert tokens(function(current, n)) == tokens(function(original, n)), n
        entry = 'int main(void){assert(!previous_acl_main());check_acl_reads();return 0;}'
        assert original.count(entry) == 1
        source = original.replace(entry, entry.replace('int main(', 'static int prior_setattr_prerequisite_main(')) + TEST
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert after[:len(before)] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
             '-Wno-invalid-noreturn', '-fno-builtin', '-I', str(ROOT / 'nomount'),
             '-fsanitize=address,undefined', str(out / 'contracts.c'), str(a.cli_source),
             '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before),
                     'result': 'PASS', 'observation': 'old live inodes remain stale; prerequisite NOT closed'})
    receipt = {'scope': 'Developer Tier-3 prerequisite observation; not native permission/syscall/concurrency proof',
               'host': rows, 'btf': [btf_evidence(path) for path in a.btf]}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
