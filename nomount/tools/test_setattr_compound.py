#!/usr/bin/env python3
"""保留1158处断言，逐条追加三种含ATTR_SIZE的复合标记拒绝用例。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = {'int': '0985edf926909eccced7bdde8ea61fecb0de303d3e62369e37aabb466e8668f0',
           'bool': '089c753a9ed2c33f75872727d9bec805cbe78e5ef4d90bccded6777326390ad9'}
TEST = r'''
static void check_setattr_compound(void){
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,904));
 struct inode*outer=nm_dentry_inode(outer_root);assert(outer&&outer!=backing);
 struct nm_inode_info*info=nm_inode_private(outer);
 struct nm_mount_context_head mount={.context.userns=(void*)0x8765};void*saved_mnt=backing_path.mnt;
 backing_path.mnt=&mount;info->r_path.mnt=&mount;
 unsigned char source_before[768],outer_before[768];
 memcpy(source_before,backing,768);memcpy(outer_before,outer,768);
 struct nm_iattr_head attr;sa_attr=&attr;
 for(int shape=0;shape<4;shape++){
  sn_ready(shape,&mount);attr.ia_valid=1U|8U;
  assert(sn_call(shape,(void*)outer_root,&attr)==-EOPNOTSUPP);
  assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  sn_ready(shape,&mount);attr.ia_valid=1U|8U|16U;
  assert(sn_call(shape,(void*)outer_root,&attr)==-EOPNOTSUPP);
  assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  sn_ready(shape,&mount);attr.ia_valid=2U|8U;
  assert(sn_call(shape,(void*)outer_root,&attr)==-EOPNOTSUPP);
  assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
 }
 backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;port_iput(outer);
 assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);nm_setattr_status=-EOPNOTSUPP;
 puts("compound ATTR_SIZE: 9/25/10 x 4 ABI shapes, pre-lock refusal and both inode snapshots PASS");
}
int main(void){assert(!previous_compound_main());check_setattr_compound();return 0;}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for abi, digest in DIGESTS.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        assert original.count((ROOT / 'nomount/nm_setattr.c').read_text()) == 1
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1158
        entry = 'int main(void){assert(!previous_setattr_a_main());check_setattr_audit_negatives();return 0;}'
        assert original.count(entry) == 1
        source = original.replace(entry, entry.replace('int main(', 'static int previous_compound_main('), 1) + TEST
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
                     'total_assert_sites': len(after), 'compound_values': [9, 25, 10], 'cases': 12, 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer host stubs, ASan/UBSan', 'host': rows}, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
