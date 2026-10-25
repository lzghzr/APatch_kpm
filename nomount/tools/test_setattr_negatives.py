#!/usr/bin/env python3
"""在1133处原断言后追加setattr四组审计负例；Developer手动宿主自检。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = {
    'int': 'e2c0efcc91c6b5591b686437408aa5c6c1deabd7b25b2bafae76aa5c8e8c153a',
    'bool': 'c9f829961d2f6d46462953fc7bfe0c96842c5ec3105fca1065b3917bdbb702d3',
}

HELPERS = r'''
/* 复用原生准备函数体；BTF布局和符号解析由宿主提供，生产代码不作改写。 */
static int sn_btf(struct nm_setattr_layout*l,bool*unavailable){
 *unavailable=false;*l=nm_setattr_layout;return 0;
}
static unsigned long sn_lookup(const char*n){
 if(!strcmp(n,"down_write_killable"))return (uintptr_t)sa_lock;
 if(!strcmp(n,"up_write"))return (uintptr_t)sa_unlock;
 if(!strcmp(n,"__mnt_is_readonly"))return (uintptr_t)sa_readonly;
 if(!strcmp(n,"notify_change"))return (uintptr_t)(nm_setattr_layout.context?(void*)sa_notify_mapped:(void*)sa_notify);
 if(!strcmp(n,"notify_change2"))return (uintptr_t)sa_notify_mapped;
 return 0;
}
'''

TEST = r'''
static struct nm_mount_context_head*sn_outer_mount;
static bool sn_readonly(struct vfsmount*m){
 assert((void*)m==backing_path.mnt&&(void*)m!=sn_outer_mount);
 assert(!(sn_outer_mount->flags&0x40));sa_ro_calls++;
 return ((struct nm_mount_context_head*)m)->flags&0x40;
}
static int sn_unlinked_notify(struct dentry*d,void*a,struct inode**delegated){
 assert(!nm_inode_nlink(nm_dentry_inode(d)));
 return sa_notify(d,a,delegated);
}
static int sn_unlinked_mapped(void*c,struct dentry*d,void*a,struct inode**delegated){
 assert(c==sa_expected_context);return sn_unlinked_notify(d,a,delegated);
}
static void sn_ready(int shape,struct nm_mount_context_head*source){
 sa_ready(shape<3?shape:0);
 if(shape==3){struct_offset.permission_abi=0;struct_offset.iop_getattr=128;nm_setattr_layout.slot=112;}
 sa_expected_context=shape==3?(void*)source:(void*)source->context.userns;
 assert(!sn_prepare_dynamic()&&!nm_setattr_status);
 assert(nm_setattr_lock&&nm_setattr_unlock&&nm_setattr_readonly);
 assert((shape?nm_notify_context!=NULL:nm_notify_plain!=NULL));
}
static int sn_call(int shape,struct dentry*d,void*a){
 return shape?nm_setattr_mapped(sa_expected_context,d,a):nm_setattr(d,a);
}
static void check_setattr_audit_negatives(void){
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,903));
 struct inode*outer=nm_dentry_inode(outer_root);assert(outer&&outer!=backing);
 struct nm_inode_info*info=nm_inode_private(outer);assert(info&&info->initialized);
 struct nm_mount_context_head outer_mount={.flags=0};
 struct nm_mount_context_head source_mount={.flags=0,.context.userns=(void*)0x8765};
 sn_outer_mount=&outer_mount;void*saved_mnt=backing_path.mnt;
 backing_path.mnt=&source_mount;info->r_path.mnt=&source_mount;
 struct nm_iattr_head attr={1};sa_attr=&attr;
 unsigned char source_before[768],outer_before[768],linked_source[768];
 for(int shape=0;shape<4;shape++){
  /* plain / userns / idmap / Android notify_change2，均经动态准备分支置ready。 */
  sn_ready(shape,&source_mount);nm_setattr_readonly=sn_readonly;source_mount.flags=0x40;
  memcpy(source_before,backing,768);memcpy(outer_before,outer,768);
  assert(sn_call(shape,(void*)outer_root,&attr)==-EROFS);
  assert(sa_locks==1&&sa_unlocks==1&&sa_ro_calls==1&&!sa_notify_calls);
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  source_mount.flags=0;
  sn_ready(shape,&source_mount);attr.ia_valid=1U|8U;
  assert(sn_call(shape,(void*)outer_root,&attr)==-EOPNOTSUPP);
  assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  attr.ia_valid=1;
  for(int missing=0;missing<4;missing++){
   sn_ready(shape,&source_mount);
   if(missing==0)nm_setattr_lock=NULL;
   if(missing==1)nm_setattr_unlock=NULL;
   if(missing==2)nm_setattr_readonly=NULL;
   if(missing==3){if(shape)nm_notify_context=NULL;else nm_notify_plain=NULL;}
   assert(sn_call(shape,(void*)outer_root,&attr)==-ENOENT);
   assert(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls);
   assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  }
  memcpy(linked_source,backing,768);
  /* 外部源变化可使held inode仍是旧快照；notify失败不得把该变化当作本次成功同步。 */
  ((struct nm_inode_owner_prefix*)backing)->i_mode=0100600;
  ((struct nm_inode_owner_prefix*)backing)->i_uid=222;
  ((struct nm_inode_owner_prefix*)backing)->i_gid=333;
  struct nm_inode_size_times*times=(void*)((uintptr_t)backing+struct_offset.inode_size);
  times->i_size=4321;times->i_atime.seconds=100;times->i_mtime.seconds=200;times->i_ctime.seconds=300;
  assert(nm_inode_mode(backing)!=nm_inode_mode(outer)&&nm_inode_size(backing)!=nm_inode_size(outer));
  *(u32*)((uintptr_t)backing+struct_offset.inode_nlink)=0;
  memcpy(source_before,backing,768);
  const int errors[]={-ENOENT,-ESTALE};
  for(unsigned e=0;e<sizeof(errors)/sizeof(errors[0]);e++){
   sn_ready(shape,&source_mount);sa_notify_error=errors[e];
   nm_notify_plain=sn_unlinked_notify;nm_notify_context=sn_unlinked_mapped;
   assert(sn_call(shape,(void*)outer_root,&attr)==errors[e]);
   assert(sa_locks==1&&sa_unlocks==1&&sa_ro_calls==1&&sa_notify_calls==1);
   assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768));
  }
  memcpy(backing,linked_source,768);
 }
 backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;
 port_iput(outer);assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 nm_setattr_status=-EOPNOTSUPP;
 puts("audit negatives PASS: outer rw/source ro=4; MODE|SIZE pre-lock=4; NULL helper=16; unlinked notify errno=8");
}
int main(void){assert(!previous_setattr_a_main());check_setattr_audit_negatives();return 0;}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    production = (ROOT / 'nomount/nm_setattr.c').read_text()
    prepare = function(production, 'nm_prepare_setattr')
    dynamic = prepare.replace('nm_prepare_setattr(', 'sn_prepare_dynamic(', 1)
    dynamic = dynamic.replace('calculate_btf_setattr(', 'sn_btf(').replace('kallsyms_lookup_name_by_suffix(', 'sn_lookup(')
    rows = []
    for abi, digest in DIGESTS.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        assert original.count(production) == 1, 'fixture must contain the current production implementation'
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1133
        entry = 'int main(void){assert(!previous_setattr_main());check_setattr();check_setattr_static_profiles();return 0;}'
        assert original.count(entry) == 1
        source = original.replace(entry, entry.replace('int main(', 'static int previous_setattr_a_main('), 1)
        source += HELPERS + '\n#undef CONFIG_KPM_BASELINES\n' + dynamic + '\n#define CONFIG_KPM_BASELINES 1\n' + TEST
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
                     'total_assert_sites': len(after), 'negative_cases': 32, 'result': 'PASS'})
    receipt = {'scope': 'Developer ASan/UBSan host fixtures; BTF/symbol/readonly/notify helpers modeled; not native RO/freeze/LSM proof',
               'unlinked': 'injected native ENOENT/ESTALE propagation; nlink zero does not imply universal native failure',
               'host': rows}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
