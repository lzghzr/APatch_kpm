#!/usr/bin/env python3
"""保持1058处原断言，追加A档源属性回调与拒绝路径；Developer宿主自检。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
BASE = 'd0f74b0ac98ba8d516ea9ac1c0c9defb0f64d075'
DIGESTS = {'int': 'de17ebb206976f299e8495e497293ccf3636cc7360d33bc591fb05cdf3669bf5',
           'bool': '41bbf1f1bd3be9abf6648ff1b78deecf76a401d375a437726f811ce1b61da9cb'}
TEST = r'''
static int sa_locks,sa_unlocks,sa_ro_calls,sa_notify_calls,sa_lock_error,sa_notify_error;
static bool sa_ro;static void*sa_expected_lock;static void*sa_expected_context;static void*sa_attr;
static int sa_lock(void*p){assert(p==sa_expected_lock&&!rcu_depth&&!spin_depth);sa_locks++;return sa_lock_error;}
static void sa_unlock(void*p){assert(p==sa_expected_lock&&sa_locks>sa_unlocks);sa_unlocks++;}
static bool sa_readonly(struct vfsmount*m){assert((void*)m==backing_path.mnt);sa_ro_calls++;return sa_ro;}
static int sa_notify(struct dentry*d,void*a,struct inode**delegated){
 assert(d==(void*)backing_path.dentry&&a==sa_attr&&!delegated&&sa_locks>sa_unlocks);sa_notify_calls++;
 if(sa_notify_error)return sa_notify_error;
 struct nm_inode_owner_prefix*o=(void*)backing;o->i_mode=0100600;o->i_uid=222;o->i_gid=333;
 struct nm_inode_size_times*t=(void*)((uintptr_t)backing+struct_offset.inode_size);t->i_atime.seconds=100;t->i_mtime.seconds=200;t->i_ctime.seconds=300;
 return 0;
}
static int sa_notify_mapped(void*c,struct dentry*d,void*a,struct inode**delegated){assert(c==sa_expected_context);return sa_notify(d,a,delegated);}
static void sa_ready(int context){
 struct_offset.permission_abi=context+1;struct_offset.getattr_context_kind=context;struct_offset.iop_getattr=112;
 struct_offset.getattr_callback_args=context?5:4;struct_offset.getattr_function_args=4;struct_offset.fillattr_abi=context+2;
 nm_setattr_layout=(struct nm_setattr_layout){160,1,104,context};nm_setattr_status=0;
 nm_setattr_lock=sa_lock;nm_setattr_unlock=sa_unlock;nm_setattr_readonly=sa_readonly;
 nm_notify_plain=sa_notify;nm_notify_context=sa_notify_mapped;sa_expected_lock=(void*)((uintptr_t)backing+160);
 sa_locks=sa_unlocks=sa_ro_calls=sa_notify_calls=sa_lock_error=sa_notify_error=0;sa_ro=false;
}
static void check_setattr(void){
 security_fixture_reset();security_target();
 struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,901));
 security_query(outer_again);assert(!nm_materialize_file(parent,(void*)outer_again,&rule,902));
 struct inode*first=nm_dentry_inode(outer_root);struct inode*alias=nm_dentry_inode(outer_again);
 assert(first&&alias&&first!=alias);
 int second;assert(nm_setattr_slots(&second)==112&&second==120);
 assert(nm_operation_callback(nm_inode_engine.inode_ops,112)==nm_setattr&&nm_operation_callback(nm_inode_engine.inode_ops,120)==nm_setattr_mapped);
 assert(nm_operation_callback(nm_inode_engine.directory_ops,112)==nm_setattr);
 assert(nm_inode_engine.symlink_ops&&nm_operation_callback(nm_inode_engine.symlink_ops,112)==nm_setattr);
 struct nm_iattr_head attr={1};sa_attr=&attr;
 assert(nm_setattr((void*)outer_root,&attr)==-EOPNOTSUPP);
 sa_ready(0);unsigned char before_source[768],before_outer[768];
 memcpy(before_source,backing,768);memcpy(before_outer,first,768);
 sa_ro=true;assert(nm_setattr((void*)outer_root,&attr)==-EROFS);
 assert(sa_locks==1&&sa_unlocks==1&&sa_ro_calls==1&&!sa_notify_calls);
 assert(!memcmp(before_source,backing,768)&&!memcmp(before_outer,first,768));
 sa_ready(0);sa_lock_error=-EINTR;assert(nm_setattr((void*)outer_root,&attr)==-EINTR);
 assert(sa_locks==1&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls&&!memcmp(before_source,backing,768));
 sa_ready(0);sa_notify_error=-EPERM;assert(nm_setattr((void*)outer_root,&attr)==-EPERM);
 assert(sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1&&!memcmp(before_outer,first,768));
 sa_ready(0);attr.ia_valid=8;sa_notify_error=-EFBIG;assert(nm_setattr((void*)outer_root,&attr)==-EFBIG&&sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1);attr.ia_valid=1;sa_ready(0);
 nm_setattr_layout.lock_offset=-8;assert(nm_setattr((void*)outer_root,&attr)==-EINVAL&&!sa_locks);nm_setattr_layout.lock_offset=160;
 int saved_size=struct_offset.inode_size;struct_offset.inode_size=-8;assert(nm_setattr((void*)outer_root,&attr)==-EINVAL&&!sa_locks);struct_offset.inode_size=saved_size;
 struct_offset.iop_getattr=-8;assert(nm_setattr((void*)outer_root,&attr)==-EINVAL&&!sa_locks);struct_offset.iop_getattr=112;
 nm_setattr_lock=NULL;assert(nm_setattr((void*)outer_root,&attr)==-ENOENT&&!sa_locks);nm_setattr_lock=sa_lock;
 struct nm_inode_info*info=nm_inode_private(first);void*saved=info->r_path.dentry;info->r_path.dentry=NULL;
 assert(nm_setattr((void*)outer_root,&attr)==-EOPNOTSUPP&&!sa_locks);info->r_path.dentry=saved;
 ((struct nm_dentry_head*)saved)->d_inode=first;assert(nm_setattr((void*)outer_root,&attr)==-ELOOP&&!sa_locks);((struct nm_dentry_head*)saved)->d_inode=backing;
 assert(nm_setattr(NULL,&attr)==-EINVAL&&nm_setattr((void*)outer_root,NULL)==-EINVAL&&!sa_locks);
 /* 模拟外部源size变化；本次mode回调不执行truncate。 */
 *(int64_t*)((uintptr_t)backing+struct_offset.inode_size)=567;
 _Alignas(8)unsigned char held[768]={0};((struct nm_file_inode_ops*)(held+struct_offset.file_inode_ops))->f_inode=first;
 assert(!nm_setattr((void*)outer_root,&attr)&&sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1);
 assert(nm_inode_mode(first)==0100600&&((struct nm_inode_owner_prefix*)first)->i_uid==222&&((struct nm_inode_owner_prefix*)first)->i_gid==333);
 assert(!memcmp((void*)((uintptr_t)first+struct_offset.inode_size),(void*)((uintptr_t)backing+struct_offset.inode_size),sizeof(struct nm_inode_size_times))&&nm_inode_size(first)==567);
 assert(nm_inode_mode(alias)==0100644&&nm_inode_secid(first)==71&&((struct nm_file_inode_ops*)(held+struct_offset.file_inode_ops))->f_inode==first);
 struct nm_mount_context_head mount={.context.userns=(void*)0x8765};void*saved_mnt=backing_path.mnt;
 backing_path.mnt=&mount;info->r_path.mnt=&mount;
 for(int context=1;context<=2;context++){
  sa_ready(context);sa_expected_context=mount.context.userns;
  assert(!nm_setattr_mapped(sa_expected_context,(void*)outer_root,&attr)&&sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1);
  assert(nm_setattr_mapped((void*)0x1111,(void*)outer_root,&attr)==-EXDEV&&sa_locks==1);
  mount.context.userns=NULL;assert(nm_setattr_mapped((void*)0x1111,(void*)outer_root,&attr)==-EINVAL&&sa_locks==1);mount.context.userns=(void*)0x8765;
 }
 backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;
 sa_ready(0);struct_offset.permission_abi=0;struct_offset.iop_getattr=128;nm_setattr_layout.slot=112;sa_expected_context=saved_mnt;
 assert(!nm_setattr((void*)outer_root,&attr)&&sa_locks==1&&sa_unlocks==1&&sa_notify_calls==1);
 for(int i=0;i<2;i++){
  target();directory_target();struct_offset.iop_getattr=i?144:128;struct_offset.permission_abi=0;
  int slot=nm_setattr_slots(&second);assert(slot==(i?128:112)&&second==slot+8);
 }
 port_iput(first);port_iput(alias);assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 nm_setattr_status=-EOPNOTSUPP;puts("A setattr: readonly unchanged, source-lock errno/unlock pairing, notify errno, initiating inode/held-FD, alias snapshot, mapped source context, SIZE native errno/negative-layout refusal PASS");
}
int main(void){assert(!previous_setattr_main());check_setattr();return 0;}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output', type=Path, required=True)
    p.add_argument('--cli-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    configs = sorted((ROOT / 'local/nomount/configs').glob('*v4.json'))
    if len(configs) != 12:
        raise FileNotFoundError('12 local static regression profiles required in local/nomount/configs; '
                                'restore the target-bound evidence before running this test')
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    old_header = subprocess.check_output(['git', 'show', BASE + ':nomount/nm_structs.h'], cwd=ROOT).decode()
    for abi, digest in DIGESTS.items():
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == digest
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert len(before) == 1058
        assert original.count(old_header) == 1
        source = original.replace(old_header, (ROOT / 'nomount/nm_structs.h').read_text(), 1)
        anchor = function(source, 'nm_is_virtual_inode')
        source = source.replace(anchor, anchor + '\n' + (ROOT / 'nomount/nm_setattr.c').read_text(), 1)
        for file, names in {'nm_inode.c': ['nm_prepare_inode_engine', 'nm_new_symlink_operations'],
                            'nm_virtual_directory.c': ['nm_prepare_virtual_directory_engine']}.items():
            for name in names:
                updated = function((ROOT / 'nomount' / file).read_text(), name)
                if name == 'nm_new_symlink_operations':
                    updated = updated.replace('kallsyms_lookup_name_by_suffix(', 'consistency_lookup(')
                source = source.replace(function(source, name), updated, 1)
        assert re.findall(r'\bassert\s*\([^;]+\);', source) == before
        entry = 'int main(void){assert(!prior_setattr_prerequisite_main());check_live_attribute_aliases();return 0;}'
        assert source.count(entry) == 1
        source = source.replace(entry, entry.replace('int main(', 'static int previous_setattr_main('), 1)
        matrix = '\nstatic void check_setattr_static_profiles(void){\n'
        for config in configs:
            values = json.loads(config.read_text())['offsets']
            matrix += 'struct_offset=(struct struct_offset){' + ','.join(f'.{k}={v}' for k,v in values.items()) + '};\n'
            matrix += '{unsigned char table[512]={0};assert(!nm_prepare_setattr()&&nm_setattr_status==-EOPNOTSUPP);assert(!nm_install_setattr(table));assert(nm_setattr(NULL,NULL)==-EOPNOTSUPP); }\n'
        matrix += 'puts(\"12 static setter profiles: registered refusal callbacks, unknown lock rejected PASS\");}\n'
        source += matrix + TEST.replace('check_setattr();return 0;', 'check_setattr();check_setattr_static_profiles();return 0;')
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert after[:len(before)] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn',
             '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'),
             str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before), 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer host callback stubs; not native filesystem/LSM/remount/freeze proof', 'host': rows}, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
