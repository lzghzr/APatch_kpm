#!/usr/bin/env python3
"""M2前置：保留M1断言，执行截断拒绝边界与固定原生killpriv片段；不开放truncate。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = {'int': 'c70f98bf051ac482faf120b68d17e1d8cfb9af6d56d4185303b076f9cd778c1b',
           'bool': 'b1209c3032cd3122bae757df7302f98a2423ff19c96b925401d0a9ddb09b8509'}
TEST = r'''
static void m2_check_open_contract(void){
 nm_discard_directory_view();target();directory_target();missing=NULL;fail_alloc=0;
 nm_backing_open_permission=NULL;nm_backing_write_open_permission=NULL;
 assert(!nm_prepare_inode_engine()&&!nm_prepare_directory_engine()&&!nm_prepare_virtual_directory_engine());
 mw_path=(struct nm_path){(void*)0x1234,mw_dentry};mw_info=(struct nm_inode_info){.r_path=mw_path,.initialized=true};
 ((struct nm_dentry_head*)mw_dentry)->d_inode=(void*)mw_source_inode;nm_set_inode_private(mw_inode,&mw_info);
 *(const void**)(mw_outer+struct_offset.file_cred)=(void*)0x1234;
 kf_nm_dentry_open=mw_source_open;kf_nm_fput=mw_put;mw_open_error=mw_dac_error=0;
 for(unsigned mode=1;mode<=2;mode++){
  ((struct nm_file_flags_mode*)(mw_outer+struct_offset.file_flags))->f_flags=mode;
  unsigned opens_before=mw_opens;
  assert(nm_open((void*)mw_inode,mw_file)==-EROFS&&mw_opens==opens_before&&!nm_file_private(mw_file));
 }
 assert(!nm_prepare_backing_inode_engine());struct_offset.permission_abi=0;kf_nm_inode_permission2=mw_permission;
 assert(((struct nm_file_io_ops*)nm_inode_engine.file_ops)->write_iter==nm_write_iter);
 for(unsigned mode=1;mode<=2;mode++){
  ((struct nm_file_flags_mode*)(mw_outer+struct_offset.file_flags))->f_flags=mode;
  unsigned opens_before=mw_opens;int rc=nm_open((void*)mw_inode,mw_file);
  /* 原来“写打开必EROFS”的表达式，不再是完整引擎的通用不变量。 */
  bool old_readonly_predicate=rc==-EROFS&&mw_opens==opens_before&&!nm_file_private(mw_file);
  assert(!old_readonly_predicate&&rc==0&&mw_opens==opens_before+1&&nm_file_private(mw_file)==mw_backing);
  assert(mw_mask==(mode==1?(0x20|2):(0x20|2|4)));
  assert(!nm_release((void*)mw_inode,mw_file)&&!nm_file_private(mw_file));
 }
 mw_info.flags=NM_FLAG_VIRTUAL_DIR;unsigned opens_before=mw_opens;
 assert(nm_open((void*)mw_inode,mw_file)==-EROFS&&mw_opens==opens_before&&!nm_file_private(mw_file));mw_info.flags=0;
 nm_backing_write_open_permission=NULL;nm_backing_open_permission=NULL;nm_discard_directory_view();
 puts("M1 old readonly predicate: independent engine true; full engine WRONLY/RDWR false; virtual directory still refused PASS");
}
/* 只ia_valid头部交给当前生产回调；其余是拒绝路径的哨兵，不宣称原生iattr布局。 */
struct m2_test_attr {struct nm_iattr_head head;uint64_t sentinel_size;void*sentinel_file;unsigned char tail[48];};
static void m2_check_refusal(void){
 security_fixture_reset();security_target();struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0106755;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,906));
 struct inode*outer=nm_dentry_inode(outer_root);struct nm_inode_info*info=nm_inode_private(outer);assert(outer&&info);
 struct nm_mount_context_head mount={.context.userns=(void*)0x8765};void*saved_mnt=backing_path.mnt;
 backing_path.mnt=&mount;info->r_path.mnt=&mount;
 const unsigned requests[]={ATTR_SIZE,ATTR_SIZE|ATTR_FILE,ATTR_SIZE|ATTR_OPEN|ATTR_MTIME|ATTR_CTIME,
  ATTR_SIZE|ATTR_MODE,ATTR_SIZE|ATTR_UID,ATTR_SIZE|ATTR_MODE|ATTR_KILL_SUID};
 const uint64_t lengths[]={0,7,UINT64_MAX,0x7fffffffffffffffULL};
 for(int shape=0;shape<4;shape++)for(unsigned r=0;r<sizeof(requests)/sizeof(requests[0]);r++)for(unsigned n=0;n<sizeof(lengths)/sizeof(lengths[0]);n++){
  sn_ready(shape,&mount);struct m2_test_attr a;memset(&a,0xA5,sizeof(a));a.head.ia_valid=requests[r];a.sentinel_size=lengths[n];a.sentinel_file=mw_file;sa_attr=&a;
  bool compound=requests[r]&(ATTR_MODE|ATTR_UID);if(!compound)sa_notify_error=-EFBIG;
  unsigned char source_before[768],outer_before[768],attr_before[sizeof(a)];
  memcpy(source_before,backing,768);memcpy(outer_before,outer,768);memcpy(attr_before,&a,sizeof(a));
  assert(sn_call(shape,(void*)outer_root,&a)==(compound?-EOPNOTSUPP:-EFBIG));
  assert(compound?(!sa_locks&&!sa_unlocks&&!sa_ro_calls&&!sa_notify_calls):(sa_locks==1&&sa_unlocks==1&&sa_ro_calls==1&&sa_notify_calls==1));
  assert(!memcmp(source_before,backing,768)&&!memcmp(outer_before,outer,768)&&!memcmp(attr_before,&a,sizeof(a)));
 }
 backing_path.mnt=saved_mnt;info->r_path.mnt=saved_mnt;port_iput(outer);nm_setattr_status=-EOPNOTSUPP;
 assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 puts("M2 admission: 48 pure SIZE native errors + 48 compound pre-lock refusals; inode/iattr bytes unchanged PASS");
}
static void m2_check_native_transform(void){
 struct m2_native_attr a={.ia_valid=ATTR_SIZE|ATTR_KILL_SUID};
 assert(!m2_native_transform(0104755,&a));
 assert((a.ia_valid&(ATTR_SIZE|ATTR_MODE|ATTR_KILL_SUID))==(ATTR_SIZE|ATTR_MODE|ATTR_KILL_SUID));
 assert(m2_native_transform(0104755,&a)==M2_WOULD_BUG);
 a=(struct m2_native_attr){.ia_valid=ATTR_SIZE|ATTR_KILL_SGID};
 assert(!m2_native_transform(0102755,&a));
 assert((a.ia_valid&(ATTR_SIZE|ATTR_MODE|ATTR_KILL_SGID))==(ATTR_SIZE|ATTR_MODE|ATTR_KILL_SGID));
 assert(m2_native_transform(0102755,&a)==M2_WOULD_BUG);
 a=(struct m2_native_attr){.ia_valid=ATTR_SIZE};assert(!m2_native_transform(0100644,&a)&&a.ia_valid==ATTR_SIZE);
 puts("fixed native notify snippet: SUID/SGID first rewrite adds MODE; raw second notify reaches BUG condition; not a kernel panic execution PASS");
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output',type=Path,required=True)
    p.add_argument('--cli-source',type=Path,required=True)
    p.add_argument('--native-attr',type=Path,required=True)
    p.add_argument('--native-fs-header',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    native=a.native_attr.read_text();start=native.index('\tif ((ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID)) &&')
    end=native.index('\tif (!(attr->ia_valid & ~(ATTR_KILL_SUID | ATTR_KILL_SGID)))',start)
    block=native[start:end];assert block.count('BUG();')==1 and block.count('attr->ia_valid |= ATTR_MODE')==2
    flags=[];header=a.native_fs_header.read_text()
    for name in ('MODE','UID','SIZE','FILE','OPEN','MTIME','CTIME','KILL_SUID','KILL_SGID'):
        hit=re.findall(r'^#define ATTR_'+name+r'\b[^\n]*',header,re.M);assert len(hit)==1;flags.extend(hit)
    prefix='\n#include <sys/stat.h>\n'+'\n'.join(flags)+'''
#define M2_WOULD_BUG (-12345)
struct m2_native_attr {unsigned ia_valid,ia_mode;};
static int m2_native_transform(unsigned mode,struct m2_native_attr*attr){
 struct {unsigned i_mode;} object={mode};typeof(object)*inode=&object;unsigned ia_valid=attr->ia_valid;
#define BUG() return M2_WOULD_BUG
'''+block+'\n#undef BUG\nreturn 0;\n}\n'
    rows=[]
    for abi,digest in DIGESTS.items():
        original=(a.oracle_output/abi/'contracts.c').read_text();assert hashlib.sha256(original.encode()).hexdigest()==digest
        before=re.findall(r'\bassert\s*\([^;]+\);',original);assert len(before)==1322
        for file,names in {'nm_file.c':['nm_open','nm_write_iter'],'nm_setattr.c':['nm_setattr_context']}.items():
            for name in names:assert function(original,name)==function((ROOT/'nomount'/file).read_text(),name),name
        entry='int main(void){assert(!previous_m1_main());check_file_writes();check_m1_failure_cleanup();return 0;}'
        assert original.count(entry)==1
        source=original.replace(entry,entry.replace('int main(','static int previous_m2_main('),1)+prefix+TEST
        source+='\nint main(void){assert(!previous_m2_main());m2_check_open_contract();m2_check_refusal();m2_check_native_transform();return 0;}\n'
        after=re.findall(r'\bassert\s*\([^;]+\);',source);assert after[:len(before)]==before
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        rows.append({'abi':abi,'prior_assert_sites':len(before),'added_assert_sites':len(after)-len(before),'total_assert_sites':len(after),'size_refusal_cases':96,'result':'PASS'})
    receipt={'scope':'Developer Tier-3 admission checks + exact bounded Sony native transformation snippet; BUG replaced by return sentinel; no kernel panic execution; no new truncate support',
             'native_source_commit':'7fc8455b2fa84be76364c2457e6503b867ceb12a','native_block_start_line':native[:start].count('\n')+1,'native_block_end_line':native[:end].count('\n'),'host':rows}
    (a.output/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n');print(rows)

if __name__=='__main__':main()
