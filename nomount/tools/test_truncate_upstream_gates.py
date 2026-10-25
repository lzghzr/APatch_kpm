#!/usr/bin/env python3
"""保留1362处断言，补上S_NOSEC/CAP门控与冻结上游setter的二次notify轨迹。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from test_directory_abis import function
from test_file_control import run
from test_truncate_native_entries import extract

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = 'bf1847f98fed382369c43bfd652cd93774b9b8e3'
TEST = r'''
static void check_upstream_truncate_gates(void){
 /* 新虚拟inode的S_NOSEC使实际入口不产生KILL；旧片段反例没有这层门控。 */
 kx_reset(04777);kx_cap_fsetid=false;
 assert(kx_needs(&kx_outer_dentry)==0);
 assert(!kx_truncate(NULL,&kx_outer_dentry,0,0,NULL)&&!kx_bugs&&kx_outer.size==0&&kx_source.size==0);
 assert(!(kx_last_source_flags&(KX_ATTR_MODE|KX_ATTR_KILL_SUID|KX_ATTR_KILL_SGID)));
 /* CAP_FSETID是第二个独立门；不依赖S_NOSEC也可不生成KILL。 */
 kx_reset(04777);kx_outer.i_flags&=~KX_S_NOSEC;kx_cap_fsetid=true;
 assert(kx_needs(&kx_outer_dentry)==0);
 assert(!kx_truncate(NULL,&kx_outer_dentry,0,0,NULL)&&!kx_bugs);
 /* 使用原生MODE片段与冻结上游nm_setattr执行chmod，观察两侧NOSEC被清掉。 */
 for(unsigned mode_index=0;mode_index<2;mode_index++){
  unsigned mode=mode_index?02777:04777;kx_reset(0644);kx_cap_fsetid=false;
  struct kx_iattr chmod_attr={.ia_valid=KX_ATTR_MODE,.ia_mode=0100000U|mode};
  kx_inode_lock(&kx_outer);int rc=kx_notify2(NULL,&kx_outer_dentry,&chmod_attr,NULL);kx_inode_unlock(&kx_outer);
  assert(!rc&&kx_outer.i_mode==(0100000U|mode)&&kx_source.i_mode==(0100000U|mode));
  assert(!(kx_outer.i_flags&KX_S_NOSEC)&&!(kx_source.i_flags&KX_S_NOSEC));
  unsigned expected=mode_index?KX_ATTR_KILL_SGID:KX_ATTR_KILL_SUID;
  assert(kx_needs(&kx_outer_dentry)==(int)expected);
  unsigned source_calls=kx_source_calls;
  assert(kx_truncate(NULL,&kx_outer_dentry,0,KX_ATTR_MTIME|KX_ATTR_CTIME,&kx_outer_file)==KX_WOULD_BUG);
  assert(kx_bugs==1&&kx_source_calls==source_calls+1&&kx_source.size==32&&kx_outer.size==32);
  assert((kx_last_source_flags&(KX_ATTR_MODE|expected))==(KX_ATTR_MODE|expected));
  assert(!kx_outer.locked&&!kx_source.locked);
 }
 /* 提案中的MODE|SIZE前置拒绝能拦下派生MODE；它不是清KILL位的伪修复。 */
 kx_reset(04777);kx_outer.i_flags&=~KX_S_NOSEC;kx_guard_compound=true;
 assert(kx_truncate(NULL,&kx_outer_dentry,0,0,NULL)==-EOPNOTSUPP);
 assert(!kx_source_calls&&!kx_bugs&&!kx_outer.locked&&!kx_source.locked&&kx_source.size==32);
 puts("upstream gates PASS: initial S_NOSEC / CAP_FSETID avoid KILL; chmod then unprivileged truncate reaches two-notify BUG condition; compound guard stops source call (no kernel panic execution)");
}
'''


def native_probe(args):
    header = args.native_header.read_text()
    attr = args.native_attr.read_text()
    inode = args.native_inode.read_text()
    opening = args.native_open.read_text()
    upstream = subprocess.check_output(['git', '-C', str(ROOT/'nomount/upstream/nomount'), 'show', UPSTREAM+':kernel/src/nomount.c'], text=True)
    setter = function(upstream, 'nm_setattr')
    bodies = [extract(inode, name)[0] for name in ('should_remove_suid', 'dentry_needs_remove_privs')]
    bodies.append(extract(opening, 'do_truncate2')[0])
    start = attr.index('\tif ((ia_valid & ATTR_MODE)) {')
    end = attr.index('\n\tnow = current_time(inode);', start)
    mode_block = attr[start:end]
    start = attr.index('\tif ((ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID)) &&')
    end = attr.index('\tif (!(attr->ia_valid & ~(ATTR_KILL_SUID | ATTR_KILL_SGID)))', start)
    kill_block = attr[start:end]
    sxid = function(header, 'is_sxid')
    initial = re.search(r'^\s*inode->i_flags \|= S_PRIVATE \| S_NOATIME \| S_NOCMTIME \| S_NOSEC;', upstream, re.M).group(0).strip()
    module_init = function((ROOT/'nomount/nm_offsets.c').read_text(), 'nm_copy_backing_inode_attributes')
    nosec = int(re.search(r'^#define S_NOSEC\s+(\d+)', header, re.M).group(1))
    flags_expr = re.search(r'owner->i_flags \|= ([^;]+);', module_init).group(1)
    assert nosec in [int(n) for n in re.findall(r'(\d+)U', flags_expr)]
    names = {'inode':'kx_inode', 'dentry':'kx_dentry', 'iattr':'kx_iattr', 'file':'kx_file', 'vfsmount':'kx_mount',
             'nm_inode_info':'kx_info', 'd_inode':'kx_d_inode', 'd_backing_inode':'kx_d_inode',
             'dentry_needs_remove_privs':'kx_needs', 'should_remove_suid':'kx_should', 'do_truncate2':'kx_truncate',
             'nm_setattr':'kx_upstream_setattr', 'notify_change2':'kx_notify2', 'notify_change':'kx_notify_source',
             'inode_lock':'kx_inode_lock', 'inode_unlock':'kx_inode_unlock', 'i_size_read':'kx_size_read', 'i_size_write':'kx_size_write',
             'nm_sync_inode_times':'kx_sync_times', 'security_inode_need_killpriv':'kx_need_priv', 'IS_NOSEC':'KX_IS_NOSEC',
             'is_sxid':'kx_is_sxid', 'BUG':'KX_BUG', 'capable':'kx_capable', 'likely':'kx_likely', 'unlikely':'kx_likely',
             'umode_t':'unsigned short', 'loff_t':'int64_t', 'IDMAP_ARG':'', 'IDMAP_CALL':''}
    for name in re.findall(r'^#define\s+(ATTR_\w+|S_NOSEC|S_PRIVATE|S_NOATIME|S_NOCMTIME)\b', header, re.M):
        names[name] = 'KX_'+name
    tags = {n:names.pop(n) for n in ('inode','dentry','iattr','file','vfsmount','nm_inode_info')}
    def rename(text):
        text = re.sub(r'\bstruct (inode|dentry|iattr|file|vfsmount|nm_inode_info)\b', lambda m:'struct '+tags[m.group(1)], text)
        return re.sub(r'(?<![.>])\b[A-Za-z_]\w*\b', lambda m:names.get(m.group(),m.group()), text)
    definitions = '\n'.join(rename(line) for line in header.splitlines() if re.match(r'^#define\s+(ATTR_\w+|S_NOSEC|S_PRIVATE|S_NOATIME|S_NOCMTIME)\b', line))
    prefix = r'''
struct kx_inode {unsigned i_mode,i_flags,i_uid,i_gid;int64_t size;void*i_private;bool locked;};
struct kx_dentry {struct kx_inode*d_inode;};
struct kx_mount {int unused;};
struct kx_file {int unused;};
struct kx_iattr {unsigned ia_valid,ia_mode;int64_t ia_size;struct kx_file*ia_file;};
struct kx_info {struct {struct kx_mount*mnt;struct kx_dentry*dentry;}r_path;};
static struct kx_inode kx_outer,kx_source;
static struct kx_dentry kx_outer_dentry={&kx_outer},kx_source_dentry={&kx_source};
static struct kx_info kx_binding;
static struct kx_file kx_outer_file;
static bool kx_cap_fsetid,kx_guard_compound;
static unsigned kx_bugs,kx_source_calls,kx_last_source_flags;
#define KX_WOULD_BUG (-12345)
#define KX_BUG() do{kx_bugs++;return KX_WOULD_BUG;}while(0)
#define kx_likely(x) (x)
#define kx_capable(...) (kx_cap_fsetid)
#define KX_IS_NOSEC(i) ((i)->i_flags&KX_S_NOSEC)
static struct kx_inode*kx_d_inode(struct kx_dentry*d){return d->d_inode;}
static int kx_need_priv(struct kx_dentry*d){(void)d;return 0;}
static int64_t kx_size_read(struct kx_inode*i){return i->size;}
static void kx_size_write(struct kx_inode*i,int64_t n){i->size=n;}
static void kx_sync_times(struct kx_inode*i,struct kx_inode*s){(void)i;(void)s;}
static void kx_inode_lock(struct kx_inode*i){assert(!i->locked);i->locked=true;}
static void kx_inode_unlock(struct kx_inode*i){assert(i->locked);i->locked=false;}
static int kx_notify2(struct kx_mount*,struct kx_dentry*,struct kx_iattr*,struct kx_inode**);
static int kx_notify_source(struct kx_dentry*d,struct kx_iattr*a,struct kx_inode**delegated){return kx_notify2(NULL,d,a,delegated);}
'''
    notify = r'''
static int kx_notify2(struct kx_mount*m,struct kx_dentry*dentry,struct kx_iattr*attr,struct kx_inode**delegated){
 (void)m;(void)delegated;struct kx_inode*inode=dentry->d_inode;unsigned mode=inode->i_mode,ia_valid=attr->ia_valid;
 if(dentry==&kx_source_dentry){kx_source_calls++;kx_last_source_flags=ia_valid;}
''' + rename(mode_block) + '\n' + rename(kill_block) + r'''
 if(dentry==&kx_outer_dentry){
  if(kx_guard_compound&&(attr->ia_valid&(KX_ATTR_MODE|KX_ATTR_SIZE))==(KX_ATTR_MODE|KX_ATTR_SIZE))return -EOPNOTSUPP;
  return kx_upstream_setattr(dentry,attr);
 }
 if(attr->ia_valid&KX_ATTR_SIZE)inode->size=attr->ia_size;
 if(attr->ia_valid&KX_ATTR_MODE)inode->i_mode=attr->ia_mode;
 return 0;
}
static void kx_reset(unsigned mode){
 kx_source=(struct kx_inode){.i_mode=0100000U|mode,.size=32};
 kx_binding=(struct kx_info){.r_path={NULL,&kx_source_dentry}};
 kx_outer=(struct kx_inode){.i_mode=0100000U|mode,.size=32,.i_private=&kx_binding};
 struct kx_inode*inode=&kx_outer;
''' + rename(initial) + r'''
 kx_cap_fsetid=kx_guard_compound=false;kx_bugs=kx_source_calls=kx_last_source_flags=0;
}
'''
    # 同时记录open调用边界；没有把宿主open(O_TRUNC)冒充内核dentry_open。
    dentry_open, dentry_span = extract_file_function(opening, 'dentry_open')
    vfs_open, vfs_span = extract(opening, 'vfs_open')
    do_open, do_span = extract(opening, 'do_dentry_open')
    assert 'vfs_open(path, f)' in dentry_open and 'do_dentry_open(' in vfs_open
    assert 'f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);' in do_open
    assert 'handle_truncate(' not in dentry_open+vfs_open+do_open
    return definitions+'\n'+prefix+rename(sxid)+'\n'+rename(setter)+'\n'+notify+'\n'+'\n'.join(rename(b) for b in bodies), {
        'upstream_commit':UPSTREAM, 'native_gate_functions':['should_remove_suid','dentry_needs_remove_privs','do_truncate2'],
        'bounded_notify_parts':['ATTR_MODE is_sxid clears S_NOSEC','MODE/KILL conflict and KILL transformation'],
        'dentry_open_call_graph':{'dentry_open':dentry_span,'vfs_open':vfs_span,'do_dentry_open':do_span,'findings':['dentry_open -> vfs_open -> do_dentry_open','do_dentry_open clears O_TRUNC','these three functions do not call handle_truncate']}}


def extract_file_function(source,name):
    m=re.search(r'(?m)^struct file \*'+name+r'\([^;]+?\)\s*\{',source)
    assert m,name
    end,depth=m.end(),1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[m.start():end],[source[:m.start()].count('\n')+1,source[:end].count('\n')+1]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output','cli-source','native-header','native-inode','native-attr','native-open','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    probe,evidence=native_probe(a);rows=[]
    for abi in ('int','bool'):
        original=(a.oracle_output/abi/'contracts.c').read_text();before=re.findall(r'\bassert\s*\([^;]+\);',original);assert len(before)==1362
        for file,names in {'nm_file.c':['nm_open','nm_write_iter'],'nm_setattr.c':['nm_setattr_context']}.items():
            for name in names:assert function(original,name)==function((ROOT/'nomount'/file).read_text(),name),name
        entry='int main(void){assert(!previous_edges_main());check_m1_edges();return 0;}'
        assert original.count(entry)==1
        source=original.replace(entry,entry.replace('int main(','static int previous_gates_main('),1)+probe+'\n'+TEST
        source+='\nint main(void){assert(!previous_gates_main());check_upstream_truncate_gates();return 0;}\n'
        after=re.findall(r'\bassert\s*\([^;]+\);',source);assert after[:len(before)]==before
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-pthread','-fno-builtin','-I',str(ROOT/'nomount'),'-fsanitize=address,undefined',str(out/'contracts.c'),str(a.cli_source),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        rows.append({'abi':abi,'prior_assert_sites':len(before),'added_assert_sites':len(after)-len(before),'total_assert_sites':len(after),'result':'PASS'})
    receipt={'scope':'Developer Tier-3 exact named gates + bounded notify parts + frozen upstream setter with host type/FS/security stubs; BUG replaced by sentinel; no device panic or full syscall/LSM result','evidence':evidence,'host':rows}
    (a.output/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n');print(rows)


if __name__=='__main__':main()
