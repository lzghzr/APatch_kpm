#!/usr/bin/env python3
"""保留int/bool各1433处Oracle，执行生产源锁推导、目标窗口与拒绝反例。"""
import argparse
import json
from pathlib import Path
import re
import struct
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]

PRE = r'''
static unsigned char*il_image;
static size_t il_size;
static bool il_enabled;
static const char*il_missing;
static int il_alias,il_btf_mode;
static unsigned il_queries;
static uintptr_t il_lookup(const char*name);
static int calculate_function_setattr(struct nm_setattr_layout*,int);
'''
TEST = r'''
static unsigned il_bl(uintptr_t from,uintptr_t to){
 intptr_t delta=(intptr_t)to-(intptr_t)from;
 assert(!(delta%4)&&delta>=-(1<<27)&&delta<(1<<27));
 return inst_get_bl_value()|((uint32_t)(delta/4)&0x3ffffffU);
}
static void il_reset(void){
 il_enabled=true;il_missing=NULL;il_alias=0;il_btf_mode=0;il_queries=0;
 memcpy(il_image,il_original,il_size);
 struct_offset.getattr_context_kind=0;struct_offset.permission_abi=0;
}
static void il_calls(int source,int kind){
 unsigned*words=(void*)(il_image+il_sources[source]);
 words[il_lock_at[source]]=il_bl((uintptr_t)&words[il_lock_at[source]],(uintptr_t)(il_image+il_helpers[kind*2]));
 words[il_unlock_at[source]]=il_bl((uintptr_t)&words[il_unlock_at[source]],(uintptr_t)(il_image+il_helpers[kind*2+1]));
}
static void il_offset(int source,unsigned value){
 unsigned*words=(void*)(il_image+il_sources[source]);
 unsigned positions[]={il_lock_at[source]-1,il_unlock_at[source]-1};
 for(unsigned i=0;i<2;i++)words[positions[i]]=(words[positions[i]]&~(4095U<<10))|(value<<10);
}
static int il_derive(void){struct nm_setattr_layout l;return calculate_function_setattr(&l,112);}
static int il_btf(struct nm_setattr_layout*l,bool*unavailable){
 *unavailable=il_btf_mode==0;
 if(il_btf_mode==3){*l=nm_setattr_layout;return 0;}
 return il_btf_mode==1?-EINVAL:-ENODATA;
}
static const char*il_runtime_missing;
static bool il_truncate_notify;
static uintptr_t il_runtime_lookup(const char*n){
 if(il_runtime_missing&&!strcmp(n,il_runtime_missing))return 0;
 if(il_truncate_notify&&!strcmp(n,"notify_change"))return (uintptr_t)tm_notify;
 if(!strcmp(n,"mutex_lock_interruptible"))return (uintptr_t)sa_lock;
 if(!strcmp(n,"mutex_unlock"))return (uintptr_t)sa_unlock;
 return sn_lookup(n);
}
PREPARE
static void check_inode_lock(void){
 il_reset();struct nm_setattr_layout l;
 assert(!calculate_function_setattr(&l,112)&&l.lock_offset==160&&l.lock_kind==1&&l.slot==112&&!l.context);
 uintptr_t helpers[4];for(unsigned i=0;i<4;i++)helpers[i]=(uintptr_t)(il_image+il_helpers[i]);
 for(unsigned i=0;i<3;i++){
  int kind=0;assert(nm_find_inode_lock((void*)(il_image+il_sources[i]),il_windows[i],i==2?1:0,helpers,(uintptr_t)il_image,(uintptr_t)il_image+il_size,&kind)==160&&kind==1);
  il_missing=il_names[i];assert(!il_derive());il_missing=NULL;
 }
 /* 所有来源改用另一合法偏移/锁对，证明数值与锁类型来自目标。 */
 for(unsigned i=0;i<3;i++)il_offset(i,168);
 assert(!calculate_function_setattr(&l,112)&&l.lock_offset==168&&l.lock_kind==1);
 for(unsigned i=0;i<3;i++)il_calls(i,1);
 assert(!calculate_function_setattr(&l,112)&&l.lock_offset==168&&l.lock_kind==2);
 il_reset();il_calls(2,1);assert(il_derive()<0);
 il_reset();il_offset(2,168);assert(il_derive()<0); // 两票不覆盖第三处冲突。
 il_reset();il_alias=1;assert(il_derive()<0);
 il_reset();il_alias=2;assert(il_derive()<0); // 两个来源缺失。
 const char*missing[]={"down_write","up_write","_stext","_etext"};
 for(unsigned i=0;i<4;i++){il_reset();il_missing=missing[i];assert(il_derive()<0);}
 il_reset();struct_offset.getattr_context_kind=1;assert(il_derive()==-EOPNOTSUPP);
 il_reset();struct_offset.permission_abi=2;assert(il_derive()==-EOPNOTSUPP);
 unsigned*set=(void*)(il_image+il_sources[0]);
 /* 变异只作用于私有映射；每轮恢复完整目标原字节。 */
 il_reset();set[34]+=8U<<10;assert(il_derive()<0); // lock/unlock偏移不一致。
 il_reset();set[24]&=~(1U<<31);assert(il_derive()<0); // W0不是锁指针。
 il_reset();set[24]|=1U<<22;assert(il_derive()<0); // 未确认的shift。
 il_reset();il_offset(0,161);assert(il_derive()<0);
 il_reset();set[16]=(set[16]&~(31U<<5))|(1U<<5);assert(il_derive()<0); // inode基址不是dentry。
 il_reset();set[16]=(set[16]&~(31U<<5))|(22U<<5);assert(!il_derive());
 set[13]&=~(1U<<31);assert(il_derive()<0); // W寄存器不能保存dentry。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=0xa940641fU;assert(il_derive()<0); // LDP第二目的不能隐蔽覆盖inode。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=0xc8007c19U;assert(il_derive()<0); // 未支持的原子状态写入。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=0xf800873fU;assert(il_derive()<0); // STR写回x25清来源。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=il_bl((uintptr_t)&set[23],(uintptr_t)(il_image+il_helpers[2]));assert(il_derive()<0);
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=inst_get_b_value()|2U;assert(il_derive()<0); // 绕过ADD直入BL。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=inst_get_b_value()|11U;assert(il_derive()<0); // 绕过lock直入unlock。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=inst_get_b_value()|0x3ffffffU;assert(il_derive()<0); // 回边。
 il_reset();set[18]=inst_get_b_value()|5U;set[23]=0xd503201fU;assert(il_derive()<0); // 未支持指令。
 il_reset();set[35]=il_bl((uintptr_t)&set[35],(uintptr_t)(il_image+il_helpers[3]));assert(il_derive()<0);
 il_reset();set[25]=il_bl((uintptr_t)&set[25],(uintptr_t)(il_image+il_helpers[3]));assert(il_derive()<0); // unlock先于lock。
 il_reset();set[16]&=~(1U<<30);assert(il_derive()<0); // 32位load不能建立inode来源。
 /* 合流有一条路径破坏来源：交集不得仍保留inode。 */
 il_reset();set[18]=inst_get_b_value()|4U;set[22]=inst_get_cbz_value()|(2U<<5);set[23]=0xaa0103f9U;assert(il_derive()<0);
 il_reset();unsigned*tr=(void*)(il_image+il_sources[2]);tr[32]=il_bl((uintptr_t)&tr[32],(uintptr_t)(il_image+il_helpers[2]));assert(il_derive()<0);
 il_reset();tr[40]=il_bl((uintptr_t)&tr[40],(uintptr_t)&tr[38]+inst_get_bl_label(tr[38]));assert(il_derive()<0); // 普通BL切断x8来源。
 il_reset();int kind=0;
 assert(nm_find_inode_lock(set,35,0,helpers,(uintptr_t)il_image,(uintptr_t)il_image+il_size,&kind)<0);
 assert(nm_find_inode_lock(set,44,0,helpers,(uintptr_t)il_image,(uintptr_t)il_image+il_size,&kind)==-EINVAL);
 assert(nm_find_inode_lock(set,0,0,helpers,(uintptr_t)il_image,(uintptr_t)il_image+il_size,&kind)==-EINVAL);
 uintptr_t lo=(uintptr_t)il_image,hi=lo+il_size;
 assert(!nm_inode_lock_body(lo+1,lo,hi));assert(!nm_inode_lock_body(hi-4,lo,hi));
 /* CFI/BTI只跟随一跳，且必须在核心代码范围。 */
 unsigned*stub=(void*)(il_image+il_stub);stub[0]=inst_get_bti_c_value();stub[1]=il_bl((uintptr_t)&stub[1],lo+il_helpers[0])&~(1U<<31);
 assert(nm_inode_lock_body((uintptr_t)stub,lo,hi)==lo+il_helpers[0]);
 stub[1]=inst_get_b_value()|0x3ffffffU;assert(!nm_inode_lock_body((uintptr_t)stub,lo,hi));
 /* 最后一个字恰在保护页前，扫描不得触及下一页。 */
 size_t page=sysconf(_SC_PAGESIZE);void*guard=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(guard!=MAP_FAILED);
 assert(!mprotect((char*)guard+page,page,PROT_NONE));
 for(unsigned n=28;n<=43;n++){
  unsigned*edge=(void*)((char*)guard+page-n*4);
  for(unsigned j=0;j<n;j++)edge[j]=0x5280001fU;
  assert(nm_find_inode_lock(edge,n,0,helpers,lo,hi,&kind)==-ENOENT);
 }
 assert(!munmap(guard,page*2));
 /* BTF有效错误、ENODATA但非unavailable均不进入新fallback。 */
 il_reset();sa_ready(0);il_btf_mode=1;assert(il_prepare()==-EINVAL&&!il_queries&&nm_setattr_status==-EOPNOTSUPP);
 il_btf_mode=2;assert(il_prepare()==-ENODATA&&!il_queries&&nm_setattr_status==-EOPNOTSUPP);
 il_btf_mode=3;assert(!il_prepare()&&!il_queries&&!nm_setattr_status);
 il_reset();sa_ready(0);assert(!il_prepare()&&!nm_setattr_status&&nm_setattr_layout.lock_offset==160&&nm_setattr_layout.lock_kind==1);
 assert(nm_setattr_lock==sa_lock&&nm_setattr_unlock==sa_unlock&&nm_notify_plain==sa_notify);
 il_reset();sa_ready(0);struct_offset.permission_abi=0;struct_offset.iop_getattr=128;
 assert(!il_prepare()&&!nm_setattr_status&&nm_setattr_layout.slot==112&&nm_notify_context==sa_notify_mapped);
 il_reset();sa_ready(0);il_offset(2,168);assert(!il_prepare()&&nm_setattr_status==-EOPNOTSUPP);
 il_reset();sa_ready(0);il_runtime_missing="down_write_killable";assert(!il_prepare()&&nm_setattr_status==-ENOENT);il_runtime_missing=NULL;
 il_reset();sa_ready(0);for(unsigned i=0;i<3;i++)il_calls(i,1);
 assert(!il_prepare()&&!nm_setattr_status&&nm_setattr_layout.lock_kind==2&&nm_setattr_lock==sa_lock&&nm_setattr_unlock==sa_unlock);
 /* 用非BTF准备结果执行实际生产setter，源notify由宿主ftruncate承担。 */
 security_fixture_reset();security_target();struct nomount_rule rule={.r_path=backing_path,.refs=1};
 ((struct nm_inode_owner_prefix*)backing)->i_mode=0100644;security_set_sid(backing,71);
 security_query(outer_root);assert(!nm_materialize_file(parent,(void*)outer_root,&rule,909));
 struct inode*outer=nm_dentry_inode(outer_root);assert(outer&&nm_inode_private(outer));
 char file[]="/tmp/nomount-lock-XXXXXX";tm_fd=mkstemp(file);assert(tm_fd>=0);
 il_reset();sa_ready(0);assert(!il_prepare()&&!nm_setattr_status);
 struct nm_iattr_head mode={1};sa_attr=&mode;
 assert(!nm_setattr((void*)outer_root,&mode)&&sa_locks==1&&sa_unlocks==1&&nm_inode_mode(outer)==0100600);
 il_reset();sa_ready(0);il_truncate_notify=true;assert(!il_prepare()&&!nm_setattr_status);
 tm_seed(outer,"abcdefghij");tm_outer_ro=false;tm_error=tm_after_error=0;
 assert(!tm_path_truncate(0,3)&&nm_inode_size(outer)==3&&nm_inode_size(backing)==3&&sa_locks==1&&sa_unlocks==1);
 mw_contents(tm_fd,"abc");unsigned locks=sa_locks;struct tm_attr compound={{1U|8U},0,NULL};
 assert(tm_set(0,&compound)==-EOPNOTSUPP&&sa_locks==locks);mw_contents(tm_fd,"abc");
 assert(!close(tm_fd)&&!unlink(file));port_iput(outer);assert(!q_count&&!rcu_depth&&!spin_depth&&!hash_depth);
 il_truncate_notify=false;il_enabled=false;nm_setattr_status=-EOPNOTSUPP;
 puts("source inode lock: 3 target prefixes agree offset=160/rw_semaphore; synthetic mutex/168, conflicts/provenance/CFG/bounds/BTF dispatch PASS");
}
'''


def assertions(text):
    return re.findall(r'\bassert\s*\([^;]+\);', text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'cli-source', 'evidence', 'symbols', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    symbols = {n: at for at, _, n in json.loads(a.symbols.read_text())}
    names = ['vfs_setxattr', 'vfs_removexattr', 'do_truncate2']
    windows = [json.loads((a.evidence / (n + '.json')).read_text()) for n in names]
    image = (a.evidence / 'Image').read_bytes()
    for name, window, count in zip(names, windows, (36, 28, 43)):
        assert symbols[name] == window['offset'] and len(window['words']) == count
        assert image[window['offset']:window['offset'] + count * 4] == struct.pack('<' + 'I' * count, *window['words'])
    helper_names = ['down_write', 'up_write', 'mutex_lock', 'mutex_unlock']
    selected = {n: symbols[n] for n in names + helper_names + ['_stext', '_etext']}
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    block = offsets.split('// 源锁锚点：', 1)[1].split('\n#endif', 1)[0]
    block = '// 源锁锚点：' + block
    block = block.replace('kallsyms_lookup_name_by_suffix(', 'il_lookup(').replace('kallsyms_lookup_name(', 'il_lookup(')
    setter = function((ROOT / 'nomount/nm_setattr.c').read_text(), 'nm_prepare_setattr')
    pre = PRE + '#define nm_log_info(...) do { if(il_enabled)fprintf(stderr,__VA_ARGS__); } while(0)\n' + block
    data = 'static const unsigned il_sources[]={' + ','.join(str(w['offset']) for w in windows) + '};\n'
    data += 'static const unsigned il_windows[]={36,28,43},il_lock_at[]={25,20,33},il_unlock_at[]={35,27,42};\n'
    data += 'static const unsigned il_helpers[]={' + ','.join(str(symbols[n]) for n in helper_names) + '};\n'
    data += 'static const char*il_names[]={"vfs_setxattr","vfs_removexattr","do_truncate2"};\n'
    data += 'static const unsigned il_stub=4096;static unsigned char*il_original;\n'
    lookup = 'static uintptr_t il_lookup(const char*name){il_queries++;if(!il_enabled||(il_missing&&!strcmp(il_missing,name)))return 0;\n'
    lookup += 'if(il_alias==1&&!strcmp(name,"vfs_removexattr"))return (uintptr_t)(il_image+il_sources[0]);\n'
    lookup += 'if(il_alias==2&&(!strcmp(name,"vfs_removexattr")||!strcmp(name,"do_truncate2")))return 0;\n'
    lookup += ''.join(f'if(!strcmp(name,"{n}"))return (uintptr_t)(il_image+{at}U);\n' for n, at in selected.items())
    lookup += 'return 0;}\n'
    prepare = setter.replace('nm_prepare_setattr(', 'il_prepare(', 1).replace('calculate_btf_setattr(', 'il_btf(').replace('kallsyms_lookup_name_by_suffix(', 'il_runtime_lookup(')
    added = data + lookup + TEST.replace('PREPARE', '\n#undef CONFIG_KPM_BASELINES\n' + prepare + '\n#define CONFIG_KPM_BASELINES 1\n')
    rows = []
    for abi in ('int', 'bool'):
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = assertions(original)
        assert len(before) == 1433
        # 生产准备函数及其两种宿主命名副本一起更新，原断言表达式与顺序不变。
        source = original.replace(function(original, 'nm_prepare_setattr'), pre + '\n' + setter, 1)
        for name, btf, lookup_name in [('sn_prepare_dynamic', 'sn_btf', 'sn_lookup'), ('cold_nm_prepare_setattr', 'cold_setattr_btf', 'cold_lookup')]:
            replacement = setter.replace('nm_prepare_setattr(', name + '(', 1).replace('calculate_btf_setattr(', btf + '(').replace('kallsyms_lookup_name_by_suffix(', lookup_name + '(')
            if name.startswith('cold_'):
                replacement = replacement.replace('nm_prepare_permission_abi(', 'cold_nm_prepare_permission_abi(')
                at = replacement.index('{') + 1
                replacement = replacement[:at] + '\n  cold_note("nm_prepare_setattr");' + replacement[at:]
            source = source.replace(function(source, name), replacement, 1)
        assert assertions(source) == before
        entry = 'int main(void){assert(!previous_truncate_main());check_truncate();return 0;}'
        assert source.count(entry) == 1
        source = source.replace(entry, entry.replace('int main(', 'static int previous_inode_lock_main('), 1)
        source += added + r'''
int main(int argc,char**argv){
 assert(!previous_inode_lock_main());assert(argc==2);
 FILE*f=fopen(argv[1],"rb");assert(f);assert(!fseek(f,0,SEEK_END));il_size=ftell(f);rewind(f);
 il_original=malloc(il_size);il_image=mmap(NULL,il_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(il_original&&il_image!=MAP_FAILED);assert(fread(il_original,1,il_size,f)==il_size);assert(!fclose(f));
 check_inode_lock();assert(!munmap(il_image,il_size));free(il_original);return 0;
}
'''
        assert assertions(source)[:1433] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'), str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str((a.evidence / 'Image').resolve())], out / 'run.log')
        rows.append({'abi': abi, 'prior_assert_sites': 1433, 'unchanged_assert_sites': 1433, 'added_assert_sites': len(assertions(source)) - 1433, 'total_assert_sites': len(assertions(source)), 'result': 'PASS'})
    receipt = {'scope': 'Developer target machine-code prefixes and ASan/UBSan host; not target execution/concurrency proof', 'source_windows': {n: len(w['words']) for n, w in zip(names, windows)}, 'host': rows}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
