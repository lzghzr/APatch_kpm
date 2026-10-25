#!/usr/bin/env python3
"""保留1505条Oracle，回放设备真实内核的源锁窗口并验证新增尾字边界。"""
import argparse
import json
from pathlib import Path
import struct

from test_directory_abis import function
from test_file_control import run
from test_inode_lock import assertions

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('vfs_setxattr', 'vfs_removexattr', 'do_truncate2')
HELPERS = ('down_write', 'up_write', 'mutex_lock', 'mutex_unlock')
TEST = r'''
static int dl_find(unsigned source,unsigned count,int*kind){
 uintptr_t helpers[4];for(unsigned i=0;i<4;i++)helpers[i]=(uintptr_t)(dl_image+dl_helpers[i]);
 return nm_find_inode_lock((void*)(dl_image+dl_sources[source]),count,source==2?1:0,
                           helpers,(uintptr_t)(dl_image+dl_start),(uintptr_t)(dl_image+dl_end),kind);
}
static void dl_reset(void){
 memcpy(dl_image,dl_original,dl_size);dl_enabled=true;dl_missing=NULL;dl_alias=false;
 struct_offset.getattr_context_kind=0;struct_offset.permission_abi=0;
}
static int dl_derive(void){struct nm_setattr_layout l;return calculate_function_setattr(&l,112);}
static void check_device_lock(void){
 dl_reset();int kind=0;struct nm_setattr_layout l;
 /* 相同生产追踪器：旧28条缺解锁BL，新29条完整。 */
 assert(dl_find(0,36,&kind)==160&&kind==1);
 kind=0;assert(dl_find(1,28,&kind)==-ENOENT&&kind==0);
 assert(dl_find(1,29,&kind)==160&&kind==1);
 kind=0;assert(dl_find(2,43,&kind)==160&&kind==1);
 uintptr_t trhelpers[4];for(unsigned i=0;i<4;i++)trhelpers[i]=(uintptr_t)(dl_image+dl_helpers[i]);
 kind=0;assert(nm_find_inode_lock((void*)(dl_image+dl_truncate),41,0,trhelpers,(uintptr_t)(dl_image+dl_start),(uintptr_t)(dl_image+dl_end),&kind)==160&&kind==1);
 assert(!calculate_function_setattr(&l,112)&&l.lock_offset==160&&l.lock_kind==1&&l.slot==112&&!l.context);
 for(unsigned i=0;i<3;i++){dl_missing=dl_names[i];assert(!dl_derive());dl_missing=NULL;}
 /* 两个xattr来源本身足够；同函数体别名不能充数。 */
 dl_missing="do_truncate2";assert(!dl_derive());dl_missing=NULL;
 dl_alias=true;assert(dl_derive()==-EINVAL);dl_alias=false;
 dl_missing="xattrs";assert(dl_derive()==-ENOENT);dl_missing=NULL;
 unsigned*r=(void*)(dl_image+dl_sources[1]);
 assert(inst_is_add_imm(r[27])&&inst_get_add_imm_rn(r[27])==23&&inst_get_add_imm_imm(r[27])==160);
 assert(inst_is_bl(r[28]));
 /* 把入口前向边接到条件分支，来源仍完整，fallthrough可接受。 */
 r[14]=inst_get_b_value()|5U;assert(!dl_derive());dl_reset();
 /* 该BL及其ADD均是必要证据，末字不是任意可接受的调用。 */
 r[28]=il_bl((uintptr_t)&r[28],(uintptr_t)(dl_image+dl_helpers[0]));assert(dl_derive()<0);
 dl_reset();r[28]=il_bl((uintptr_t)&r[28],(uintptr_t)(dl_image+dl_helpers[3]));assert(dl_derive()<0);
 dl_reset();r[28]=r[26];assert(dl_derive()<0); // 没有解锁调用。
 dl_reset();r[28]=0;assert(dl_derive()==-EOPNOTSUPP); // 未知指令。
 dl_reset();r[28]=inst_get_b_value()|0x3ffffffU;assert(dl_derive()==-EOPNOTSUPP); // 回边。
 dl_reset();r[14]=inst_get_b_value()|14U;assert(dl_derive()<0); // 直入解锁BL，绕过定义和锁。
 dl_reset();r[26]=(r[26]&~31U)|23U;assert(dl_derive()<0); // 中间调用返回值覆盖源inode。
 dl_reset();r[27]=il_bl((uintptr_t)&r[27],(uintptr_t)&r[25]+inst_get_bl_label(r[25]));assert(dl_derive()<0);
 dl_reset();r[27]&=~(1U<<31);assert(dl_derive()<0); // W0截断。
 dl_reset();r[27]+=8U<<10;assert(dl_derive()==-EINVAL); // 同函数偏移冲突。
 dl_reset();r[20]+=8U<<10;r[27]+=8U<<10;assert(dl_derive()==-EINVAL); // 第三来源冲突不投票。
 /* 明确来自dentry的callee-saved基址可跨普通BL；更换寄存器不改变结论。 */
 dl_reset();r[12]=(r[12]&~31U)|26U;
 r[20]=(r[20]&~(31U<<5))|(26U<<5);r[27]=(r[27]&~(31U<<5))|(26U<<5);
 assert(!dl_derive());
 /* 同样改为caller-saved x8，普通BL必须清掉来源。 */
 dl_reset();r[12]=(r[12]&~31U)|8U;
 r[20]=(r[20]&~(31U<<5))|(8U<<5);r[27]=(r[27]&~(31U<<5))|(8U<<5);
 assert(dl_derive()<0);
 dl_reset();struct_offset.getattr_context_kind=1;assert(dl_derive()==-EOPNOTSUPP);
 dl_reset();struct_offset.permission_abi=2;assert(dl_derive()==-EOPNOTSUPP);
 /* 真实29条前缀末字紧贴保护页；28条截短对照也不越读。 */
 dl_reset();size_t page=sysconf(_SC_PAGESIZE);void*g=dl_image+dl_map_size-page*2;
 assert(!((uintptr_t)g%page));assert(!mprotect((char*)g+page,page,PROT_NONE));
 uintptr_t helpers[4];for(unsigned i=0;i<4;i++)helpers[i]=(uintptr_t)(dl_image+dl_helpers[i]);
 for(unsigned n=28;n<=29;n++){
  unsigned*edge=(void*)((char*)g+page-n*4);memcpy(edge,r,n*4);
  for(unsigned i=0;i<n;i++)if(inst_is_bl(r[i]))edge[i]=il_bl((uintptr_t)&edge[i],(uintptr_t)&r[i]+inst_get_bl_label(r[i]));
  kind=0;int rc=nm_find_inode_lock(edge,n,0,helpers,(uintptr_t)(dl_image+dl_start),(uintptr_t)(dl_image+dl_end),&kind);
  assert(n==28?(rc==-ENOENT&&kind==0):(rc==160&&kind==1));
 }
 assert(!mprotect((char*)g+page,page,PROT_READ|PROT_WRITE));
 dl_enabled=false;
 puts("device inode lock: 36/29/43 prefixes agree 160/rw_semaphore; 28-word truncation and new-tail rejection fixtures PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'reference-image', 'cli-source', 'image', 'symbols', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    symbols = {n: at for at, _, n in json.loads(a.symbols.read_text())}
    selected = {n: symbols[n] for n in NAMES + HELPERS + ('_stext', '_etext')}
    image = a.image.read_bytes()
    assert all(0 <= at < len(image) for at in selected.values())
    # 输入为本轮明确选定的设备Image；调用点也必须来自其实际字节。
    call_positions = ((25, 35), (21, 28), (33, 42))
    for name, positions in zip(NAMES, call_positions):
        words = struct.unpack_from('<' + 'I' * (max(positions) + 1), image, symbols[name])
        for i, helper in zip(positions, HELPERS[:2]):
            word = words[i]
            assert word >> 26 == 0x25
            delta = (word & 0x3ffffff) * 4
            if delta & (1 << 27):
                delta -= 1 << 28
            assert symbols[name] + i * 4 + delta == symbols[helper]
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    block = '// 源锁锚点：' + offsets.split('// 源锁锚点：', 1)[1].split('\n#endif', 1)[0]
    block = block.replace('kallsyms_lookup_name_by_suffix(', 'il_lookup(').replace('kallsyms_lookup_name(', 'il_lookup(')
    data = r'''
static bool dl_enabled,dl_alias;
static const char*dl_missing;
static unsigned char*dl_image,*dl_original;
static size_t dl_size,dl_map_size;
static uintptr_t dl_lookup(const char*);
'''
    data += 'static const unsigned dl_sources[]={' + ','.join(str(symbols[n]) for n in NAMES) + '};\n'
    data += 'static const unsigned dl_helpers[]={' + ','.join(str(symbols[n]) for n in HELPERS) + '};\n'
    data += f'static const unsigned dl_truncate={symbols["do_truncate"]};\n'
    data += f'static const unsigned dl_start={symbols["_stext"]},dl_end={symbols["_etext"]};\n'
    data += 'static const char*dl_names[]={"vfs_setxattr","vfs_removexattr","do_truncate2"};\n'
    lookup = r'''
static uintptr_t dl_lookup(const char*n){
 if(dl_missing&&(!strcmp(n,dl_missing)||(!strcmp(dl_missing,"xattrs")&&(!strcmp(n,"vfs_setxattr")||!strcmp(n,"vfs_removexattr")))))return 0;
 if(dl_alias&&!strcmp(n,"vfs_removexattr"))return (uintptr_t)(dl_image+dl_sources[0]);
'''
    lookup += ''.join(f'if(!strcmp(n,"{n}"))return (uintptr_t)(dl_image+{at}U);\n' for n, at in selected.items())
    lookup += 'return 0;}\n'
    rows = []
    for abi in ('int', 'bool'):
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = assertions(original)
        assert len(before) == 1505
        start = original.index('// 源锁锚点：')
        old_block = original[start:original.index(function(original, 'calculate_function_setattr'), start)] + function(original, 'calculate_function_setattr')
        source = original.replace(old_block, data + block, 1)
        entry = 'static uintptr_t il_lookup(const char*name){'
        assert source.count(entry) == 1
        source = source.replace(entry, entry + 'if(dl_enabled)return dl_lookup(name);', 1)
        source = source.replace('int main(int argc,char**argv)', 'static int previous_device_main(int argc,char**argv)', 1)
        assert assertions(source) == before
        source += lookup + TEST + r'''
int main(int argc,char**argv){
 assert(argc==3);assert(!previous_device_main(2,argv));
 FILE*f=fopen(argv[2],"rb");assert(f);assert(!fseek(f,0,SEEK_END));dl_size=ftell(f);rewind(f);
 size_t page=sysconf(_SC_PAGESIZE);dl_map_size=(dl_size+page-1)/page*page+2*page;
 dl_original=malloc(dl_size);dl_image=mmap(NULL,dl_map_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(dl_original&&dl_image!=MAP_FAILED);assert(fread(dl_original,1,dl_size,f)==dl_size);assert(!fclose(f));
 check_device_lock();assert(!munmap(dl_image,dl_map_size));free(dl_original);return 0;
}
'''
        assert assertions(source)[:1505] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'), str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str(a.reference_image.resolve()), str(a.image.resolve())], out / 'run.log')
        rows.append({'abi': abi, 'unchanged_assert_sites': 1505, 'added_assert_sites': len(assertions(source)) - 1505, 'total_assert_sites': len(assertions(source)), 'result': 'PASS'})
    receipt = {'scope': 'Developer ASan/UBSan host execution of production recognizer on reference and device Image; not ARM64 target execution', 'device_sources': {n: {'offset': symbols[n], 'lock_unlock_indices': list(pos)} for n, pos in zip(NAMES, call_positions)}, 'host': rows}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
