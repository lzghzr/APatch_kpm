#!/usr/bin/env python3
"""执行目标key_type尾部推导与控制准备；追加用例，保留已有回调Oracle。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('image', 'symbols', 'reference', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'nomount/tools'))
    import inspect_target
    image = inspect_target.unpack_target(args.image).data
    reference = json.loads(args.reference.read_text())
    symbols = {name: at for at, kind, name in json.loads(args.symbols.read_text())}
    names = ('unregister_key_type', 'down_write', '__list_del_entry_valid')
    at = symbols['unregister_key_type']
    words = struct.unpack_from('<17I', image, at)
    expected = reference['offsets']['key_type_size']

    def extend(c):
        needle = 'static unsigned int queries;'
        assert c.count(needle) == 1
        c = c.replace(needle, 'static bool key_extent_enabled;\n' + needle, 1)
        needle = 'static unsigned long kallsyms_lookup_name(const char* name) { queries++;'
        lookup = '\nif(key_extent_enabled){\n'
        lookup += ''.join(f'if(!strcmp(name,"{name}"))return missing&&!strcmp(missing,name)?0:(uintptr_t)(arena+{symbols[name]}U);\n'
                          for name in names)
        lookup += '}\n'
        assert c.count(needle) == 1
        c = c.replace(needle, needle + lookup, 1)
        reset = 'key_extent_enabled=false;nm_owned_operation_fallback=false;\n'
        reset += '{const u32 words[]={' + ','.join(map(str, words)) + f'}};memcpy(arena+{at}U,words,sizeof(words));}}\n'
        needle = '}\nint main(void) {'
        assert c.count(needle) == 1
        setup = '''static void key_extent_base(void){
 reset();key_symbols=true;key_extent_enabled=true;nm_owned_operation_fallback=true;
}
'''
        # 使用实际分配路径，核对推导结果确实替代容量，并且新表完整清零。
        setup += '''#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
static size_t key_requested;
static void* nm_zalloc(size_t n){key_requested=n;return calloc(1,n);}
static void nm_free(void* p){free(p);}
'''
        operations = (root / 'nomount/nm_operations.c').read_text()
        setup += operations[operations.index('static void* nm_new_operations'):]
        c = c.replace(needle, reset + '}\n' + setup + 'int main(void) {', 1)
        cases = f'''
u32* key_unreg=(void*)(arena+{at}U);
key_extent_base();assert(!nm_prepare_control_layout());
assert(struct_offset.key_type_size=={expected}&&nm_owned_operation_size(NM_KEY_TYPE)=={expected});
void* key_new=nm_new_operations(NM_KEY_TYPE,NULL);assert(!IS_ERR_OR_NULL(key_new)&&key_requested=={expected});
for(unsigned i=0;i<key_requested;i++)assert(!((unsigned char*)key_new)[i]);
nm_discard_operations(key_new);
assert(nm_find_key_type_link(key_unreg,(uintptr_t)(arena+{symbols['down_write']}U),
 (uintptr_t)(arena+{symbols['__list_del_entry_valid']}U))=={expected}-sizeof(struct nm_key_type_tail));
'''
        # 每一条均是有语义的固定形态；NOP与原子状态写回不能穿越。
        for instruction in (0xd503201f, 0xc8137c83):
            cases += f'''for(unsigned i=0;i<17;i++){{
key_extent_base();key_unreg[i]={instruction}U;
assert(!calculate_function_control_offsets()&&!calculate_function_key_callbacks());
assert(calculate_function_key_type_size()<0&&struct_offset.key_type_size==-1);
}}\n'''
        # 已识别形态内部矛盾必须经真正准备入口失败，不能回到容量分支。
        for index, mask in ((12, 1 << 15), (13, 1 << 5), (14, 1 << 31),
                            (15, 1 << 10), (16, 1 << 10)):
            cases += f'key_extent_base();key_unreg[{index}]^={mask}U;assert(nm_prepare_control_layout()==-EINVAL&&struct_offset.key_type_size==-1);\n'
        cases += '''key_extent_base();
key_unreg[8]=(key_unreg[8]&~0x3ffc00U)|(128U<<10);
key_unreg[12]=(key_unreg[12]&~0x3f8000U)|(16U<<15);
key_unreg[15]=(key_unreg[15]&~0x3ffc00U)|(16U<<10);
key_unreg[16]=(key_unreg[16]&~0x3ffc00U)|(17U<<10);
assert(nm_prepare_control_layout()==-EINVAL&&struct_offset.key_type_size==-1);
'''
        cases += '''key_extent_base();assert(!calculate_function_control_offsets()&&!calculate_function_key_callbacks());
struct_offset.mutex_no_lockdep=0;assert(calculate_function_key_type_size()==-EOPNOTSUPP&&struct_offset.key_type_size==-1);
key_extent_base();assert(!calculate_function_control_offsets()&&!calculate_function_key_callbacks());
struct_offset.key_callbacks+=8;assert(calculate_function_key_type_size()==-EOPNOTSUPP&&struct_offset.key_type_size==-1);
'''
        # 窄指针、左移立即数、错误调用目标与分支落点均拒绝。
        for index, mask in ((8, 1 << 22), (8, 1 << 31), (7, 1), (10, 1),
                            (11, 1 << 5), (11, 1 << 19), (11, 1 << 31)):
            cases += f'''key_extent_base();key_unreg[{index}]^={mask}U;
assert(!calculate_function_control_offsets()&&!calculate_function_key_callbacks());
assert(calculate_function_key_type_size()<0&&struct_offset.key_type_size==-1);\n'''
        for name in names:
            cases += f'''key_extent_base();missing="{name}";assert(!nm_prepare_control_layout());
assert(struct_offset.key_type_size==-1&&nm_owned_operation_size(NM_KEY_TYPE)==512);\n'''
        cases += '''key_extent_base();mode=1;assert(nm_prepare_control_layout()==-EINVAL&&!queries&&struct_offset.key_type_size==-1);
key_extent_base();mode=2;assert(nm_prepare_control_layout()==-ENODATA&&!queries&&struct_offset.key_type_size==-1);
'''
        # 17条恰好结束于保护页，既不扫描函数尾也不读取原生对象尾部。
        cases += f'''key_extent_base();long key_page=sysconf(_SC_PAGESIZE);
void* key_pages=mmap(NULL,2*key_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(key_pages!=MAP_FAILED&&!mprotect((char*)key_pages+key_page,key_page,PROT_NONE));
u32* key_edge=(void*)((char*)key_pages+key_page-17*sizeof(u32));memcpy(key_edge,key_unreg,17*sizeof(u32));
uintptr_t write_target=(uintptr_t)&key_edge[7]+inst_get_bl_label(key_edge[7]);
uintptr_t valid_target=(uintptr_t)&key_edge[10]+inst_get_bl_label(key_edge[10]);
assert(nm_find_key_type_link(key_edge,write_target,valid_target)=={expected}-sizeof(struct nm_key_type_tail));
assert(!munmap(key_pages,2*key_page));
puts("PASS: key_type extent, native anchor agreement, failure routing and 17-instruction guard");
'''
        needle = 'free(arena);puts('
        assert c.count(needle) == 1
        return c.replace(needle, cases + needle, 1)

    original = root / 'nomount/tools/test_function_key_callbacks.py'
    source = original.read_text()
    needle = '    args.output.mkdir(parents=True, exist_ok=False)'
    assert source.count(needle) == 1
    source = source.replace(needle, '    c = extend(c)\n' + needle, 1)
    scope = {'__file__': str(original), '__name__': 'key_extent_fixture', 'extend': extend}
    exec(compile(source, str(original), 'exec'), scope)
    scope['main']()
    receipt = {
        'scope': 'Developer selected-image key_type tail contract; no native registration or device result',
        'target': reference['target'], 'kernel_sha256': reference['kernel_sha256'],
        'source_commit': reference['kernel_source_commit'], 'key_type_size': expected,
        'link_offset': expected - 16, 'unregister_words': list(words),
        'oracle': str(original.relative_to(root)), 'oracle_assertions': 'unchanged and executed before new cases',
        'residual': 'unobserved vendor appendages are outside the verified declaration contract',
        'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (args.output / 'key-type-extent.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
