#!/usr/bin/env python3
"""Developer：两目标末端片段尺寸推导及完整布局准备；保留原动态准备断言。"""
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
    symbols = {name: at for at, kind, name in json.loads(args.symbols.read_text())}
    reference = json.loads(args.reference.read_text())
    offsets = reference['offsets']
    table_at = symbols['sdcardfs_ci_dops']
    table = struct.unpack_from('<14Q', image, table_at)
    blk = struct.unpack_from('<2Q', image, symbols['def_blk_fops'])
    llseek = [n for n in symbols if n.startswith('block_llseek.') and n.endswith('.cfi_jt')]
    native_base = blk[1] - symbols[llseek[0] if llseek else 'block_llseek']
    names = ['set_posix_acl', 'super_cache_count', 'sdcardfs_ci_dops', 'sdcardfs_canonical_path']
    windows = {'set_posix_acl': 13, 'super_cache_count': 21}
    chunks = {name: image[symbols[name]:symbols[name] + count * 4] for name, count in windows.items()}
    evidence = {'windows': {name: {'offset': symbols[name], 'words': list(struct.unpack('<' + 'I' * windows[name], raw))}
                            for name, raw in chunks.items()},
                'dentry_prefix': {'offset': table_at, 'size': 112,
                                 'sha256': hashlib.sha256(image[table_at:table_at+112]).hexdigest()}}

    def extend(c):
        c = c.replace('static unsigned int queries;', 'static bool tail_enabled; static uintptr_t* tail_override;\nstatic unsigned int queries;', 1)
        needle = 'static unsigned long kallsyms_lookup_name(const char* name) { queries++;'
        lookup = 'if(tail_enabled){\nif(!strcmp(name,"sdcardfs_ci_dops")&&tail_override)return (uintptr_t)tail_override;\n'
        lookup += ''.join(f'if(!strcmp(name,"{name}"))return missing&&!strcmp(missing,name)?0:(uintptr_t)(arena+{symbols[name]}U);\n'
                          for name in names)
        lookup += '}\n'
        ops = (root / 'nomount/nm_operations.c').read_text().split('// 原表按', 1)[0]
        btf = 'static int calculate_btf_operation_sizes(bool* unavailable){*unavailable=mode==0;'
        btf += 'if(mode==3){'
        btf += ''.join(f'struct_offset.{name}={offsets[name]};' for name in ['inode_ops_size', 'super_ops_size', 'dentry_ops_size', 'key_type_size'])
        btf += 'return 0;}return mode==1?-EINVAL:-ENODATA;}\n'
        assert c.count(needle) == 1
        c = c.replace(needle, btf + ops + needle + lookup, 1)
        reset = 'tail_enabled=false;tail_override=NULL;\n'
        for name, raw in chunks.items():
            words = struct.unpack('<' + 'I' * windows[name], raw)
            reset += '{const u32 words[]={' + ','.join(map(str, words)) + f'}};memcpy(arena+{symbols[name]}U,words,sizeof(words));}}\n'
        for i, value in enumerate(table):
            at = value - native_base
            if symbols['_stext'] <= at <= symbols['_etext'] - 4:
                reset += f'((uintptr_t*)(arena+{table_at}U))[{i}]=(uintptr_t)(arena+{at}U);\n'
                word = struct.unpack_from('<I', image, at)[0]
                reset += f'*(u32*)(arena+{at}U)={word}U;\n'
            else:
                reset += f'((uintptr_t*)(arena+{table_at}U))[{i}]={value}ULL;\n'
        setup = '''static void tail_base(void){reset();tail_enabled=true;extra_symbols=true;key_symbols=true;
assert(!calculate_function_offsets());assert(!nm_prepare_rule_layout());assert(!nm_prepare_file_layout());}
'''
        needle = '}\nint main(void) {'
        assert c.count(needle) == 1
        c = c.replace(needle, reset + '}\n' + setup + 'int main(void) {', 1)
        cases = 'tail_base();assert(!nm_prepare_operation_sizes());\n'
        for name in ['inode_ops_size', 'super_ops_size', 'dentry_ops_size']:
            cases += f'assert(struct_offset.{name}=={offsets[name]});\n'
        cases += 'assert(struct_offset.key_type_size==-1&&nm_owned_operation_size(NM_KEY_TYPE)==512);\n'
        cases += '''assert(!nm_prepare_inode_layout());assert(!nm_prepare_directory_layout());
assert(!nm_prepare_control_layout());assert(!nm_prepare_permission_abi());
assert(!nm_prepare_virtual_directory_abi()&&!nm_prepare_topology_abi()&&!nm_prepare_backing_directory_abi());
'''
        for name in names:
            cases += f'tail_base();missing="{name}";assert(nm_prepare_operation_sizes()==-ENOENT);\n'
        for name, count in [('set_posix_acl', 11 if offsets['dop_init'] >= 0 else 13),
                            ('super_cache_count', 21 if offsets['dop_init'] >= 0 else 17)]:
            cases += f'for(unsigned i=0;i<{count};i++){{tail_base();((u32*)(arena+{symbols[name]}U))[i]=0x94000000;assert(nm_prepare_operation_sizes()<0);}}\n'
        cases += 'tail_base();mode=1;queries=0;assert(nm_prepare_operation_sizes()==-EINVAL&&!queries&&!nm_owned_operation_fallback);\n'
        cases += 'tail_base();mode=2;queries=0;assert(nm_prepare_operation_sizes()==-ENODATA&&!queries&&!nm_owned_operation_fallback);\n'
        cases += 'tail_base();mode=3;queries=0;assert(!nm_prepare_operation_sizes()&&!queries&&!nm_owned_operation_fallback);\n'
        # 实际表前缀紧邻不可访问页，找不到回调也不得继续读第15槽。
        cases += f'''tail_base();long tail_page=sysconf(_SC_PAGESIZE);
void* tail_guard=mmap(NULL,2*tail_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(tail_guard!=MAP_FAILED&&!mprotect((char*)tail_guard+tail_page,tail_page,PROT_NONE));
tail_override=(void*)((char*)tail_guard+tail_page-NM_DENTRY_TAIL_PROBE_SIZE);
memcpy(tail_override,arena+{table_at}U,NM_DENTRY_TAIL_PROBE_SIZE);
assert(!nm_prepare_operation_sizes());
tail_override[0]=tail_override[13];assert(nm_prepare_operation_sizes()==-EINVAL);tail_override[0]=0;
tail_override[13]=0;assert(nm_prepare_operation_sizes()==-ENOENT);
assert(!munmap(tail_guard,2*tail_page));tail_override=NULL;
'''
        # 用已确认值核对混合声明、负数、边界及最终对齐。
        acl = 176 if offsets['dop_init'] >= 0 else 216
        cache = 232 if offsets['dop_init'] >= 0 else 216
        cases += f'tail_base();assert(!nm_prepare_operation_sizes());assert(!nm_set_operation_extents({acl},{cache},104));\n'
        for field in ['iop_getattr', 'sop_drop_inode', 'sop_evict_inode', 'dop_init', 'dop_release']:
            cases += f'{{int saved=struct_offset.{field};struct_offset.{field}+=8;assert(nm_set_operation_extents({acl},{cache},104)<0);struct_offset.{field}=saved;}}\n'
        cases += '''assert(nm_tail_extent(-1,8,64)==-EINVAL);
assert(nm_tail_extent(4096,8,64)==-EINVAL);assert(nm_tail_extent(3,8,64)==-EINVAL);
assert(nm_tail_extent(216,8,64)==256);assert(nm_tail_extent(104,8,64)==128);
assert(nm_tail_extent(176,40,64)==256);assert(nm_tail_extent(104,32,64)==192);
assert(inst_is_dmb_ishld(0xD50339BF)&&!inst_is_dmb_ishld(0xD5033BBF));
puts("PASS: three operation extents, full layout preparation, BTF routing and guarded table prefix");
'''
        assert c.count('free(arena);puts(') == 1
        return c.replace('free(arena);puts(', cases + 'free(arena);puts(', 1)

    # 原工具原地不变，原断言全部执行；仅在生成编译单元后追加真实窗口与新用例。
    original = root / 'nomount/tools/test_dynamic_preparation.py'
    source = original.read_text()
    needle = '    args.output.mkdir(parents=True, exist_ok=False)'
    assert source.count(needle) == 1
    source = source.replace(needle, '    c = extend(c)\n' + needle, 1)
    scope = {'__file__': str(original), '__name__': 'operation_extents_fixture', 'extend': extend}
    exec(compile(source, str(original), 'exec'), scope)
    scope['main']()
    receipt = {'scope': 'Developer operation extents and complete layout preparation; no native allocation, registration or runtime claim',
               'image_sha256': reference['image_sha256'], 'kernel_sha256': reference['kernel_sha256'],
               'evidence': evidence, 'derived': {name: offsets[name] for name in ['inode_ops_size', 'super_ops_size', 'dentry_ops_size']},
               'oracle_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
               'fixture_extension': 'original assertions unchanged; append operation-size BTF stub, target windows and new assertions'}
    (args.output / 'operation-extents.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
