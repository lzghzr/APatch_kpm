#!/usr/bin/env python3
"""Developer：完整动态布局准备；真实目标窗口、BTF路由与接口声明回退。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(data):
    return hashlib.sha256(data).hexdigest()


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
    assert sha(args.image.read_bytes()) == reference['image_sha256']
    assert sha(image) == reference['kernel_sha256']
    offsets = reference['offsets']
    symbols = {name: at for at, kind, name in json.loads(args.symbols.read_text())}
    windows = {'full_name_hash': 6, 'dentry_open': 5, 'vfs_open': 10, 'tty_default_fops': 7, 'simple_open': 4,
               'noop_llseek': 2, 'nonseekable_open': 5, 'file_ns_capable': 12,
               'vfs_llseek': 16, 'generic_file_mmap': 8, 'iterate_dir': 12, 'generic_fillattr': 36,
               'set_nlink': 8, 'inc_nlink': 16, 'd_set_d_op': 16,
               'address_space_init_once': 8, 'inode_init_always': 21}
    windows.update({'ext4_drop_inode': 12, 'simple_getattr': 9,
                    'vfs_getattr_nosec': 29 if offsets['getattr_function_args'] == 4 else 12})
    windows.update({'__mutex_init': 7 if offsets['mutex_size']==32 else 10, 'user_preparse': 11})
    windows.update({'__dentry_kill':23 if offsets['getattr_function_args']==4 else 17, 'empty_dir_readdir':30 if offsets['dir_actor_abi']==0 and offsets['getattr_function_args']==4 else 20,
                    'inode_permission':7,'inode_permission2':8 if offsets['getattr_function_args']==4 else 4,'lockref_mark_dead':1})
    windows['generic_shutdown_super']=35 if offsets['getattr_function_args']==4 else 25
    windows.update({'register_key_type':18,'key_instantiate_and_link':22 if offsets['getattr_function_args']==4 else 26})
    callbacks = ['blkdev_open', 'blkdev_close', 'generic_file_mmap', 'generic_file_splice_read']
    fields = ['fop_open', 'fop_release', 'fop_mmap', 'fop_splice_read']
    table_at, size = symbols['def_blk_fops'], offsets['file_ops_size']
    values = struct.unpack_from('<' + 'Q' * (size // 8), image, table_at)
    llseek = [name for name in symbols if name.startswith('block_llseek.') and name.endswith('.cfi_jt')]
    assert len(llseek) <= 1
    native_base = values[1] - symbols[llseek[0] if llseek else 'block_llseek']
    # 校验每项需要的真实地址；CFI跳板必须直接B到对应原生函数。
    evidence = {}
    chunks = {}
    for name, count in windows.items():
        at = symbols[name]
        raw = image[at:at + count * 4]
        assert len(raw) == count * 4
        chunks[name] = (at, raw)
        evidence[name] = {'offset': at, 'words': list(struct.unpack('<' + 'I' * count, raw)), 'sha256': sha(raw)}
    for name, field in zip(callbacks, fields):
        at = values[offsets[field] // 8] - native_base
        assert symbols['_stext'] <= at <= symbols['_etext'] - 4
        word = struct.unpack_from('<I', image, at)[0]
        if at != symbols[name]:
            assert word & 0xfc000000 == 0x14000000
            delta = word & 0x3ffffff
            delta = delta - (1 << 26) if delta & (1 << 25) else delta
            assert at + delta * 4 == symbols[name]
        evidence[field] = {'slot': offsets[field], 'pointer_offset': at, 'function_offset': symbols[name],
                           'entry_word': word, 'direct': at == symbols[name]}
    # 回调表中的核心代码指针按同一重定位平移，其他数据保持原字节。
    table = list(values)
    code_words = {}
    for i, value in enumerate(values):
        at = value - native_base
        if symbols['_stext'] <= at <= symbols['_etext'] - 4:
            table[i] = at
            code_words[at] = struct.unpack_from('<I', image, at)[0]
    dir_at=symbols['simple_dir_operations']
    dir_values=struct.unpack_from('<'+'Q'*(size//8),image,dir_at)
    dir_table=[]
    for value in dir_values:
        at=value-native_base
        if symbols['_stext']<=at<=symbols['_etext']-4:
            dir_table.append(at)
            code_words[at]=struct.unpack_from('<I',image,at)[0]
        else: dir_table.append(value)
    dir_slot=offsets['fop_iterate_shared'] if offsets['fop_iterate_shared']>=0 else offsets['fop_iterate']
    dir_callback=dir_values[dir_slot//8]-native_base
    if dir_callback!=symbols['dcache_readdir']:
        word=code_words[dir_callback]
        assert word&0xfc000000==0x14000000
        delta=word&0x3ffffff
        if delta&(1<<25): delta-=1<<26
        assert dir_callback+delta*4==symbols['dcache_readdir']
    evidence['directory_callback']={'slot':dir_slot,'pointer_offset':dir_callback,'function_offset':symbols['dcache_readdir'],'entry_word':code_words[dir_callback]}
    call_at=symbols['__dentry_kill']+40
    word=struct.unpack_from('<I',image,call_at)[0]
    assert word&0xfc000000==0x94000000
    delta=word&0x3ffffff
    if delta&(1<<25):delta-=1<<26
    called=call_at+delta*4
    if called!=symbols['lockref_mark_dead']:
        jump=struct.unpack_from('<I',image,called)[0]
        assert jump&0xfc000000==0x14000000
        d=jump&0x3ffffff
        if d&(1<<25):d-=1<<26
        assert called+d*4==symbols['lockref_mark_dead']
        code_words[called]=jump
    evidence['mark_dead_call']={'call_offset':call_at,'called_offset':called,'function_offset':symbols['lockref_mark_dead']}
    key_at=symbols['key_type_user']
    key_values=struct.unpack_from('<7Q',image,key_at)
    key_table=[]
    for value in key_values:
        at=value-native_base
        if symbols['_stext']<=at<=symbols['_etext']-4:
            key_table.append(at)
            code_words[at]=struct.unpack_from('<I',image,at)[0]
        else: key_table.append(value)
    key_names=['key_type_user','strcmp','user_free_preparse','generic_key_instantiate','register_key_type','key_instantiate_and_link']
    evidence['key_prefix']={'offset':key_at,'size':56,'sha256':sha(image[key_at:key_at+56]),'callbacks':offsets['key_callbacks']}
    needed = key_names + ['simple_dir_operations'  ,'dcache_readdir'] + ['_stext', '_etext', 'def_blk_fops', 'memcpy', 'memset'] + list(windows) + callbacks
    tty = [n for n in symbols if n == 'tty_fops' or n.startswith('tty_fops.')]
    assert len(tty) == 1
    selected = {name: symbols[name] for name in needed}
    selected['tty_fops'] = symbols[tty[0]]
    no_open = [n for n in symbols if n == 'inode_init_always.no_open_fops' or n.startswith('no_open_fops.')]
    assert len(no_open) == 1
    selected['inode_init_always.no_open_fops'] = symbols[no_open[0]]
    extent = max(list(selected.values()) + [table_at + size]) + 8192
    extent = (extent + 4095) & ~4095
    source = (root / 'nomount/nm_offsets.c').read_text()
    prefix = source.split('// int保留', 1)[0].replace('__attribute__((section(".data.re_offsets"), used))', '')
    functions = source.split('#include "nm_btf.c"\n', 1)[1].split('static int nm_scalar_copy', 1)[0]
    more = 'static int nm_scalar_copy(' + source.split('static int nm_scalar_copy(', 1)[1].split('#endif\n\nstatic int calculate_offsets', 1)[0]
    inode_validation = 'static int nm_validate_inode_offsets' + source.split('static int nm_validate_inode_offsets', 1)[1].split('static int nm_validate_directory_offsets', 1)[0]
    inode_route = 'static int nm_prepare_inode_layout' + source.split('static int nm_prepare_inode_layout', 1)[1].split('static int nm_prepare_directory_layout', 1)[0]
    validation = 'static int nm_validate_file_offsets' + source.split('static int nm_validate_file_offsets', 1)[1].split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
    route = 'static int nm_prepare_rule_layout' + source.split('static int nm_prepare_rule_layout', 1)[1].split('static int nm_prepare_inode_layout', 1)[0]
    control_validation='static int nm_validate_control_layout' + source.split('static int nm_validate_control_layout',1)[1].split('static struct inode* nm_file_inode',1)[0]
    control_route='static int nm_prepare_control_layout' + source.split('static int nm_prepare_control_layout',1)[1]
    directory_validation='static int nm_validate_directory_offsets' + source.split('static int nm_validate_directory_offsets',1)[1].split('static int nm_validate_file_offsets',1)[0]
    directory_route='static int nm_prepare_directory_layout' + source.split('static int nm_prepare_directory_layout',1)[1].split('static int nm_prepare_control_layout',1)[0]
    utils = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    c = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
static unsigned char* arena;
static const char* missing;
static unsigned int queries;
static int mode;
static bool extra_symbols;
static bool key_symbols;
static uintptr_t* key_override;
static unsigned long kallsyms_lookup_name(const char* name);
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) { return kallsyms_lookup_name(name); }
static int calculate_btf_virtual_directory_abi(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_topology_abi(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_backing_directory_abi(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_rule_prefixes(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_file_offsets(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_directory_offsets(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_backing_inode_abi(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_control_layout(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
static int calculate_btf_inode_offsets(bool* unavailable) { *unavailable=mode==0; return mode==1?-EINVAL:-ENODATA; }
'''
    c += utils + (root / 'nomount/nm_structs.h').read_text() + prefix + functions + more + inode_validation + validation + route + inode_route + control_validation + control_route + directory_validation + directory_route
    c += 'static unsigned long kallsyms_lookup_name(const char* name) { queries++; if(missing&&!strcmp(missing,name))return 0;\n'
    c += 'if(!strcmp(name,"key_type_user")&&key_override)return (uintptr_t)key_override;\n'
    c += ''.join(f'if(!strcmp(name,"{name}"))return '+('!extra_symbols?0:' if name in ['__dentry_kill','empty_dir_readdir','inode_permission','inode_permission2','lockref_mark_dead'] else '!key_symbols?0:' if name in key_names else '')+f'(uintptr_t)(arena+{at}U);\n' for name, at in selected.items())
    c += 'return 0;}\nstatic void reset(void) { queries=0; missing=NULL; mode=0; extra_symbols=false;key_symbols=false;key_override=NULL;\n'
    c += 'memset((void*)&struct_offset,0xff,sizeof(struct_offset));\n'
    c += f'struct_offset.file_inode_ops={offsets["file_inode_ops"]};struct_offset.file_mapping={offsets["file_mapping"]};\n'
    for name, (at, raw) in chunks.items():
        words = struct.unpack('<' + 'I' * (len(raw) // 4), raw)
        c += '{const u32 words[]={' + ','.join(map(str, words)) + f'}};memcpy(arena+{at}U,words,sizeof(words));}}\n'
    for at, word in code_words.items():
        c += f'*(u32*)(arena+{at}U)={word}U;\n'
    for i, value in enumerate(table):
        original = values[i]
        expression = f'(uintptr_t)(arena+{value}U)' if value != original else f'{value}ULL'
        c += f'((uintptr_t*)(arena+{table_at}U))[{i}]={expression};\n'
    for i,value in enumerate(dir_table):
        original=dir_values[i]
        expression=f'(uintptr_t)(arena+{value}U)' if value!=original else f'{value}ULL'
        c += f'((uintptr_t*)(arena+{dir_at}U))[{i}]={expression};\n'
    for i,value in enumerate(key_table):
        expression=f'(uintptr_t)(arena+{value}U)' if value!=key_values[i] else f'{value}ULL'
        c += f'((uintptr_t*)(arena+{key_at}U))[{i}]={expression};\n'
    c += '}\nint main(void) {\n'
    c += f'arena=aligned_alloc(4096,{extent}U);assert(arena);memset(arena,0,{extent}U);reset();\n'
    c += f'u32* hash=(void*)(arena+{symbols["full_name_hash"]}U);uintptr_t* table=(void*)(arena+{table_at}U);\n'
    c += 'struct_offset.file_inode_ops=-1;struct_offset.file_mapping=-1;assert(!calculate_function_offsets());\n'
    base_fields=['file_inode_ops','file_mapping','inode_superblock','inode_number','inode_nlink','inode_size','dentry_ops','kstat_inode_first']
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in base_fields)
    c += 'assert(!calculate_function_inode_offsets());\n'
    storage_fields=['inode_file_ops','inode_data','inode_data_size','inode_blocks']
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in storage_fields)
    callback_fields=['inode_hash','iop_getattr','getattr_callback_args','getattr_function_args','getattr_context_kind','fillattr_abi']
    c += 'assert(!calculate_function_inode_callbacks());\n'
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in callback_fields)
    control_fields=['mutex_size','mutex_no_lockdep','key_preparse_data']
    c += 'assert(!calculate_function_control_offsets());\n'
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in control_fields)
    c += 'assert(nm_prepare_control_layout()==-ENOENT); // key_type完整尺寸与回调仍不可用。\n'
    super_fields=['sop_drop_inode','sop_evict_inode']
    c += 'assert(!calculate_function_super_callbacks());\n'
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in super_fields)
    c += 'assert(nm_prepare_inode_layout()==-EINVAL); // 完整公共校验仍拒绝未取得的操作表尺寸／super回调。\n'
    c += f'assert(!nm_prepare_rule_layout()&&struct_offset.name_hash_args=={offsets["name_hash_args"]});\n'
    c += 'assert(!nm_prepare_file_layout());\n'
    checked = ['inode_private', 'file_private', 'file_position', 'file_flags', 'file_cred', 'file_ops_size'] + fields
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in checked)
    c += r'''
'''
    directory_fields=['dentry_lock','fop_iterate','fop_iterate_shared']
    c += 'assert(!calculate_function_directory_offsets());\n'
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in directory_fields)
    c += 'assert(nm_prepare_directory_layout()==-ENOENT); // actor ABI和dentry完整表仍不可用。\n'
    callback_fields_v6=['dop_init','dop_release','dir_actor_abi','permission_abi']
    c += 'extra_symbols=true;assert(!calculate_function_directory_callbacks());assert(!nm_prepare_permission_abi());\n'
    c += ''.join(f'assert(struct_offset.{name}=={offsets[name]});\n' for name in callback_fields_v6)
    c += 'assert(nm_prepare_directory_layout()==-EINVAL);extra_symbols=false; // 新回调已取得，完整表仍不可用。\n'

    c += r'''
assert(!nm_validate_file_offsets((const void*)&struct_offset));
struct_offset.fop_open=-1;assert(nm_validate_file_offsets((const void*)&struct_offset)==-EINVAL);
reset();missing="full_name_hash";assert(nm_prepare_rule_layout()==-ENOENT);
reset();mode=1;assert(nm_prepare_rule_layout()==-EINVAL&&!queries);assert(nm_prepare_file_layout()==-EINVAL&&!queries);
reset();mode=2;assert(nm_prepare_rule_layout()==-ENODATA&&!queries);assert(nm_prepare_file_layout()==-ENODATA&&!queries);
reset();hash[0]=0x94000000;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);
'''
    # 每条识别指令破坏为调用；不穿越未知指令取后续证据。
    count = 4 if offsets['name_hash_args'] == 2 else 6
    c += f'for(unsigned i=0;i<{count};i++){{reset();hash[i]=0x94000000;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);}}\n'
    c += f'u32* dopen=(void*)(arena+{symbols["dentry_open"]}U);u32* vfs=(void*)(arena+{symbols["vfs_open"]}U);\n'
    c += 'reset();missing="vfs_open";assert(nm_prepare_rule_layout()==-ENOENT);\n'
    c += 'reset();dopen[0]=0xAA0103E0;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);\n'
    # 把共同成员挪开，确认动态入口拒绝；不改变共同结构来迁就机器码。
    mount_at = 0 if offsets['name_hash_args'] == 3 else 4
    path_at = 7 if offsets['name_hash_args'] == 3 else 6
    inode_at = 9 if offsets['name_hash_args'] == 3 else 8
    c += f'reset();dopen[{mount_at}]^=1U<<10;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);\n'
    c += f'reset();vfs[{path_at}]^=1U<<10;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);\n'
    c += f'reset();vfs[{inode_at}]^=1U<<10;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);\n'
    c += 'reset();vfs[0]=0xAA0103E0;assert(nm_prepare_rule_layout()==-EOPNOTSUPP);\n'
    c += 'reset();missing="def_blk_fops";assert(nm_prepare_file_layout()==-ENOENT);\n'
    c += 'reset();missing="blkdev_open";assert(nm_prepare_file_layout()==-ENOENT);\n'
    field = offsets['fop_open']
    c += f'reset();table[{field // 8}]=1;assert(nm_prepare_file_layout()==-ENOENT);\n'
    c += f'reset();table[{(field + 8) // 8}]=table[{field // 8}];assert(nm_prepare_file_layout()==-EINVAL);\n'
    c += f'reset();table[{field // 8}]=(uintptr_t)(arena+{symbols["_etext"]}U);assert(nm_prepare_file_layout()==-ENOENT);\n'
    c += f'reset();table[{field // 8}]+=1;assert(nm_prepare_file_layout()==-ENOENT);\n'
    callback = evidence['fop_open']
    if not callback['direct']:
        c += f'reset();*(u32*)(arena+{callback["pointer_offset"]}U)=0xD61F0000;assert(nm_prepare_file_layout()==-ENOENT);\n'
        c += 'reset();missing="_etext";assert(nm_prepare_file_layout()==-ENOENT);\n'
        c += f'reset();*(u32*)(arena+{callback["pointer_offset"]}U)^=1;assert(nm_prepare_file_layout()==-ENOENT);\n'
    c += f'u32* init=(void*)(arena+{symbols["inode_init_always"]}U);u32* clear=(void*)(arena+{symbols["address_space_init_once"]}U);u32* attr=(void*)(arena+{symbols["generic_fillattr"]}U);\n'
    c += 'reset();mode=1;assert(nm_prepare_inode_layout()==-EINVAL&&!queries);\n'
    c += 'reset();mode=2;assert(nm_prepare_inode_layout()==-ENODATA&&!queries);\n'
    c += 'reset();missing="address_space_init_once";assert(calculate_function_inode_offsets()==-ENOENT);\n'
    c += 'reset();init[0]=0xAA1303E1;assert(calculate_function_inode_offsets()==-EOPNOTSUPP);\n'
    c += 'reset();init[0]=0xC8017C83;assert(calculate_function_inode_offsets()==-EOPNOTSUPP);\n'
    mapping_index=9 if offsets['name_hash_args']==3 else 15
    c += f'reset();init[{mapping_index}]^=1U<<10;assert(calculate_function_inode_offsets()==-EINVAL);\n'
    length_index=5 if offsets['name_hash_args']==3 else 2
    c += f'reset();clear[{length_index}]=0x52800002;assert(calculate_function_inode_offsets()==-EINVAL);\n'
    c += 'reset();clear[0]=0xAA1303E0;assert(calculate_function_inode_offsets()==-EOPNOTSUPP);\n'
    c += 'reset();clear[7]=0x94000000;\n' if offsets['name_hash_args']==3 else 'reset();clear[6]=0x94000000;\n'
    c += 'assert(calculate_function_inode_offsets()==-EOPNOTSUPP);\n'
    c += 'reset();attr[0]=0xC8007C83;assert(nm_find_kstat_prefix(attr)==-EOPNOTSUPP);\n'
    c += 'reset();attr[0]=0x54000080;assert(nm_find_kstat_prefix(attr)==-EOPNOTSUPP);\n'
    c += 'reset();attr[0]=0x94000000;assert(nm_find_kstat_prefix(attr)==-EOPNOTSUPP);\n'
    if offsets['name_hash_args']==2:
        c += f'u32* iter=(void*)(arena+{symbols["iterate_dir"]}U);u32* map=(void*)(arena+{symbols["generic_file_mmap"]}U);u32* dop=(void*)(arena+{symbols["d_set_d_op"]}U);\n'
        c += 'reset();iter[8]^=1U<<10;assert(nm_find_file_objects_from_iterate(iter)==-ENOENT);\n'
        c += 'reset();map[6]=0xAA0303E3;assert(nm_find_mapping(map)==-ENOENT);\n'
        c += 'reset();dop[0]^=2;assert(nm_find_dentry_ops(dop)==-ENOENT);\n'
    adrp_at=18 if offsets['name_hash_args']==3 else 5
    add_at=19 if offsets['name_hash_args']==3 else 9
    original=struct.unpack('<21I',chunks['inode_init_always'][1])
    for reg,overwrite in [(29,0x910003fd),(18,0xf800865e)]:
        adrp=(original[adrp_at]&~31)|reg
        add=(original[add_at]&~1023)|(reg<<5)|reg
        store=0xf9000020|reg|((offsets['inode_file_ops']//8)<<10)
        c += 'reset();for(unsigned i=0;i<21;i++)init[i]=0xD65F03C0;\n'
        c += f'init[0]={adrp}U;init[1]={add}U;init[2]={overwrite}U;init[3]={original[mapping_index]}U;init[4]={store}U;\n'
        c += f'int data_{reg}=-1;assert(nm_find_inode_storage(init,(uintptr_t)(arena+{selected["inode_init_always.no_open_fops"]}U),&data_{reg})<0);\n'
    if offsets['name_hash_args']==2:
        c += f'u32* nlink=(void*)(arena+{symbols["set_nlink"]}U);\n'
        c += 'reset();nlink[3]=(nlink[3]&~0x00FFFFE0U)|(5U<<5);assert(nm_find_nlink(nlink,8)<0);\n'
        c += 'reset();nlink[1]=0xAA0203E0;assert(nm_find_nlink(nlink,8)<0);\n'
    c += f'u32* drop=(void*)(arena+{symbols["ext4_drop_inode"]}U);u32* getattr=(void*)(arena+{symbols["vfs_getattr_nosec"]}U);u32* simple=(void*)(arena+{symbols["simple_getattr"]}U);\n'
    for dep in ['ext4_drop_inode','vfs_getattr_nosec','simple_getattr','generic_fillattr']:
        c += f'reset();missing="{dep}";assert(calculate_function_inode_callbacks()==-ENOENT);\n'
    # 每条入口指令分别变为未知调用，不能靠忽略中间写入取得字段。
    for name,var in [('ext4_drop_inode','drop'),('vfs_getattr_nosec','getattr'),('simple_getattr','simple')]:
        count=windows[name]
        if name=='simple_getattr': count=9 if offsets['getattr_function_args']==4 else 8
        if name=='ext4_drop_inode': count=12 if offsets['getattr_function_args']==4 else 9
        c += f'for(unsigned i=0;i<{count};i++){{reset();struct_offset.inode_nlink={offsets["inode_nlink"]};struct_offset.inode_superblock={offsets["inode_superblock"]};{var}[i]=0x94000000;assert(calculate_function_inode_callbacks()<0);}}\n'
    nlink_i=7 if offsets['getattr_function_args']==4 else 5
    hash_i=10 if offsets['getattr_function_args']==4 else 7
    attr_i=14 if offsets['getattr_function_args']==4 else 7
    for var,index in [('drop',nlink_i),('drop',hash_i),('getattr',attr_i)]:
        # nlink 错位、无效 hash 基址及不可用回调槽分别拒绝。
        change='^=1U<<10' if index==nlink_i and var=='drop' else '=0xF9400000'
        c += f'reset();struct_offset.inode_nlink={offsets["inode_nlink"]};struct_offset.inode_superblock={offsets["inode_superblock"]};{var}[{index}]{change};assert(calculate_function_inode_callbacks()<0);\n'
    # nlink 的窄加载不能覆盖 inode 基址；保存 inode 时也不能覆盖待测 nlink。
    for reg in ([0,19,31] if offsets['getattr_function_args']==4 else [0,31]):
        branch_i=9 if offsets['getattr_function_args']==4 else 6
        c += f'reset();struct_offset.inode_nlink={offsets["inode_nlink"]};drop[{nlink_i}]=(drop[{nlink_i}]&~31U)|{reg};drop[{branch_i}]=(drop[{branch_i}]&~31U)|{reg};assert(nm_find_inode_hash(drop)<0);\n'
    if offsets['getattr_function_args']==4:
        # req_mask / flags 的类型、来源、值和间接调用均绑定。
        for index,value in [(26,0x92402C42),(26,0x12002C62),(27,0x12130443),(28,0xD63F0120),
                            (22,0xCB090129),(23,0x93C90529),(25,0x54000022),(15,0xB4000028),
                            (17,0xD100C3E0),(19,0x910083E0),(18,0xA902003F)]:
            c += f'reset();struct_offset.inode_nlink={offsets["inode_nlink"]};struct_offset.inode_superblock={offsets["inode_superblock"]};getattr[{index}]={value}U;assert(calculate_function_inode_callbacks()<0);\n'
    else:
        for index,value in [(1,0xAA0103E5),(2,0xAA0303E2),(8,0xB4000023),(9,0xF94004A0),(10,0xAA0503E1),(11,0xD63F00A0)]:
            c += f'reset();struct_offset.inode_nlink={offsets["inode_nlink"]};struct_offset.inode_superblock={offsets["inode_superblock"]};getattr[{index}]={value}U;assert(calculate_function_inode_callbacks()<0);\n'
    c += r'''
assert(inst_is_sub_imm(0xD100C3FF)&&inst_get_sub_imm_imm(0xD100C3FF)==48);
assert(inst_is_sub_reg(0xCB090109)&&inst_get_sub_reg_rd(0xCB090109)==9&&inst_get_sub_reg_rn(0xCB090109)==8);
assert(!inst_is_sub_reg(0xEB090109)&&inst_is_subs_reg(0xEB1F003F));
assert(inst_get_subs_reg_rn(0xEB1F003F)==1&&inst_get_subs_reg_rm(0xEB1F003F)==31);
assert(inst_is_extr(0x93C90929)&&inst_get_extr_n(0x93C90929)&&inst_get_extr_imm6(0x93C90929)==2);
assert(!inst_is_extr(0x93E90929)&&inst_get_extr_rn(0x93E90929)==-1);
'''
    c += f'u32* mutex=(void*)(arena+{symbols["__mutex_init"]}U);u32* prep=(void*)(arena+{symbols["user_preparse"]}U);\n'
    for dep in ['__mutex_init','user_preparse']:
        c += f'reset();missing="{dep}";assert(calculate_function_control_offsets()==-ENOENT);\n'
    c += 'reset();mode=1;assert(nm_prepare_control_layout()==-EINVAL&&!queries);\n'
    c += 'reset();mode=2;assert(nm_prepare_control_layout()==-ENODATA&&!queries);\n'
    for name,var in [('__mutex_init','mutex'),('user_preparse','prep')]:
        c += f'for(unsigned i=0;i<{windows[name]};i++){{reset();{var}[i]=0x94000000;assert(calculate_function_control_offsets()<0);}}\n'
    length_index=4 if offsets['mutex_size']==32 else 5
    c += f'reset();prep[{length_index}]^=1U<<10;assert(calculate_function_control_offsets()==-EINVAL);\n'
    c += 'reset();prep[9]^=1U<<10;assert(calculate_function_control_offsets()==-EINVAL);\n'
    for index in [8,10]:
        c += f'reset();prep[{index}]=(prep[{index}]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_control_offsets()==-EOPNOTSUPP);\n'
    c += 'reset();prep[10]^=1U<<5;assert(calculate_function_control_offsets()==-EOPNOTSUPP);\n'
    c += f'reset();mutex[{windows["__mutex_init"]-1}]=0xF900401F;assert(calculate_function_control_offsets()==-EOPNOTSUPP);\n'
    c += f'reset();mutex[{windows["__mutex_init"]-1}]=0xD65F0000;assert(calculate_function_control_offsets()==-EOPNOTSUPP);\n'
    for var,index in [('drop',9 if offsets['getattr_function_args']==4 else 6),('getattr',15 if offsets['getattr_function_args']==4 else 8)]:
        c += f'reset();struct_offset.inode_nlink={offsets["inode_nlink"]};struct_offset.inode_superblock={offsets["inode_superblock"]};{var}[{index}]=({var}[{index}]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_inode_callbacks()<0);\n'
    if offsets['getattr_function_args']==4:
        c += 'reset();getattr[25]=(getattr[25]&~0x00FFFFE0U)|0x00FFFFE0U;assert(nm_find_getattr_layout(getattr,simple,(uintptr_t)attr)<0);\n'
    c += r'''
assert(inst_get_cbz_label(0xB4FFFFE0)==-4&&inst_get_b_cond_label(0x54FFFFE0)==-4);
assert(inst_get_cbz_label(0xB4000080)==16&&inst_get_b_cond_label(0x54000080)==16);
assert(inst_get_cbz_label(0xB4800000)==-1048576&&inst_get_b_cond_label(0x54800000)==-1048576);
assert(inst_get_cbz_label(0xB47FFFE0)==1048572&&inst_get_b_cond_label(0x547FFFE0)==1048572);
assert(inst_get_cbz_label(0x94000000)==-1&&inst_get_b_cond_label(0x94000000)==-1);
assert(sizeof(struct nm_mutex_count)==40&&sizeof(struct nm_mutex_owner)==32);
'''
    c += f'uintptr_t* directory_table=(void*)(arena+{dir_at}U);u32* directory_iter=(void*)(arena+{symbols["iterate_dir"]}U);\n'
    base=f'struct_offset.file_inode_ops={offsets["file_inode_ops"]};struct_offset.file_ops_size={offsets["file_ops_size"]};struct_offset.dentry_ops={offsets["dentry_ops"]};'
    for dep in ['simple_dir_operations','dcache_readdir','iterate_dir','__mutex_init']:
        c += f'reset();{base}missing="{dep}";assert(calculate_function_directory_offsets()==-ENOENT);\n'
    c += 'reset();mode=1;assert(nm_prepare_directory_layout()==-EINVAL&&!queries);\n'
    c += 'reset();mode=2;assert(nm_prepare_directory_layout()==-ENODATA&&!queries);\n'
    c += f'for(unsigned i=0;i<12;i++){{reset();{base}directory_iter[i]=0x94000000;assert(calculate_function_directory_offsets()<0);}}\n'
    c += f'reset();{base}directory_table[{dir_slot//8}]=1;assert(calculate_function_directory_offsets()==-ENOENT);\n'
    c += f'reset();{base}directory_table[{(dir_slot+8)//8}]=directory_table[{dir_slot//8}];assert(calculate_function_directory_offsets()==-EINVAL);\n'
    c += f'reset();{base}directory_iter[10]=(directory_iter[10]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_directory_offsets()<0);\n'
    c += f'reset();{base}directory_iter[9]^=1U<<10;assert(calculate_function_directory_offsets()<0);\n'
    c += f'reset();{base}struct_offset.file_ops_size=-1;assert(calculate_function_directory_offsets()==-EINVAL);\n'
    c += f'reset();{base}struct_offset.dentry_ops=0;assert(calculate_function_directory_offsets()==-EINVAL);\n'
    c += f'reset();{base}assert(!calculate_function_directory_offsets());queries=0;missing="__mutex_init";assert(!calculate_function_control_offsets());\n'
    c += f'u32* lifecycle=(void*)(arena+{symbols["__dentry_kill"]}U);u32* actor=(void*)(arena+{symbols["empty_dir_readdir"]}U);u32* permission=(void*)(arena+{symbols["inode_permission"]}U);u32* mounted=(void*)(arena+{symbols["inode_permission2"]}U);\n'
    setup=f'extra_symbols=true;struct_offset.dentry_ops={offsets["dentry_ops"]};struct_offset.dentry_lock={offsets["dentry_lock"]};struct_offset.inode_number={offsets["inode_number"]};struct_offset.inode_superblock={offsets["inode_superblock"]};'
    for dep in ['__dentry_kill','empty_dir_readdir','lockref_mark_dead']:
        c += f'reset();{setup}missing="{dep}";assert(calculate_function_directory_callbacks()==-ENOENT);\n'
    for dep in ['inode_permission','inode_permission2']:
        c += f'reset();{setup}missing="{dep}";assert(nm_prepare_permission_abi()==-ENOENT);\n'
    c += 'reset();mode=1;assert(nm_prepare_permission_abi()==-EINVAL&&!queries);\n'
    c += 'reset();mode=2;assert(nm_prepare_permission_abi()==-ENODATA&&!queries);\n'
    for name,var,fn in [('__dentry_kill','lifecycle','calculate_function_directory_callbacks()'),('empty_dir_readdir','actor','calculate_function_directory_callbacks()'),('inode_permission','permission','nm_prepare_permission_abi()'),('inode_permission2','mounted','nm_prepare_permission_abi()')]:
        c += f'for(unsigned i=0;i<{windows[name]};i++){{reset();{setup}{var}[i]=0x94000000;assert({fn}<0);}}\n'
    c += f'reset();{setup}lifecycle[12]^=1U<<19;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}lifecycle[12]=(lifecycle[12]&~0x7FFE0U)|0x7FFE0U;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}lifecycle[9]^=1U<<12;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}lifecycle[14]^=3U<<10;assert(calculate_function_directory_callbacks()==-EOPNOTSUPP);\n'
    c += f'reset();{setup}lifecycle[13]^=1U<<10;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}lifecycle[10]^=1U;assert(calculate_function_directory_callbacks()<0);\n'
    last=29 if offsets['getattr_function_args']==4 else 19
    c += f'reset();{setup}actor[{last}]^=1U<<24;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}actor[{last}]|=1U<<31;assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}actor[{last}]=(actor[{last}]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_directory_callbacks()<0);\n'
    if offsets['getattr_function_args']==4:
        c += f'reset();{setup}actor[17]=(actor[17]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_directory_callbacks()<0);\n'
    if offsets['getattr_function_args']==4:
        c += f'reset();{setup}actor[17]=(actor[17]&~0x00FFFFE0U)|(4U<<5);assert(calculate_function_directory_callbacks()<0);\n'
        c += f'reset();{setup}lifecycle[20]=(lifecycle[20]&~0x00FFFFE0U)|(2U<<5);assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}lifecycle[12]=(lifecycle[12]&~0x7FFE0U)|(3U<<5);assert(calculate_function_directory_callbacks()<0);\n'
    c += f'reset();{setup}permission[6]^=1U;assert(nm_prepare_permission_abi()<0);\n'
    mask=3 if offsets['getattr_function_args']==4 else 2
    c += f'reset();{setup}permission[{mask}]|=1U<<31;assert(nm_prepare_permission_abi()<0);\n'
    branch=7 if offsets['getattr_function_args']==4 else 3
    c += f'reset();{setup}mounted[{branch}]^=1U<<19;assert(nm_prepare_permission_abi()<0);\n'
    c += r'''
assert(inst_is_csel(0x9A8803F5)&&inst_get_csel_sf(0x9A8803F5)&&inst_get_csel_cond(0x9A8803F5)==0);
assert(inst_get_csel_rd(0x9A8803F5)==21&&inst_get_csel_rn(0x9A8803F5)==31&&inst_get_csel_rm(0x9A8803F5)==8);
assert(inst_get_csel_cond(0x9A9F1294)==1&&!inst_is_csel(0x9A8807F5));
assert(inst_get_tbz_bit(0x36200000)==4&&inst_get_tbnz_bit(0x37080002)==1);
assert(inst_get_tbz_bit(0xB6200000)==36&&inst_get_tbnz_bit(0xB7080002)==33);
assert(inst_get_tbz_label(0x3607FFE0)==-4&&inst_get_tbnz_label(0x3707FFE0)==-4);
assert(inst_get_tbz_label(0x36000080)==16&&inst_get_tbnz_label(0x37000080)==16);
assert(inst_get_tbz_label(0x36040000)==-32768&&inst_get_tbnz_label(0x3703FFE0)==32764);
assert(inst_get_cbnz_label(0xB5FFFFE0)==-4&&inst_get_cbnz_label(0xB5000080)==16);
'''
    c += f'u32* shutdown=(void*)(arena+{symbols["generic_shutdown_super"]}U);\n'
    c += 'reset();missing="generic_shutdown_super";assert(calculate_function_super_callbacks()==-ENOENT);\n'
    c += f'for(unsigned i=0;i<{windows["generic_shutdown_super"]};i++){{reset();shutdown[i]=0xC8017C83;assert(calculate_function_super_callbacks()<0);}}\n'
    put_at=25 if offsets['getattr_function_args']==4 else 21
    guard_at=26 if offsets['getattr_function_args']==4 else 22
    security=22 if offsets['getattr_function_args']==4 else 18
    c += f'reset();shutdown[{guard_at}]=(shutdown[{guard_at}]&~0x00FFFFE0U)|(2U<<5);assert(calculate_function_super_callbacks()<0);\n'
    c += f'reset();shutdown[{guard_at}]=(shutdown[{guard_at}]&~0x00FFFFE0U)|0x00FFFFE0U;assert(calculate_function_super_callbacks()<0);\n'
    c += f'reset();shutdown[{put_at}]=0xF9400281;assert(calculate_function_super_callbacks()<0);\n'
    c += f'reset();shutdown[{security}]^=1U<<5;assert(calculate_function_super_callbacks()<0);\n'
    # 不能穿越对callee-saved来源的显式或隐藏覆盖。
    for inst in [0xAA0003F4,0xAA0003F3,0xF8408E74,0xC8137C83]:
        c += f'reset();shutdown[{10 if offsets["getattr_function_args"]==4 else 7}]={inst}U;assert(calculate_function_super_callbacks()<0);\n'
    if offsets['getattr_function_args']==4:
        c += 'reset();shutdown[32]=(shutdown[32]&~0x00FFFFE0U)|(2U<<5);assert(calculate_function_super_callbacks()<0);\n'
    c += f'u32* key_register=(void*)(arena+{symbols["register_key_type"]}U);u32* key_init=(void*)(arena+{symbols["key_instantiate_and_link"]}U);uintptr_t* key_table=(void*)(arena+{key_at}U);\n'
    c += 'reset();key_symbols=true;assert(!calculate_function_key_callbacks());\n'
    c += f'assert(NM_KEY_TYPE_PROBE_SIZE==56&&struct_offset.key_callbacks=={offsets["key_callbacks"]}&&struct_offset.key_type_size==-1);\n'
    c += 'assert(nm_prepare_control_layout()==-EINVAL);\n'
    for dep in key_names+['user_preparse']:
        c += f'reset();key_symbols=true;missing="{dep}";assert(calculate_function_key_callbacks()==-ENOENT);\n'
    for var,name in [('key_register','register_key_type'),('key_init','key_instantiate_and_link')]:
        c += f'for(unsigned i=0;i<{windows[name]};i++){{reset();key_symbols=true;{var}[i]=0xC8017C83;assert(calculate_function_key_callbacks()<0);}}\n'
    for var,index in [('key_register',16),('key_init',18 if offsets['getattr_function_args']==4 else 21)]:
        c += f'reset();key_symbols=true;{var}[{index}]^=1U<<10;assert(calculate_function_key_callbacks()<0);\n'
    # 不一致的槽、超出已证前缀、窄指针、来源覆写、指令写回均拒绝。
    preparse=21 if offsets['getattr_function_args']==4 else 25
    for value in [16,40,4096]:
        c += f'reset();key_symbols=true;key_init[{preparse}]=(key_init[{preparse}]&~0x3FFC00U)|({value//8}U<<10);assert(calculate_function_key_callbacks()<0);\n'
    for index in [16,17,14]:
        c += f'reset();key_symbols=true;key_register[{index}]^=1U<<31;assert(calculate_function_key_callbacks()<0);\n'
    for index in [14,preparse]:
        c += f'reset();key_symbols=true;key_init[{index}]^=1U<<31;assert(calculate_function_key_callbacks()<0);\n'
    c += 'reset();key_symbols=true;key_register[17]^=1U;assert(calculate_function_key_callbacks()==-EOPNOTSUPP);\n'
    c += 'reset();key_symbols=true;key_register[14]=(key_register[14]&~0xFFFFE0U)|(2U<<5);assert(calculate_function_key_callbacks()==-EOPNOTSUPP);\n'
    source_at=7 if offsets['getattr_function_args']==4 else 5
    c += f'reset();key_symbols=true;key_init[{source_at}]^=1U<<5;assert(calculate_function_key_callbacks()<0);\n'
    key_slot=offsets['key_callbacks']//8
    for i in range(3):
        c += f'reset();key_symbols=true;key_table[{key_slot+i}]=1;assert(calculate_function_key_callbacks()==-ENOENT);\n'
    c += f'reset();key_symbols=true;key_table[{key_slot+1}]=key_table[{key_slot+2}];assert(calculate_function_key_callbacks()==-ENOENT);\n'
    # 已证56字节之外即使存在正确组也不读取；紧邻不可访问页验证真正边界。
    c += 'reset();key_symbols=true;long page=sysconf(_SC_PAGESIZE);assert(page>0);void* guarded=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(guarded!=MAP_FAILED);\n'
    c += 'assert(!mprotect((char*)guarded+page,page,PROT_NONE));uintptr_t* bounded=(void*)((char*)guarded+page-56);memcpy(bounded,key_table,56);key_override=bounded;\n'
    c += 'assert(!calculate_function_key_callbacks());memset(bounded,0,56);assert(calculate_function_key_callbacks()==-ENOENT);assert(!munmap(guarded,2*page));key_override=NULL;\n'
    # 三项指针核对，包括CFI落点、未对齐及核心代码边界。
    for i in range(3):
        at=key_table[key_slot+i]
        c += f'reset();key_symbols=true;key_table[{key_slot+i}]+=1;assert(calculate_function_key_callbacks()==-ENOENT);\n'
        if at!=symbols[['user_preparse','user_free_preparse','generic_key_instantiate'][i]]:
            c += f'reset();key_symbols=true;*(u32*)(arena+{at}U)^=1U;assert(calculate_function_key_callbacks()==-ENOENT);\n'
    c += f'reset();key_symbols=true;key_table[{key_slot}]=(uintptr_t)(arena+{symbols["_etext"]}U);assert(calculate_function_key_callbacks()==-ENOENT);\n'
    c += 'reset();mode=1;key_symbols=true;assert(nm_prepare_control_layout()==-EINVAL&&!queries);\n'
    c += 'reset();mode=2;key_symbols=true;assert(nm_prepare_control_layout()==-ENODATA&&!queries);\n'
    c += 'reset();assert(nm_prepare_virtual_directory_abi()==-EOPNOTSUPP);\n'
    c += 'struct_offset.fillattr_abi=2;struct_offset.getattr_context_kind=0;struct_offset.file_inode_ops=-1;assert(nm_prepare_virtual_directory_abi()==-EINVAL);\n'
    c += f'struct_offset.file_inode_ops={offsets["file_inode_ops"]};assert(!nm_prepare_virtual_directory_abi());\n'
    c += 'struct_offset.fillattr_abi=3;assert(nm_prepare_virtual_directory_abi()==-EOPNOTSUPP);\n'
    c += 'struct_offset.fillattr_abi=2;struct_offset.getattr_context_kind=1;assert(nm_prepare_virtual_directory_abi()==-EOPNOTSUPP);\n'
    c += 'assert(!nm_prepare_topology_abi()&&!nm_prepare_backing_directory_abi());\n'
    for name in ['virtual_directory','topology','backing_directory']:
        c += f'reset();mode=1;assert(nm_prepare_{name}_abi()==-EINVAL&&!queries);\n'
        c += f'reset();mode=2;assert(nm_prepare_{name}_abi()==-ENODATA&&!queries);\n'
    c += 'assert(nm_find_complete_object_size(clear,9,0,1,0,8)==-EINVAL);\n'
    c += r'''
uintptr_t minimal[7]={0};minimal[6]=123;
assert(nm_find_file_callback(minimal,48,123,0,0)==-ENOENT);
assert(nm_find_file_callback(minimal,56,123,0,0)==48);
assert(nm_find_file_callback(minimal,55,123,0,0)==-EINVAL);
assert(nm_find_file_callback(minimal,4104,123,0,0)==-EINVAL);
assert(nm_find_file_callback(minimal,56,0,0,0)==-ENOENT);
assert(inst_is_ubfm(0x531D7048)&&!inst_get_ubfm_sf(0x531D7048));
assert(inst_get_ubfm_rn(0x531D7048)==2&&inst_get_ubfm_rd(0x531D7048)==8);
assert(inst_get_ubfm_immr(0x531D7048)==29&&inst_get_ubfm_imms(0x531D7048)==28);
assert(!inst_is_ubfm(0x331D7048)&&inst_get_ubfm_rn(0x331D7048)==-1);
free(arena);puts("PASS: 42 target fields, three common native ABI preparations and refusal boundaries");return 0;}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output / 'dynamic-preparation.c'
    path.write_text(c)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
               '-g', str(path), '-o', str(args.output / 'dynamic-preparation')]
    run = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    run = subprocess.run([str(args.output / 'dynamic-preparation')], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    files = ['nomount/nm_offsets.c', 'nomount/nm_structs.h', 'kpm_utils.h', 'nomount/nm_btf.c', 'nomount/nm_control_entry.c', 'nomount/nm_backing_inode.c', 'nomount/tools/test_dynamic_preparation.py']
    receipt = {'scope': 'Developer real target windows/tables with relocated addresses; partial directory/control and fresh base/inode stages; BTF routing fixture, no native calls or complete init proof',
               'image_sha256': reference['image_sha256'], 'kernel_sha256': reference['kernel_sha256'],
               'reference_sha256': sha(args.reference.read_bytes()), 'symbol_sha256': sha(args.symbols.read_bytes()),
               'sources': {name: sha((root / name).read_bytes()) for name in files},
               'evidence': evidence, 'table_sha256': sha(image[table_at:table_at+size]), 'directory_table_sha256':sha(image[dir_at:dir_at+size]),
               'derived': {name: offsets[name] for name in checked + ['name_hash_args'] + base_fields + storage_fields + callback_fields + control_fields + directory_fields + callback_fields_v6 + super_fields + ['key_callbacks']}, 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
