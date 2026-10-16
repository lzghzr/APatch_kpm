#!/usr/bin/env python3
"""Developer 离线分析：从目标末端访问取得起点，只参考声明的尾部计算尺寸。"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(text):
    match = re.fullmatch(r'ldr\s+x(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+))?\]', text)
    return tuple([int(match[1]), int(match[2]), int(match[3] or '0', 0)]) if match else None


def chained_slot(code, object_slot, container=False):
    found = []
    for i, text in enumerate(code):
        first = load(text)
        if not first or first[2] != object_slot:
            continue
        if container:
            pattern = rf'sub\s+x{first[1]}, x0, #0x[0-9a-f]+'
            if not any(re.fullmatch(pattern, line) for line in code[:i]):
                continue
        elif first[1] != 0:
            continue
        for j in range(i + 1, min(i + 4, len(code) - 1)):
            second = load(code[j])
            if not second or second[1] != first[0]:
                continue
            if not re.match(rf'cbz\s+x{second[0]}, ', code[j + 1]):
                continue
            # 间隔只允许不改操作表寄存器的参数保存或空指针前向判断。
            gap = code[i+1:j]
            if any(not (re.fullmatch(r'mov\s+x(?:19|20), x[01]', line)
                        or re.match(rf'cbz\s+x{first[0]}, ', line)) for line in gap):
                continue
            found.append({'slot': second[2], 'table_load_index': i, 'member_load_index': j})
    assert len(found) == 1, found
    return found[0]


def real_slot(code):
    found = []
    for i in range(len(code) - 4):
        first = load(code[i])
        if not first or first[1] != 1:
            continue
        if (re.match(rf'cbz\s+x{first[0]}, ', code[i+1])
                and code[i+2] == f'ldr\tw{first[0]}, [x0]'
                and code[i+3] == f'orr\tw{first[0]}, w{first[0]}, #0x4000000'
                and code[i+4] == f'str\tw{first[0]}, [x0]'):
            found.append({'slot': first[2], 'member_load_index': i, 'flag': 'DCACHE_OP_REAL'})
    assert len(found) == 1, found
    return found[0]


def link_slot(code):
    found = []
    for i, text in enumerate(code):
        match = re.fullmatch(r'add\s+x(\d+), x(\d+), #(0x[0-9a-f]+)', text)
        if not match:
            continue
        result, base, offset = int(match[1]), int(match[2]), int(match[3], 0)
        if not 19 <= base <= 28 or not any(line == f'mov\tx{base}, x0' for line in code[:i]):
            continue
        # list_del_init写回同一节点的next/prev；不取相邻符号间距。
        if all(f'str\tx{result}, [x{base}, #{hex(at)}]' in code[i+1:]
               for at in (offset, offset + 8)):
            found.append({'slot': offset, 'member_address_index': i, 'base_register': base})
    assert len(found) == 1, found
    return found[0]


def structure(text, name):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    match = re.search(r'\bstruct\s+' + name + r'\s*\{', text)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.end():end-1], text[end:text.index(';', end)]


def tail(text, name, member, reserve_enabled, cache_alignment):
    body, attributes = structure(text, name)
    # 丢弃锚点之前的声明，整份结构体的offsetof/sizeof不参与计算。
    member_line = re.search(r'(?m)^[ \t]*[^;{}#\n]*\(\*' + member + r'\)', body)
    if not member_line:
        member_line = re.search(r'(?m)^[ \t]*struct list_head\s+' + member + r'\s*;', body)
    assert member_line, (name, member)
    fragment = body[member_line.start():]
    plain = re.sub(r'(?m)^[ \t]*[^#;{}\n]+?\(\*\s*(\w+)\s*\)\s*\([^;]*?\)\s*;',
                   lambda m: 'pointer ' + m[1] + ';', fragment)
    fields = []
    for declaration in plain.split(';'):
        declaration = declaration.strip()
        if not declaration:
            continue
        if re.fullmatch(r'pointer \w+', declaration):
            fields.append({'declaration': declaration, 'bytes': 8})
        elif re.fullmatch(r'ANDROID_KABI_RESERVE\(\d+\)', declaration):
            fields.append({'declaration': declaration, 'bytes': 8 if reserve_enabled else 0})
        elif re.fullmatch(r'struct list_head\s+link', declaration):
            fields.append({'declaration': declaration, 'bytes': 16})
        elif re.fullmatch(r'struct lock_class_key\s+lock_class', declaration):
            fields.append({'declaration': declaration, 'bytes': 0})
        else:
            raise ValueError(f'尚未覆盖的尾部声明: {declaration}')
    assert fields
    return {'member': member, 'fragment': fragment.strip(), 'fields': fields,
            'span': sum(item['bytes'] for item in fields),
            'alignment': cache_alignment if '____cacheline_aligned' in attributes else 8}


def disassemble(raw, symbols, out, llvm_bin):
    windows = {'set_posix_acl': 16, 'super_cache_count': 32, 'd_set_d_op': 48, 'unregister_key_type': 24}
    marks, lines, cursor = [], [], 0
    for name, count in windows.items():
        actual = name if name in symbols else next(n for n in symbols if (n.startswith(name+'$') or n.startswith(name+'.')) and not n.endswith('.cfi_jt'))
        at = symbols[actual]
        words = struct.unpack_from('<' + 'I' * count, raw, at)
        lines.append(f'entry_{cursor}:')
        lines.extend('.inst ' + hex(word) for word in words)
        marks.append((name, actual, at, cursor, count, words))
        cursor += count
    source = out / 'windows.S'
    source.write_text('\n'.join(lines) + '\n')
    subprocess.run([str(llvm_bin/'aarch64-linux-android31-clang'), '-c', str(source), '-o', str(out/'windows.o')], check=True, capture_output=True)
    text = subprocess.check_output([str(llvm_bin/'llvm-objdump'), '-d', str(out/'windows.o')], text=True)
    (out/'disassembly.txt').write_text(text)
    instructions = [line for line in text.splitlines() if re.match(r'^\s*[0-9a-f]+:', line)]
    result = {}
    for name, actual, at, start, count, words in marks:
        code = ['\t'.join(line.split('\t')[1:]).split(' //')[0] for line in instructions[start:start+count]]
        assert len(code) == count
        result[name] = {'symbol': actual, 'offset': at, 'words': words, 'assembly': code}
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'config', 'headers', 'support', 'llvm-bin', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    raw = a.image.read_bytes()
    config = json.loads(a.config.read_text())
    assert digest(raw) == config['kernel_sha256'] == config['image_sha256']
    start, end = raw.index(b'IKCFG_ST') + 8, raw.index(b'IKCFG_ED')
    ikconfig = gzip.decompress(raw[start:end]).decode()
    assert digest(ikconfig.encode()) == config['config_sha256']
    assert 'CONFIG_LOCKDEP=y' not in ikconfig and 'CONFIG_DEBUG_LOCK_ALLOC=y' not in ikconfig
    lockdep = '\n'.join(file.read_text() for file in a.support.glob('lockdep*.h'))
    assert re.search(r'struct lock_class_key\s*\{\s*\}', lockdep)
    assert '#ifdef CONFIG_LOCKDEP' in lockdep and '#else' in lockdep
    cache = (a.support/'include/linux/cache.h').read_text()
    arch_cache = (a.support/'arch/arm64/include/asm/cache.h').read_text()
    shift = re.search(r'#define L1_CACHE_SHIFT\s+\(?(\d+)\)?', arch_cache)
    assert shift and int(shift[1]) in (6, 7)
    cache_alignment = 1 << int(shift[1])
    assert '#define SMP_CACHE_BYTES L1_CACHE_BYTES' in cache
    assert re.search(r'#define ____cacheline_aligned\s+__attribute__\(\(__aligned__\(SMP_CACHE_BYTES\)\)\)', cache)
    fs = (a.headers/'include/linux/fs.h').read_text()
    dcache = (a.headers/'include/linux/dcache.h').read_text()
    key = (a.headers/'include/linux/key-type.h').read_text()
    reserve = False
    if 'ANDROID_KABI_RESERVE' in fs:
        macros = next(file for file in [a.headers/'android_kabi.h', a.headers/'macro-reference/include/linux/android_kabi.h'] if file.exists()).read_text()
        assert re.search(r'#define _ANDROID_KABI_RESERVE\(n\)\s+u64 android_kabi_reserved##n', macros)
        reserve = 'CONFIG_ANDROID_KABI_RESERVE' not in macros or 'CONFIG_ANDROID_KABI_RESERVE=y' in ikconfig
    symbols = {name: at for at, kind, name in json.loads(a.symbols.read_text())}
    a.output.mkdir(parents=True, exist_ok=False)
    windows = disassemble(raw, symbols, a.output, a.llvm_bin)
    anchors = {'inode_ops_size': chained_slot(windows['set_posix_acl']['assembly'], 32),
               'super_ops_size': chained_slot(windows['super_cache_count']['assembly'], 48, True),
               'dentry_ops_size': real_slot(windows['d_set_d_op']['assembly']),
               'key_type_size': link_slot(windows['unregister_key_type']['assembly'])}
    specs = [('inode_ops_size', fs, 'inode_operations', 'set_acl'),
             ('super_ops_size', fs, 'super_operations', 'nr_cached_objects'),
             ('dentry_ops_size', dcache, 'dentry_operations', 'd_real'),
             ('key_type_size', key, 'key_type', 'link')]
    derived = {}
    for field, source, typename, member in specs:
        item = tail(source, typename, member, reserve, cache_alignment)
        offset = anchors[field]['slot']
        assert offset >= 0 and offset % 8 == 0
        size = (offset + item['span'] + item['alignment'] - 1) & -item['alignment']
        assert 0 < size <= 4096
        item.update(anchors[field], size=size)
        derived[field] = item
        config['offsets'][field] = size
    config.pop('reference_values', None)
    config.pop('unconfirmed_fields', None)
    config.pop('review_status', None)
    config['size_derivation'] = {name: {key: value for key, value in item.items() if key in ('member', 'slot', 'span', 'alignment', 'size')} for name, item in derived.items()}
    config['reference_scope'] = 'Target instruction/table evidence provides field positions and complete copy lengths; declarations provide only verified post-anchor tails and alignment'
    (a.output/'config.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    receipt = {'scope': 'Developer offline anchors and declared tails; not runtime discovery, independent audit or native execution',
               'kernel_sha256': digest(raw), 'symbol_input_sha256': digest(a.symbols.read_bytes()),
               'derived': derived, 'windows': windows, 'reserve_enabled': reserve,
               'lockdep_enabled': False, 'whole_reference_type_size_used': False}
    (a.output/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(config['target'], {field: item['size'] for field, item in derived.items()})


if __name__ == '__main__':
    main()
