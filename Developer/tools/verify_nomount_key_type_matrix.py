#!/usr/bin/env python3
"""离线执行冻结候选的key_type探测器；BTF尺寸、函数命中与声明条件分别记录。"""
import argparse
import gzip
import importlib.util
import json
import re
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'nomount/tools'))
import inspect_target
from test_directory_abis import function
import derive_operation_tails as tails


def btf_types(raw):
    spec = importlib.util.spec_from_file_location('btf_host', ROOT / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    at = 0
    while True:
        at = raw.find(b'\x9f\xeb\x01\x00', at)
        if at < 0:
            return None
        try:
            header = struct.unpack_from('<HBBIIIII', raw, at)
            size = header[3] + header[6] + header[7]
            blob = raw[at:at + size]
            records, strings = host.index_btf(blob)
            result = {}
            for record in records[1:]:
                name, info, value = struct.unpack_from('<III', blob, record)
                if (info >> 24) & 31 != 4:
                    continue
                end = blob.index(b'\0', strings + name)
                name = blob[strings + name:end].decode()
                if name in ('file_operations', 'inode_operations', 'super_operations', 'dentry_operations', 'key_type'):
                    result[name] = {'size': value, 'btf_record_offset': record}
            if 'key_type' in result:
                return {'image_offset': at, 'types': result}
        except (AssertionError, KeyError, ValueError, struct.error, UnicodeError):
            pass
        at += 1


def config(raw):
    start = raw.find(b'IKCFG_ST')
    if start < 0:
        return None
    end = raw.index(b'IKCFG_ED', start + 8)
    text = gzip.decompress(raw[start + 8:end]).decode()
    return {key: key + '=y' in text.splitlines() for key in
            ('CONFIG_LOCKDEP', 'CONFIG_DEBUG_LOCK_ALLOC', 'CONFIG_GCC_PLUGIN_RANDSTRUCT')}


def common_source():
    src = (ROOT / 'nomount/nm_offsets.c').read_text()
    c = '''#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
static unsigned char* arena;
static unsigned long kallsyms_lookup_name_by_suffix(const char* name);
static unsigned long kallsyms_lookup_name(const char* name){return kallsyms_lookup_name_by_suffix(name);}
'''
    c += (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    c += (ROOT / 'nomount/nm_structs.h').read_text()
    c += src.split('// int保留', 1)[0].replace('__attribute__((section(".data.re_offsets"), used))', '')
    for name in ('nm_load', 'nm_store', 'nm_rule_entry_save', 'nm_move', 'nm_load_at', 'nm_move32', 'nm_add_at',
                 'nm_zero64', 'nm_store_at', 'nm_find_mutex_size', 'nm_compare',
                 'nm_find_key_preparse_data_legacy', 'nm_find_key_preparse_data',
                 'calculate_function_mutex_offsets', 'calculate_function_control_offsets',
                 'nm_page_address', 'nm_load_unscaled', 'nm_check_key_name_legacy', 'nm_find_key_registration',
                 'nm_check_key_name', 'nm_pair_store_at', 'nm_max_signed64', 'nm_find_key_callback_slot_legacy',
                 'nm_find_key_callback_slot', 'nm_code_matches', 'calculate_function_key_callbacks',
                 'nm_find_key_type_link_legacy', 'nm_find_key_type_link', 'calculate_function_key_type_size',
                 'nm_validate_control_layout'):
        c += function(src, name) + '\n'
    c += 'static int calculate_btf_control_layout(bool* unavailable){*unavailable=true;return -ENODATA;}\n'
    c += function(src, 'nm_prepare_control_layout') + '\n'
    return c


def relocate_key_prefix(raw, symbols, log, reference):
    """只在宿主副本还原已证56字节；基址由四组原生fops槽/回调关系交叉确认。"""
    ranges = re.findall(r'arm64 relocation table range: \[0x([0-9a-f]+), 0x([0-9a-f]+)\)', log)
    if not ranges:
        return raw, None, {'status': 'no relocation table needed'}
    start, end = map(lambda x: int(x, 16), ranges[0])
    assert 0 <= start < end <= len(raw) and (end - start) % 24 == 0
    entries = list(struct.iter_unpack('<QQQ', raw[start:end]))
    specs = [('llseek', 8, 'block_llseek'), ('open', reference['fop_open'], 'blkdev_open'),
             ('release', reference['fop_release'], 'blkdev_close'), ('mmap', reference['fop_mmap'], 'generic_file_mmap')]
    sets, evidence = [], []
    for field, slot, fn in specs:
        offsets = [v for n, v in symbols.items() if n == fn or n.startswith(fn + '.') or n.startswith(fn + '$')]
        target = symbols['def_blk_fops'] + slot
        differences = {target - offset for offset in offsets}
        candidates = {off - target for off, info, addend in entries
                      if info == 0x403 and off - addend in differences and (off - target) >> 48 == 0xffff
                      and (off - target) % 4096 == 0}
        sets.append(candidates)
        evidence.append({'field': field, 'slot': slot, 'candidates': [hex(x) for x in sorted(candidates)]})
    common = set.intersection(*sets)
    assert len(common) == 1, evidence
    base = common.pop()
    data = bytearray(raw)
    first, count = symbols['key_type_user'], 0
    for off, info, addend in entries:
        at = off - base
        if first <= at <= first + 48 and (at - first) % 8 == 0 and info & 0xffffffff in (0x101, 0x403):
            if info & 0xffffffff == 0x101:
                addend += base
            value = struct.unpack_from('<Q', data, at)[0]
            if value != addend:
                struct.pack_into('<Q', data, at, (value + addend) & ((1 << 64) - 1))
                count += 1
    return data, base, {'status': 'key prefix relocated', 'base': hex(base), 'range': [start, end],
                        'prefix': [first, first + 56], 'applied': count, 'base_evidence': evidence}


def function_probe(raw, symbols, out, common, native_base=None):
    def entry(name):
        if name in symbols:
            return symbols[name]
        found = [n for n in symbols if (n.startswith(name + '.') or n.startswith(name + '$'))
                 and not n.endswith('.cfi_jt')]
        return symbols[found[0]] if len(found) == 1 else None

    names = ('register_key_type', 'unregister_key_type', '__mutex_init', 'key_instantiate_and_link',
             'key_type_user', 'strcmp', 'down_write', '__list_del_entry_valid', 'user_preparse',
             'user_free_preparse', 'generic_key_instantiate', '_stext', '_etext', 'memset')
    selected = {n: entry(n) for n in names}
    windows = {'register_key_type': 23, 'unregister_key_type': 24, '__mutex_init': 10,
               'key_instantiate_and_link': 30, 'user_preparse': 13}
    if any(selected[n] is None for n in names if n != '__list_del_entry_valid'):
        return {'status': 'not-covered', 'missing': [n for n, at in selected.items() if at is None]}
    c = common
    c += 'static unsigned long kallsyms_lookup_name_by_suffix(const char* name){\n'
    c += ''.join(f'if(!strcmp(name,"{n}"))return (uintptr_t)(arena+{at}U);\n'
                 for n, at in selected.items() if at is not None)
    c += 'return 0;}\nint main(void){\n'
    c += f'arena=calloc(1,{len(raw)}U);assert(arena);\n'
    evidence = {}
    for name, count in windows.items():
        at = selected[name]
        words = struct.unpack_from('<' + 'I' * count, raw, at)
        evidence[name] = {'offset': at, 'words': list(words)}
        c += '{const u32 w[]={' + ','.join(map(str, words)) + f'}};memcpy(arena+{at}U,w,sizeof(w));}}\n'
    # 以已知llseek指针确定镜像重定位，只重定位key_type_user的已证56字节前缀。
    seek = [n for n in symbols if n.startswith('block_llseek') and n.endswith('.cfi_jt')]
    seek_at = symbols[seek[0]] if len(seek) == 1 else entry('block_llseek')
    seek_value = struct.unpack_from('<Q', raw, symbols['def_blk_fops'] + 8)[0]
    base = native_base if native_base is not None else (seek_value - seek_at if seek_value and seek_at is not None else None)
    values = struct.unpack_from('<7Q', raw, selected['key_type_user'])
    for index, value in enumerate(values):
        at = value - base if base is not None else -1
        if value and selected['_stext'] <= at <= selected['_etext'] - 4:
            c += f'((uintptr_t*)(arena+{selected["key_type_user"]}U))[{index}]=(uintptr_t)(arena+{at}U);\n'
            count = 2 if at <= selected['_etext'] - 8 else 1
            code = struct.unpack_from('<' + 'I' * count, raw, at)
            c += '{const u32 words[]={' + ','.join(map(str, code)) + f'}};memcpy(arena+{at}U,words,sizeof(words));}}\n'
        else:
            c += f'((uintptr_t*)(arena+{selected["key_type_user"]}U))[{index}]={value}ULL;\n'
    c += f'''struct_offset.key_type_size=struct_offset.key_callbacks=-1;
struct_offset.mutex_size=nm_find_mutex_size((void*)(arena+{selected['__mutex_init']}U));
struct_offset.mutex_no_lockdep=struct_offset.mutex_size>0?1:-1;
int callbacks=calculate_function_key_callbacks();
int link=nm_find_key_type_link((void*)(arena+{selected['unregister_key_type']}U),
kallsyms_lookup_name("down_write"),kallsyms_lookup_name("__list_del_entry_valid"));
int rc=calculate_function_key_type_size();
nm_owned_operation_fallback=true;int control=nm_prepare_control_layout();
printf("%d %d %d %d %d %d %d %d\\n",struct_offset.mutex_size,callbacks,struct_offset.key_callbacks,link,rc,struct_offset.key_type_size,control,struct_offset.key_preparse_data);
free(arena);return 0;}}\n'''
    (out / 'probe.c').write_text(c)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
               str(out / 'probe.c'), '-o', str(out / 'probe')]
    built = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    run = subprocess.run([str(out / 'probe')], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    mutex, callbacks, slot, link, rc, size, control, prep = map(int, run.stdout.split())
    return {'status': 'matched' if rc == 0 and callbacks == 0 and control == 0 else 'not-covered', 'mutex_size_or_error': mutex,
            'callbacks_rc': callbacks, 'callback_offset': slot, 'link_or_error': link,
            'extent_rc': rc, 'key_type_size': size, 'windows': evidence,
            'control_layout_rc': control, 'key_preparse_data': prep,
            'prefix_relocation': 'resolved' if base is not None else 'raw prefix; relocation base unavailable'}


def btf_probe(btf, out, common):
    names = ('file_operations', 'inode_operations', 'super_operations', 'dentry_operations', 'key_type')
    sizes = [btf['types'][n]['size'] for n in names]
    c = common.replace('static unsigned char* arena;', '')
    c += '''static unsigned long kallsyms_lookup_name_by_suffix(const char* name){return 0;}
struct btf_type{u32 size;};struct kpm_btf{int unused;};
static int nm_get_btf(struct kpm_btf* btf,bool* unavailable){*unavailable=false;return 0;}
static const struct btf_type* kpm_btf_type(struct kpm_btf* btf,const char* name,int kind){
assert(kind==4);static const struct btf_type types[]={'''
    c += ','.join('{' + str(n) + '}' for n in sizes) + '};\n'
    c += ''.join(f'if(!strcmp(name,"{name}"))return &types[{i}];\n' for i, name in enumerate(names))
    c += 'return NULL;}\n'
    c += function((ROOT / 'nomount/nm_btf.c').read_text(), 'calculate_btf_operation_sizes')
    c += '''int main(void){bool unavailable=true;int rc=calculate_btf_operation_sizes(&unavailable);
assert(!rc&&!unavailable);printf("%d\\n",struct_offset.key_type_size);return 0;}\n'''
    (out / 'btf-probe.c').write_text(c)
    built = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                            str(out / 'btf-probe.c'), '-o', str(out / 'btf-probe')], capture_output=True, text=True)
    (out / 'btf-compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    result = subprocess.check_output([str(out / 'btf-probe')], text=True)
    assert int(result) == sizes[-1]
    return {'rc': 0, 'key_type_size': int(result), 'scope': 'production size reader with decoded actual BTF records; host API fixture'}


def declared_extent(probe, image, cfg, out, llvm):
    if 'windows' not in probe or cfg is None or any(cfg.values()):
        return {'status': 'not-covered'}
    headers = {
        'B2N-416G_boot.img': 'local/nomount-control-20261013/native/v4.4/include/linux/key-type.h',
        'boot_los23.2.img': 'local/nomount-control-20261013/native/target/include/linux/key-type.h',
    }
    header = ROOT / headers.get(image, 'local/nomount-extension-20261015-01/source-headers-01/' + image + '/include/linux/key-type.h')
    if not header.exists():
        return {'status': 'missing-reference-header'}
    words = probe['windows']['unregister_key_type']['words']
    (out / 'unregister.S').write_text('entry:\n' + '\n'.join('.inst ' + hex(w) for w in words) + '\n')
    subprocess.run([str(llvm / 'aarch64-linux-android31-clang'), '-c', str(out / 'unregister.S'),
                    '-o', str(out / 'unregister.o')], check=True, capture_output=True)
    text = subprocess.check_output([str(llvm / 'llvm-objdump'), '-d', str(out / 'unregister.o')], text=True)
    (out / 'unregister.txt').write_text(text)
    code = ['\t'.join(line.split('\t')[1:]).split(' //')[0] for line in text.splitlines()
            if re.match(r'^\s*[0-9a-f]+:', line)]
    try:
        anchor = tails.link_slot(code)
        tail = tails.tail(header.read_text(), 'key_type', 'link', False, 64)
        size = (anchor['slot'] + tail['span'] + tail['alignment'] - 1) & -tail['alignment']
        return {'status': 'reference-contract', 'link': anchor['slot'], 'tail': tail,
                'size': size, 'header': str(header.relative_to(ROOT)), 'assembly': code,
                'boundary': 'verified visible anchor plus reference declaration; vendor appendages remain unproven'}
    except (AssertionError, ValueError) as error:
        return {'status': 'not-covered', 'reason': str(error), 'assembly': code}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true', required=True, help='明确选择kernel_img全部当前语料')
    parser.add_argument('--kptools', type=Path, required=True, help='Python提取器未覆盖时用官方只读dump')
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    common = common_source()
    rows = []
    for image in sorted((ROOT / 'kernel_img').iterdir()):
        if not image.is_file() or not (image.suffix == '.img' or image.name.startswith('kernel_')):
            continue
        out = args.output / image.name
        out.mkdir()
        unpacked = inspect_target.unpack_target(image)
        raw = unpacked.data
        row = {'image': image.name, 'kernel_release': unpacked.release, 'config': config(raw),
               'image_sha256': unpacked.source_sha256, 'kernel_sha256': unpacked.kernel_sha256}
        btf = btf_types(raw)
        if btf:
            row.update({'route': 'BTF', 'btf': btf, 'key_type_size': btf['types']['key_type']['size'],
                        'scope': 'actual target BTF type size; not a full module initialization result'})
            row['production_size_reader'] = btf_probe(btf, out, common)
        else:
            symbols, mode = inspect_target.kallsyms_extract.extract(raw)
            row.update({'route': 'function', 'symbol_mode': mode})
            if symbols is None:
                result = subprocess.run([str(args.kptools), '-d', '-i', str(image)], capture_output=True, text=True)
                (out / 'kptools.log').write_text(result.stdout + result.stderr)
                symbols = [(int(off, 16), kind, name) for off, kind, name in
                           re.findall(r'(?m)^0x([0-9a-f]+) ([A-Za-z]) (\S+)$', result.stdout)]
                row['symbol_fallback'] = {'tool': 'KernelPatch kptools dump', 'returncode': result.returncode,
                                          'count': len(symbols)}
            if symbols:
                symbols = {name: at for at, kind, name in symbols}
                refname = 'B2N-416G' if image.name == 'B2N-416G_boot.img' else image.name.removesuffix('.img')
                reference = json.loads((ROOT / 'local/nomount/configs' / (refname + '-v4.json')).read_text())
                assert reference['kernel_sha256'] == unpacked.kernel_sha256
                log = (out / 'kptools.log').read_text() if (out / 'kptools.log').exists() else ''
                prepared, base, relocation = relocate_key_prefix(raw, symbols, log, reference['offsets'])
                row['relocation'] = relocation
                row['probe'] = function_probe(prepared, symbols, out, common, base)
                row['declared_extent'] = declared_extent(row['probe'], image.name, row['config'], out, args.llvm_bin)
                if row['probe']['status'] == 'matched':
                    checks = {'mutex_size': 'mutex_size_or_error', 'key_callbacks': 'callback_offset',
                              'key_type_size': 'key_type_size', 'key_preparse_data': 'key_preparse_data'}
                    observed = {field: row['probe'][value] for field, value in checks.items()}
                    expected = {field: reference['offsets'][field] for field in checks}
                    assert observed == expected, (image.name, observed, expected)
                    assert row['declared_extent']['status'] == 'reference-contract'
                    assert row['declared_extent']['size'] == observed['key_type_size']
                    row['reference_comparison'] = {'status': 'matched', 'fields': observed,
                                                   'reference': 'local/nomount/configs/' + refname + '-v4.json'}

            else:
                row['probe'] = {'status': 'SKIP', 'reason': 'neither extractor covered the image'}
        rows.append(row)
        print(image.name, row['route'], row.get('key_type_size',
              {k: v for k, v in row.get('probe', {}).items() if k != 'windows'}), flush=True)
        (out / 'result.json').write_text(json.dumps(row, ensure_ascii=False, indent=2) + '\n')
    report = {'role': 'Developer', 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'scope': 'key_type/control cross-image development regression; no device operation', 'targets': rows}
    (args.output / 'matrix.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
