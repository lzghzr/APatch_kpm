#!/usr/bin/env python3
"""在既有VFS矩阵Oracle之后追加回调、末端锚点与对齐证据自检。"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ('kernel_mi8-4.9', 'kernel_mi9-4.14', 'kernel_mi10-4.19',
           'kernel_mi11-5.4', 'kernel_android12-5.10')
WINDOWS = {
    'kernel_mi8-4.9': {'__dentry_kill': (94, list(range(13)) + list(range(88, 94))),
                      'empty_dir_readdir': (27, list(range(8)) + list(range(15, 27))),
                      'vfs_getattr_nosec': (11, list(range(11))),
                      'set_posix_acl': (10, list(range(10))), 'super_cache_count': (17, list(range(17))),
                      'd_set_d_op': (44, list(range(44))), 'list_lru_count_node': (5, list(range(5)))},
    'kernel_mi9-4.14': {'__dentry_kill': (17, list(range(17))), 'empty_dir_readdir': (22, list(range(22))),
                       'vfs_getattr_nosec': (26, list(range(26))),
                       'set_posix_acl': (11, list(range(11))), 'super_cache_count': (19, list(range(19))),
                       'd_set_d_op': (45, list(range(45))), 'list_lru_count_node': (5, list(range(5)))},
    'kernel_mi10-4.19': {'__dentry_kill': (17, list(range(17))), 'empty_dir_readdir': (22, list(range(22))),
                       'vfs_getattr_nosec': (26, list(range(26))),
                       'set_posix_acl': (11, list(range(11))), 'super_cache_count': (19, list(range(19))),
                       'd_set_d_op': (45, list(range(45))), 'list_lru_count_node': (5, list(range(5)))},
    'kernel_mi11-5.4': {'__dentry_kill': (24, list(range(24))), 'empty_dir_readdir': (30, list(range(30))),
                      'vfs_getattr_nosec': (47, list(range(47))),
                      'set_posix_acl': (12, list(range(12))), 'super_cache_count': (26, list(range(26))),
                      'd_set_d_op': (45, list(range(45))), 'list_lru_count_node': (5, list(range(5)))},
    'kernel_android12-5.10': {'__dentry_kill': (27, list(range(27))), 'empty_dir_readdir': (31, list(range(31))),
                            'vfs_getattr_nosec': (42, list(range(42))),
                            'set_posix_acl': (16, list(range(16))), 'super_cache_count': (27, list(range(27))),
                            'd_set_d_op': (47, list(range(47))), 'list_lru_count_node': (7, list(range(7)))}
}

for target in TARGETS:
    size = 11 if target == TARGETS[4] else 9 if target == TARGETS[3] else 8
    WINDOWS[target]['simple_getattr'] = (size, list(range(size)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', nargs='+', choices=TARGETS, required=True)
    parser.add_argument('--corpus-root', type=Path, default=ROOT)
    parser.add_argument('--kptools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    subprocess.run([sys.executable, str(ROOT / 'Developer/tools/verify_nomount_vfs_matrix.py'),
                    '--images', *args.images, '--corpus-root', str(args.corpus_root.resolve()),
                    '--kptools', str(args.kptools.resolve()), '--output', str(args.output / 'original')], check=True)
    matrix = json.loads((args.output / 'original/matrix.json').read_text())
    fields = re.findall(r'int16_t\s+(\w+)\s*;', (ROOT / 'nomount/nm_offsets.c').read_text().split('};', 1)[0])
    covered = [f for f in fields if f not in ('inode_ops_size', 'super_ops_size', 'dentry_ops_size')]
    receipts = []
    for name in args.images:
        out = args.output / 'original' / name
        symbols = json.loads((out / 'symbols.json').read_text())
        raw = (out / 'Image').read_bytes()
        ref = json.loads((ROOT / 'local/nomount/configs' / (name + '-v4.json')).read_text())
        offsets = ref['offsets']
        def address(fn):
            return symbols[fn] if fn in symbols else symbols[next(n for n in symbols if (
                n.startswith(fn + '.') or n.startswith(fn + '$')) and not n.endswith('.cfi_jt'))]
        source = (out / 'probe.c').read_text()
        # Append the direct d_set_d_op fixture binding to both old lookup implementations.
        for lookup in ('kallsyms_lookup_name', 'kallsyms_lookup_name_by_suffix'):
            needle = f'static unsigned long {lookup}(const char* name){{\n'
            source = source.replace(needle, needle + ''.join(f'if(!strcmp(name,"{fn}"))return (uintptr_t)(arena+{address(fn)}U);\n' for fn in ('d_set_d_op','list_lru_count_node')), 1)
        extra = ''.join(f'assert(struct_offset.{f}=={offsets[f]});\n' for f in covered)
        checks = {
            '__dentry_kill': 'nm_find_dentry_lifecycle(code,kallsyms_lookup_name_by_suffix("lockref_mark_dead"),start,end)',
            'empty_dir_readdir': 'nm_find_directory_actor(code)',
            'vfs_getattr_nosec': 'nm_find_getattr_layout(code,(void*)kallsyms_lookup_name_by_suffix("simple_getattr"),kallsyms_lookup_name_by_suffix("generic_fillattr"))',
            'simple_getattr': ('nm_check_inline_simple_getattr(code,(void*)kallsyms_lookup_name_by_suffix("generic_fillattr"))' if name == TARGETS[4] else 'nm_check_simple_getattr(code,kallsyms_lookup_name_by_suffix("generic_fillattr"),'+('false' if name == TARGETS[0] else 'true')+')'),
            'set_posix_acl': 'nm_find_set_acl_vfs(code)', 'super_cache_count': 'nm_find_super_cache_vfs(code)',
            'd_set_d_op': 'nm_find_dentry_real(code)', 'list_lru_count_node': 'nm_find_operation_alignment(code)'}
        # This lookup is needed only for direct evidence when the complete size path refuses before reaching it.
        anchor_values = {}
        mutant_count = 0
        for fn, (count, indices) in WINDOWS[name].items():
            at = address(fn)
            start_end = ('uintptr_t start=(uintptr_t)arena,end=(uintptr_t)arena+' + str(len(raw)) + ';') if fn == '__dentry_kill' else ''
            check = checks[fn]
            if fn == 'simple_getattr':
                expected = 0
            elif fn == 'd_set_d_op':
                expected = ref['size_derivation']['dentry_ops_size']['slot']
            elif fn == 'set_posix_acl':
                expected = ref['size_derivation']['inode_ops_size']['slot']
            elif fn == 'super_cache_count':
                expected = ref['size_derivation']['super_ops_size']['slot']
            elif fn == 'list_lru_count_node':
                expected = ref['size_derivation']['inode_ops_size']['alignment']
            else:
                expected = 0
            extra += f'{{u32* code=(void*)(arena+{at});{start_end}assert({check}=={expected});\n'
            words = struct.unpack_from('<' + 'I' * count, raw, at)
            for i in indices:
                for mutant in (0xd503201f, 0xc8137c83):
                    if words[i] == mutant:
                        continue
                    extra += f'{{u32 saved=code[{i}];code[{i}]={mutant}U;int result={check};code[{i}]=saved;'
                    extra += f'if(result>=0){{fprintf(stderr,"accepted {fn}[{i}] {mutant} rc=%d\\n",result);return 4;}}}}\n'
                    mutant_count += 1
            extra += '}\n'
            anchor_values[fn] = expected
        # Guard every new contiguous prefix. The GCC dentry jump remains inside its own 94-word region.
        for fn, (count, _) in WINDOWS[name].items():
            at = address(fn)
            expected = anchor_values[fn]
            extra += f'''{{u32* original=(void*)(arena+{at});u32* code=(void*)(pages+page-{count}*4);
assert(!mprotect(pages,page,PROT_READ|PROT_WRITE));memcpy(code,original,{count}*4);
'''
            if fn == '__dentry_kill':
                extra += 'uintptr_t start=(uintptr_t)code,end=(uintptr_t)(pages+page);'
            # Original old fixture unmapped pages; allocate fresh for this appended group below.
            if fn == '__dentry_kill':
                extra += 'override_value=kallsyms_lookup_name_by_suffix("lockref_mark_dead")+(uintptr_t)code-(uintptr_t)original;override_name="lockref_mark_dead";'
            elif fn == 'vfs_getattr_nosec' and name in TARGETS[1:4]:
                extra += 'override_value=kallsyms_lookup_name_by_suffix("memset")+(uintptr_t)code-(uintptr_t)original;override_name="memset";'
            elif fn == 'simple_getattr' and name != TARGETS[4]:
                extra += 'override_value=kallsyms_lookup_name_by_suffix("generic_fillattr")+(uintptr_t)code-(uintptr_t)original;override_name="generic_fillattr";'
            elif fn == 'super_cache_count' and name == 'kernel_mi11-5.4':
                extra += 'override_value=kallsyms_lookup_name_by_suffix("__cfi_slowpath")+(uintptr_t)code-(uintptr_t)original;override_name="__cfi_slowpath";'
            extra += f'assert({checks[fn]}=={expected});override_name=NULL;}}\n'
        # The reference tail is a static input, not runtime proof: demonstrate indistinguishable used offsets.
        extra += '''struct plain_tail {void* prefix[14];void* used[7];} __attribute__((aligned(64)));
struct reserved_tail {void* prefix[14];void* used[7];u64 reserve[4];} __attribute__((aligned(64)));
assert(offsetof(struct plain_tail,used)==offsetof(struct reserved_tail,used));
assert(sizeof(struct plain_tail)==192&&sizeof(struct reserved_tail)==256);
'''
        if name in ('kernel_mi10-4.19', 'kernel_mi11-5.4'):
            extra += '''assert(!nm_prepare_operation_sizes());
assert(struct_offset.inode_ops_size==256&&struct_offset.super_ops_size==272&&struct_offset.dentry_ops_size==192);
'''
            extra += ('assert(nm_operation_anchor==NM_OPERATION_ANCHOR_SDCARDFS);\n' if name == 'kernel_mi10-4.19'
                      else 'assert(nm_operation_anchor==NM_OPERATION_ANCHOR_D_REAL);\n')
        else:
            extra += '''assert(nm_prepare_operation_sizes()<0);
assert(struct_offset.inode_ops_size==-1&&struct_offset.super_ops_size==-1&&struct_offset.dentry_ops_size==-1);
'''
        extra += '''{struct struct_offset saved=struct_offset;
struct_offset.iop_getattr=112;struct_offset.sop_drop_inode=40;struct_offset.sop_evict_inode=48;
struct_offset.dop_init=40;struct_offset.dop_release=48;
struct_offset.inode_ops_size=struct_offset.super_ops_size=struct_offset.dentry_ops_size=-1;
assert(nm_set_operation_extents_real(160,232,96)==-EOPNOTSUPP);
assert(nm_set_operation_extents(160,224,104)==-EOPNOTSUPP);
struct_offset.dop_init+=8;assert(nm_set_operation_extents_real(160,224,96)==-EOPNOTSUPP);
assert(struct_offset.inode_ops_size==-1&&struct_offset.super_ops_size==-1&&struct_offset.dentry_ops_size==-1);
struct_offset=saved;}
assert(!munmap(pages,2*page));
'''
        marker = 'free(arena);return 0;}'
        assert source.count(marker) == 1
        # Existing guards clean up their pages, so append a fresh mapping without changing old assertions.
        setup = 'pages=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(pages!=MAP_FAILED&&!mprotect(pages+page,page,PROT_NONE));\n'
        source = source.replace(marker, setup + extra + marker)
        path = out / 'completion.c'
        path.write_text(source)
        compiled = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function',
                                   '-fsanitize=address,undefined', '-g', str(path), '-o', str(out / 'completion')], capture_output=True, text=True)
        (out / 'completion-compile.log').write_text(compiled.stdout + compiled.stderr)
        if compiled.returncode:
            print(compiled.stderr[:1500], flush=True)
            compiled.check_returncode()
        run = subprocess.run([str(out / 'completion'), str(out / 'Image')], capture_output=True, text=True)
        (out / 'completion.log').write_text(run.stdout + run.stderr)
        if run.returncode:
            print(run.stderr + run.stdout[-700:], flush=True)
            run.check_returncode()
        verified = fields if name in ('kernel_mi10-4.19', 'kernel_mi11-5.4') else covered
        receipts.append({'image': name, 'verified_fields': {f: offsets[f] for f in verified},
                         'instruction_mutants': mutant_count, 'guard_windows': len(WINDOWS[name]),
                         'anchors': anchor_values, 'uncovered': ([] if name in ('kernel_mi10-4.19', 'kernel_mi11-5.4') else ['inode_ops_size', 'super_ops_size', 'dentry_ops_size']),
                         'static_size_evidence': ref['size_derivation'],
                         'windows': {fn: {'offset': address(fn), 'words': list(struct.unpack_from('<'+'I'*n, raw, address(fn))),
                                          'consumed_indices': indices} for fn, (n, indices) in WINDOWS[name].items()}})
        print(name, len(verified), 'verified;', mutant_count, 'new mutants;', len(WINDOWS[name]), 'new guards', flush=True)
    (args.output / 'completion.json').write_text(json.dumps({'role': 'Developer', 'source_commit': matrix['source_commit'],
        'source_dirty': matrix['source_dirty'], 'scope': 'callback preparation, bounded anchors and joint size contracts; mi10/mi11 accept, other selected targets retain refusal',
        'targets': receipts}, indent=2) + '\n')


if __name__ == '__main__':
    main()
