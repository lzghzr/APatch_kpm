#!/usr/bin/env python3
"""Offline symbol-gap experiments and a source-typed sample census; never patch images."""
import argparse
import collections
import json
from pathlib import Path
import re
import struct
import subprocess

TARGETS = ('kernel_mi8-4.9', 'kernel_mi9-4.14', 'kernel_mi10-4.19',
           'kernel_mi11-5.4', 'kernel_android12-5.10')
TYPES = ('inode_operations', 'super_operations', 'dentry_operations')


def elf_symbols(path):
    """Read ELF64 little-endian SYMTAB st_size independently of nm formatting."""
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', data, 18)[0] == 183  # AArch64
    off = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * size)
                for i in range(count)]
    names = sections[strings]
    namebytes = data[names[4]:names[4] + names[5]]
    def cstr(blob, start):
        return blob[start:blob.index(b'\0', start)].decode()
    result = {}
    for sec in sections:
        if sec[1] != 2:
            continue
        strs = sections[sec[6]]
        blob = data[strs[4]:strs[4] + strs[5]]
        for pos in range(sec[4], sec[4] + sec[5], sec[9]):
            name, info, other, idx, value, extent = struct.unpack_from('<IBBHQQ', data, pos)
            if name and idx and idx < len(sections):
                result[cstr(blob, name)] = dict(address=value, size=extent,
                    type=info & 15, section=cstr(namebytes, sections[idx][0]))
    return result


def fixtures(args):
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    commands = []
    def run(argv):
        p = subprocess.run([str(x) for x in argv], text=True, capture_output=True)
        commands.append(dict(argv=[Path(str(x)).name if str(x).startswith(str(args.toolchain))
                                    else str(x).replace(str(out), '<output>') for x in argv],
                             returncode=p.returncode, diagnostics=p.stderr))
        if p.returncode:
            raise RuntimeError(p.stderr)
        return p.stdout
    cc, ld = args.toolchain / 'aarch64-linux-android31-clang', args.toolchain / 'ld.lld'
    (out / 'layout.ld').write_text('SECTIONS { . = 0x10000; .text : { *(.text*) } '
        '.rodata : { *(.rodata*) } . = ALIGN(4096); .data : { *(.data*) } '
        '.bss : { *(.bss*) } /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) } }\n')
    (out / 'layout.c').write_text('''
#define U __attribute__((used))
struct plain { unsigned long slot[17]; };
static const struct plain tight0 U = {{1}}, tight1 U = {{2}}, tight2 U = {{3}};
static const struct plain pad0 U __attribute__((aligned(64))) = {{4}};
static const struct plain pad1 U __attribute__((aligned(64))) = {{5}};
static const struct plain pad2 U __attribute__((aligned(64))) = {{6}};
const struct plain original U = {{7}};
extern const struct plain alias __attribute__((alias("original")));
static const int merge0[4] U = {11,12,13,14};
static const int merge1[4] U = {11,12,13,14};
static int removed = 17;
static int kept U = 18;
static int leaf(int x) { return x+1; }
static int (*const callbacks[])(int) U = {leaf};
int invoke(int (*fn)(int), int x) { return fn(x); }
''')
    variants = {'plain': [], 'merge': ['-fmerge-constants'],
                'merge_all': ['-fmerge-all-constants'], 'lto': ['-flto'],
                'cfi': ['-flto', '-fsanitize=cfi-icall', '-fvisibility=hidden']}
    results = {}
    for name, flags in variants.items():
        obj, exe = out / (name + '.o'), out / (name + '.elf')
        run([cc, '-O2', '-ffreestanding', *flags, '-c', out / 'layout.c', '-o', obj])
        run([ld, '-T', out / 'layout.ld', '-e', 'invoke', obj, '-o', exe])
        results[name] = elf_symbols(exe)
    (out / 'interior.S').write_text('''
.section .rodata,"a",@progbits
.global container
.type container,@object
container:
.zero 8
.global interior
interior:
.zero 56
.size container,64
.type after,@object
after:
.zero 8
.size after,8
.section .data,"aw",@progbits
.type writable,@object
writable:
.zero 8
.size writable,8
.section .rodata.str1.1,"aMS",@progbits,1
.type merged_string0,@object
merged_string0:
.asciz "identical"
.size merged_string0,10
.type merged_string1,@object
merged_string1:
.asciz "identical"
.size merged_string1,10
''')
    run([cc, '-c', out / 'interior.S', '-o', out / 'interior.o'])
    run([ld, '-T', out / 'layout.ld', '-e', 'container', out / 'interior.o',
         '-o', out / 'interior.elf'])
    results['interior'] = elf_symbols(out / 'interior.elf')
    (out / 'random.c').write_text('''
struct __attribute__((randomize_layout)) random { char a; long b; int c; char d; long e; };
struct random object __attribute__((used));
char offset_probe[__builtin_offsetof(struct random, b)+1] __attribute__((used));
''')
    for seed in range(4):
        obj = out / ('random%d.o' % seed)
        run([cc, '-O2', '-ffreestanding', '-frandomize-layout-seed=' + str(seed),
             '-c', out / 'random.c', '-o', obj])
        results['random%d' % seed] = elf_symbols(obj)
    checks = []
    def check(name, condition, measured):
        assert condition, (name, measured)
        checks.append(dict(name=name, passed=True, measured=measured))
    plain = results['plain']
    tight = [plain['tight%d' % i]['address'] for i in range(3)]
    padded = [plain['pad%d' % i]['address'] for i in range(3)]
    tg = [b-a for a,b in zip(tight, tight[1:])]
    pg = [b-a for a,b in zip(padded, padded[1:])]
    check('tight_gap_equals_size', tg == [136,136], dict(size=136,gaps=tg))
    check('identical_padding_is_not_size', pg == [192,192] and plain['pad0']['size']==136,
          dict(size=plain['pad0']['size'], gaps=pg))
    check('alias_zero_gap', plain['alias']['address']==plain['original']['address'],
          dict(size=plain['original']['size'],gap=plain['alias']['address']-plain['original']['address']))
    interior = results['interior']
    gap = interior['interior']['address'] - interior['container']['address']
    check('strictly_greater_interior_symbol_breaks_bound', gap==8 and interior['container']['size']==64,
          dict(size=64,gap=gap))
    gap = interior['writable']['address'] - interior['after']['address']
    check('section_transition_loose_bound', gap>interior['after']['size'], dict(size=8,gap=gap))
    for name in variants:
        r=results[name]
        check(name+'_named_objects_survive', all(x in r for x in ('pad0','pad1','pad2','kept','callbacks')),
              {x:r[x] for x in ('pad0','pad1','pad2','callbacks')})
        check(name+'_unused_symbol_absent', 'removed' not in r, dict(present='removed' in r))
        check(name+'_const_merge_observation', 'merge0' in r and 'merge1' in r,
              dict(merged=r['merge0']['address']==r['merge1']['address'], size=r['merge0']['size']))
    check('mergeable_section_aliases', interior['merged_string0']['address']==interior['merged_string1']['address'],
          dict(size=10,gap=interior['merged_string1']['address']-interior['merged_string0']['address']))
    check('lto_can_remove_alias_name', 'alias' not in results['lto'] and 'alias' in plain,
          dict(plain_alias=True,lto_alias=False))
    check('cfi_function_entry_differs_from_body',
          results['cfi']['leaf']['address']!=results['cfi']['leaf.cfi']['address'],
          dict(entry=results['cfi']['leaf'],body=results['cfi']['leaf.cfi']))
    offsets=[results['random%d'%i]['offset_probe']['size']-1 for i in range(4)]
    check('randomize_layout_changes_member_offset', len(set(offsets))>1, dict(offsets=offsets))
    receipt=dict(scope='AArch64 ELF offline fixtures; no ARM execution',
                 checks=checks, symbols=results, commands=commands,
                 compiler=run([cc,'--version']).splitlines()[0], linker=run([ld,'--version']).strip())
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(checks=len(checks),output=str(out/'receipt.json'))))


def base_name(name):
    return name.split('.llvm.')[0]


def census(args):
    anchors = json.loads(args.anchors.read_text())['completion']['targets']
    anchors = {t['image']:t['anchors'] for t in anchors}
    manifest = json.loads((args.sources/'manifest.json').read_text())
    result = dict(scope='five selected targets; source-declared cohort plus name census',
                  anchor_source_commit='2f03b2e490a1f3c4ee0768d9e73eb891ffeb3ae8',
                  sources=manifest, targets=[])
    # Generic TU-local names such as anon_ops cannot be assigned a C type by name alone.
    qualified = re.compile(r'^(?:shmem|simple|empty_dir|fuse|ovl|debugfs|tracefs|securityfs|pid|pipefs|tid|proc)_')
    declaration = re.compile(r'\bstruct\s+(\w+)\s+(\w+)\s*(?:__\w+\s*)?=\s*\{')
    for target in TARGETS:
        rows = [(int(a,16),kind,name) for a,kind,name in re.findall(
            r'^0x([0-9a-f]+) ([A-Za-z]) (\S+)$',
            (args.symbols/target/'symbols.log').read_text(),re.M)]
        by_addr = collections.defaultdict(list)
        for addr,kind,name in rows:
            by_addr[addr].append(dict(name=name,kind=kind))
        addresses = sorted(by_addr)
        successor = dict(zip(addresses,addresses[1:]))
        declarations = collections.defaultdict(list)
        for path in sorted((args.sources/target).rglob('*.c')):
            text=path.read_text()
            for m in declaration.finditer(text):
                declarations[m[2]].append(dict(type=m[1],file=str(path.relative_to(args.sources/target)),
                    line=text[:m.start()].count('\n')+1))
        a=anchors[target]
        alignment=a['list_lru_count_node']
        lowers={TYPES[0]:((a['set_posix_acl']+8+alignment-1)//alignment)*alignment,
                TYPES[1]:a['super_cache_count']+16,
                TYPES[2]:((a['d_set_d_op']+8+alignment-1)//alignment)*alignment}
        tables=[]
        for typ in TYPES:
            samples=[]; name_only=[]
            for addr,kind,name in rows:
                if kind.lower() not in ('r','d') or addr not in successor:
                    continue
                norm=base_name(name); next_addr=successor[addr]
                row=dict(name=name,address=addr,kind=kind,gap=next_addr-addr,
                         next_address=next_addr,next_symbols=by_addr[next_addr])
                if norm.endswith(typ) and not norm.startswith('__'):
                    name_only.append(row)
                decl=[d for d in declarations.get(norm,[]) if d['type']==typ]
                if not decl or not qualified.match(norm):
                    continue
                # A bound witness must end at another independent declared struct object.
                next_decl=[dict(symbol=n['name'],declarations=declarations[base_name(n['name'])])
                           for n in by_addr[next_addr] if base_name(n['name']) in declarations]
                row.update(declarations=decl, next_declarations=next_decl)
                samples.append(row)
            witnesses=[s for s in samples if s['next_declarations']]
            if not witnesses:
                raise RuntimeError((target,typ,'no typed bound witness'))
            upper=min(s['gap'] for s in witnesses); lower=lowers[typ]
            assert lower<=upper
            tables.append(dict(type=typ,lower=lower,upper=upper,unresolved_bytes=upper-lower,
                exact_under_alignment_contract=lower==upper,
                lower_alignment=alignment if typ!=TYPES[1] else 8,
                witness_samples=[s for s in witnesses if s['gap']==upper],
                typed_distribution=dict(sorted(collections.Counter(s['gap'] for s in samples).items())),
                name_census_distribution=dict(sorted(collections.Counter(s['gap'] for s in name_only).items())),
                typed_samples=samples,name_census=name_only))
        result['targets'].append(dict(target=target,anchors=a,tables=tables))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    for t in result['targets']:
        print(t['target'],[(x['type'],x['lower'],x['upper'],x['typed_distribution']) for x in t['tables']])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='mode',required=True)
    f=sub.add_parser('fixtures');f.add_argument('--toolchain',type=Path,required=True)
    f.add_argument('--output',type=Path,required=True);f.set_defaults(func=fixtures)
    c=sub.add_parser('census');c.add_argument('--symbols',type=Path,required=True)
    c.add_argument('--sources',type=Path,required=True);c.add_argument('--anchors',type=Path,required=True)
    c.add_argument('--output',type=Path,required=True);c.set_defaults(func=census)
    args=parser.parse_args();args.func(args)


if __name__=='__main__':
    main()
