#!/usr/bin/env python3
"""Offline native table inventory with RELATIVE relocations; no image writes.

Reference declarations classify named objects, not the target's sizeof.
The supplied configuration must already have separately accepted sizes.
"""
import argparse
import collections
import json
from pathlib import Path
import re
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'source', 'config', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    data = a.image.read_bytes()
    log = a.symbols.read_text()
    config = json.loads(a.config.read_text())
    rows = [(int(at, 16), kind, name) for at, kind, name in re.findall(
        r'^0x([0-9a-f]+) ([A-Za-z]) (\S+)$', log, re.M)]
    symbols = collections.defaultdict(list)
    for at, kind, name in rows:
        symbols[at].append(dict(kind=kind, name=name))
    addresses = sorted(symbols)
    successors = dict(zip(addresses, addresses[1:]))
    start, end = [int(x, 16) for x in re.search(
        r'relocation table range: \[0x([0-9a-f]+), 0x([0-9a-f]+)\)', log).groups()]
    assert (end - start) % 24 == 0 and end <= len(data)
    # The log's minimum relocation addend can be below _text (venus: -0x80000).
    # Bind the address domain to the relocated kallsyms_relative_base itself.
    count_at, count = [int(x, 16) for x in re.search(
        r'kallsyms_num_syms offset: 0x([0-9a-f]+), value: 0x([0-9a-f]+)', log).groups()]
    array_at = int(re.search(r'\[\+\] kallsyms_offsets offset: 0x([0-9a-f]+)', log)[1], 16)
    assert struct.unpack_from('<Q', data, count_at)[0] == count
    assert struct.unpack_from('<I', data, array_at)[0] == 0
    base_candidates = []
    for pos in range(start, end, 24):
        where, info, addend = struct.unpack_from('<QQQ', data, pos)
        if info == 1027 and addend % 4096 == 0 and array_at + count * 4 <= where - addend < count_at:
            base_candidates.append(dict(base=addend, record=hex(pos), field=hex(where - addend)))
    assert len(base_candidates) == 1, base_candidates
    base = base_candidates[0]['base']
    relocs = {}
    for pos in range(start, end, 24):
        where, info, addend = struct.unpack_from('<QQQ', data, pos)
        assert info == 1027, (hex(pos), info)  # R_AARCH64_RELATIVE only
        at = where - base
        assert at not in relocs, hex(at)
        relocs[at] = dict(record=hex(pos), addend=hex(addend))
    declarations = collections.defaultdict(list)
    pattern = re.compile(r'\bstruct\s+(inode_operations|super_operations|dentry_operations)'
                         r'\s+(\w+)\s*(?:__\w+\s*)?=\s*\{')
    source_files = list((a.source / 'fs').rglob('*.c'))
    source_files += [a.source / x for x in ('mm/shmem.c', 'security/inode.c',
                                          'net/socket.c', 'drivers/dma-buf/dma-buf.c',
                                          'drivers/android/binderfs.c', 'drivers/dax/super.c',
                                          'drivers/gpu/drm/drm_drv.c')]
    for path in sorted(set(source_files)):
        if not path.exists():
            continue
        content = path.read_text(errors='replace')
        for m in pattern.finditer(content):
            declarations[m[2]].append(dict(type=m[1], file=str(path.relative_to(a.source)),
                                           line=content[:m.start()].count('\n') + 1))
    sizes = {t: config['offsets'][k] for t, k in (
        ('inode_operations', 'inode_ops_size'), ('super_operations', 'super_ops_size'),
        ('dentry_operations', 'dentry_ops_size'))}
    lost_start = dict(inode_operations=192, super_operations=240, dentry_operations=128)
    tables, skipped, unclassified = [], [], []
    seen = set()
    for at, kind, name in rows:
        if kind.lower() not in ('r', 'd') or name.startswith('__'):
            continue
        normalized = name.split('.llvm.')[0]
        decls = declarations.get(normalized, [])
        types = {d['type'] for d in decls}
        if not types:
            if re.search(r'(?:inode_operations|super_operations|dentry_operations|dentry_ops|sops)$', name):
                unclassified.append(dict(name=name, address=hex(at)))
            continue
        if len(types) != 1:
            skipped.append(dict(name=name, reason='ambiguous reference type', declarations=decls))
            continue
        typ = next(iter(types))
        if (at, typ) in seen:
            continue
        seen.add((at, typ))
        size = sizes[typ]
        if at + size > len(data) or successors.get(at, len(data)) < at + size:
            skipped.append(dict(name=name, address=hex(at), reason='extent crosses symbol or file boundary'))
            continue
        slots = []
        for offset in range(0, size, 8):
            raw = struct.unpack_from('<Q', data, at + offset)[0]
            relocation = relocs.get(at + offset)
            value = int(relocation['addend'], 16) if relocation else raw
            resolved = symbols.get(value - base, []) if value else []
            slots.append(dict(offset=offset, raw=hex(raw), value=hex(value),
                              relocation=relocation, symbols=resolved))
        tail = [s for s in slots if s['offset'] >= lost_start[typ]]
        tables.append(dict(name=name, address=hex(at), type=typ, size=size,
                           declarations=decls, slots=slots,
                           lost_range=[lost_start[typ], size],
                           lost_nonzero=[s['offset'] for s in tail if int(s['value'], 16)],
                           lost_relocations=[s['offset'] for s in tail if s['relocation']]))
    summary = {}
    for typ in sizes:
        group = [t for t in tables if t['type'] == typ]
        summary[typ] = dict(tables=len(group),
            lost_slots=sum((t['size'] - lost_start[typ]) // 8 for t in group),
            lost_nonzero=sum(len(t['lost_nonzero']) for t in group),
            lost_relocations=sum(len(t['lost_relocations']) for t in group),
            prefix_nonzero=sum(sum(int(s['value'], 16) != 0 for s in t['slots']
                                   if s['offset'] < lost_start[typ]) for t in group))
    # Positive controls catch a wrong image/VA mapping before interpreting zero tails.
    controls = []
    for name, expected in (('ext4_sops', 'ext4_alloc_inode'), ('f2fs_sops', 'f2fs_alloc_inode')):
        row = next(t for t in tables if t['name'] == name)
        slot = row['slots'][0]
        assert any(s['name'].startswith(expected) and s['kind'].lower() == 't'
                   for s in slot['symbols']), (name, slot)
        controls.append(dict(table=name, slot=0, callback=slot))
    result = dict(target=config['target'], kernel_sha256=config['kernel_sha256'],
        identity_note='kernel identity inherited from accepted config; input path is supplied explicitly',
        reference_commit=subprocess.check_output(['git', '-C', str(a.source), 'rev-parse', 'HEAD'], text=True).strip(),
        reference_role='object-name/type classification only; not target layout proof',
        kernel_base=hex(base), base_evidence=base_candidates[0], relocation_range=[hex(start), hex(end)],
        relocation_count=len(relocs), source_files_considered=len(source_files),
        summary=summary, positive_controls=controls, tables=tables, skipped=skipped,
        unclassified_name_candidates=unclassified,
        limitations=['Named reference-declared objects only; no runtime writes or anonymous tables',
                     'Zero contents do not prove no reader or unused slot',
                     'No instruction-window consumer scan in this method'])
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(target=result['target'], summary=summary, skipped=len(skipped),
                          unclassified=len(unclassified))))


if __name__ == '__main__':
    main()
