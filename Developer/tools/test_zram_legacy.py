#!/usr/bin/env python3
"""Developer 自检：真实 zram legacy 输入及原名指针正反契约。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

from test_legacy_kp_adapter import check as check_present, pointer_call_model, inspect
from test_legacy_kp_import import check as check_absent, fixture


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--legacy-dir', type=Path, help='独立 LAYOUT_DIR 下的 out/legacy')
    parser.add_argument('--clang', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('legacy_tool', root / 'patch_offsets.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    asm, obj = args.output / 'pointer.S', args.output / 'pointer.o'
    asm.write_text('.text\n.global pointer_fixture\npointer_fixture:\nadrp x9, kallsyms_lookup_name\n'
                   'ldr x9, [x9, :lo12:kallsyms_lookup_name]\nret\n')
    subprocess.run([str(args.clang), '--target=aarch64-linux-gnu', '-c', str(asm), '-o', str(obj)], check=True)
    rows = []
    sources = sorted((args.legacy_dir or args.build / 'out/legacy').glob('*.input'))
    assert len(sources) == 2
    for src in sources:
        name = src.name.removesuffix('.input')
        dest = src.parent / name
        receipt = check_absent(src, dest)
        _, _, before = inspect(src.read_bytes())
        entries, _, _ = inspect(dest.read_bytes())
        suffix = next(s for s in before if s[0] == b'kallsyms_lookup_name_by_suffix')
        calls = 0
        for entry in entries:
            if entry[1] != 4 or entry[6] != suffix[6]:
                continue
            for offset in range(entry[4], entry[4] + entry[5], 24):
                info = struct.unpack_from('<Q', dest.read_bytes(), offset + 8)[0]
                calls += info >> 32 == suffix[7] and info & 0xffffffff == 283
        assert calls > 0
        assert sha(args.build / name) == receipt['sha256']
        rows.append({'name': name, 'parent_sha256': sha(src), 'sha256': receipt['sha256'],
                     'direct_call26_count': calls, 'pointer_import_added': True, 'checks': 'PASS'})
        augmented = args.output / (name + '.with-pointer')
        subprocess.run([str(args.clang.parent / 'ld.lld'), '-r', str(src), str(obj), '-o', str(augmented)], check=True)
        output = args.output / (name + '.with-pointer.legacy')
        subprocess.run([sys.executable, str(root / 'patch_offsets.py'), 'legacy-kp', str(augmented),
                        '--output', str(output)], capture_output=True, check=True)
        code, record = check_present(augmented, output)
        pointer_call_model(code)
        assert record['pointer_import_added'] is False
        rows.append({'name': name + '+pointer fixture', 'parent_sha256': sha(augmented), 'sha256': sha(output),
                     'pointer_import_added': False, 'checks': 'PASS'})
    malformed = bytearray(fixture())
    table = struct.unpack_from('<Q', malformed, 40)[0]
    malformed.extend(malformed[table + 3 * 64:table + 4 * 64])
    struct.pack_into('<H', malformed, 60, 6)
    for name, data in [('no-suffix', fixture().replace(b'kallsyms_lookup_name_by_suffix', b'x' * 29)),
                       ('bad-symtab', b'\x7fELF'), ('multiple-symtab', malformed),
                       ('already-adapted', dest.read_bytes())]:
        try:
            tool.legacy_lookup(data)
        except ValueError:
            rows.append({'negative': name, 'checks': 'PASS: ValueError'})
        else:
            raise AssertionError(name)
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer selfcheck; existing Oracle helpers unchanged', 'results': rows,
        'inputs': {str(p.relative_to(root)): sha(p) for p in
                   [Path(__file__), root / 'patch_offsets.py', root / 'Developer/tools/test_legacy_kp_adapter.py',
                    root / 'Developer/tools/test_legacy_kp_import.py']},
    }, indent=2) + '\n')
    print('PASS: two actual KPMs, existing/absent pointer imports, CALL26, pointer model, four ValueError negatives')


if __name__ == '__main__':
    main()
