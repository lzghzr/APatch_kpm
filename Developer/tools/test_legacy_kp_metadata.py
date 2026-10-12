#!/usr/bin/env python3
"""Developer 自检：KPM 转接的 ABI、可选元信息与精确修改范围。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from test_legacy_kp_adapter import check as check_present, inspect
from test_legacy_kp_import import check as check_absent, fixture


def digest(data):
    return hashlib.sha256(data).hexdigest()


def info(data):
    _, sections, _ = inspect(data)
    entry = sections[b'.kpm.info'][1]
    return entry, data[entry[4]:entry[4] + entry[5]]


def run_checked(command):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'命令失败（{result.returncode}）: {" ".join(map(str, command))}\n'
                           + result.stdout + result.stderr)


def add_pointer_import(args, source):
    asm, obj = args.output / 'pointer.S', args.output / 'pointer.o'
    asm.write_text('.text\n.global pointer_fixture\npointer_fixture:\n'
                   'adrp x9, kallsyms_lookup_name\nldr x9, [x9, :lo12:kallsyms_lookup_name]\nret\n')
    run_checked([str(args.clang), '--target=aarch64-linux-gnu', '-c', str(asm), '-o', str(obj)])
    augmented = args.output / f'{source.stem}-with-pointer.kpm'
    run_checked([str(args.clang.parent / 'ld.lld'), '-r', str(source), str(obj), '-o', str(augmented)])
    return augmented


def check_conversion(args, tool, tool_path, index, source):
    before = source.read_bytes()
    source_hash = digest(before)
    entry, payload = info(before)
    marker = b'kp_compat=modern\0'
    assert payload.split(b'\0').count(marker[:-1]) == 1
    value_at = entry[4] + payload.index(marker) + len(b'kp_compat=')
    # 先对不改元信息的 ABI 转接运行既有完整 Oracle，再检查组合输出。
    adapter, ranges, count, added = tool.legacy_lookup(before)
    adapter_path = args.output / f'abi-{index}.kpm'
    adapter_path.write_bytes(adapter)
    Path(str(adapter_path) + '.compat.json').write_text(json.dumps({
        'parent_sha256': source_hash, 'sha256': digest(adapter),
        'modified_ranges': ranges, 'pointer_import_added': added,
    }))
    (check_absent if added else check_present)(source, adapter_path)
    output = args.output / f'compat-{index}.kpm'
    command = [sys.executable, str(tool_path), 'legacy-kp', str(source), '--output', str(output)]
    run_checked(command)
    after = output.read_bytes()
    expected = bytearray(adapter)
    expected[value_at:value_at + 6] = b'legacy'
    assert after == bytes(expected) and count == 1
    assert info(after)[0] == entry
    assert info(after)[1] == payload.replace(marker, b'kp_compat=legacy\0', 1)
    receipt = json.loads(Path(str(output) + '.compat.json').read_text())
    assert receipt['parent_sha256'] == source_hash and receipt['sha256'] == digest(after)
    assert receipt['modified_ranges'] == ranges + [{'offset': value_at, 'size': 6}]
    assert all(any(r['offset'] <= at < r['offset'] + r['size'] for r in receipt['modified_ranges'])
               for at, (left, right) in enumerate(zip(before, after)) if left != right)
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert output.read_bytes() == after and source.read_bytes() == before
    repeated = [*command[:3], str(output), '--output', str(args.output / f'repeat-{index}.kpm')]
    assert subprocess.run(repeated, capture_output=True).returncode != 0
    assert not (args.output / f'repeat-{index}.kpm').exists()
    layout = Path(str(source) + '.json')
    if layout.exists():
        old = json.loads(layout.read_text())
        new = json.loads(Path(str(output) + '.json').read_text())
        assert new['sha256'] == digest(after) and new['parent_sha256'] == source_hash
        assert {k: v for k, v in new.items() if k not in ('sha256', 'parent_sha256', 'kpm')} == {
            k: v for k, v in old.items() if k not in ('sha256', 'parent_sha256', 'kpm')}
    return {'name': source.name, 'parent_sha256': source_hash, 'sha256': digest(after),
            'pointer_import_added': added, 'checks': 'PASS'}


def check_metadata(tool, sources):
    # 历史无字段／已标记 legacy 的输入，以及普通 ELF，保持字节。
    sample = sources[0].read_bytes()
    entry, payload = info(sample)
    for data in (fixture(), sample.replace(b'kp_compat=modern\0', b'kp_compat=legacy\0'),
                 sample.replace(b'kp_compat=modern\0', bytes(17))):
        assert tool.legacy_info(data) == (data, [])
    invalid = [sample.replace(b'kp_compat=modern\0', b'kp_compat=broken\0')]
    duplicate = bytearray(sample)
    duplicate[entry[4]:entry[4] + 34] = b'kp_compat=modern\0' * 2
    invalid.append(bytes(duplicate))
    unterminated = bytearray(sample)
    unterminated[entry[4] + entry[5] - 1] = 1
    invalid.append(bytes(unterminated))
    for data in invalid:
        try:
            tool.legacy_info(data)
        except ValueError:
            continue
        raise AssertionError('invalid metadata accepted')


def add_metadata(args, source, index):
    # 在独立夹具中保留历史字段契约，生产 KPM 不承担夹具字段。
    asm, obj = args.output / 'metadata.S', args.output / 'metadata.o'
    asm.write_text('.section .kpm.info,"a",@progbits\n.asciz "kp_compat=modern"\n')
    run_checked([str(args.clang), '--target=aarch64-linux-gnu', '-c', str(asm), '-o', str(obj)])
    tagged = args.output / f'tagged-{index}.kpm'
    run_checked([str(args.clang.parent / 'ld.lld'), '-r', str(source), str(obj), '-o', str(tagged)])
    layout = Path(str(source) + '.json')
    if layout.exists():
        value = json.loads(layout.read_text())
        before, after = source.read_bytes(), tagged.read_bytes()
        _, sections, _ = inspect(after)
        table = sections[b'.data.re_offsets'][1]
        assert after[table[4]:table[4] + table[5]] == before[
            value['table_offset']:value['table_offset'] + value['table_size']]
        value.update(kpm=tagged.name, sha256=digest(after), table_offset=table[4], table_size=table[5])
        Path(str(tagged) + '.json').write_text(json.dumps(value))
    return tagged


def check_unmarked_conversion(args, tool, tool_path, index, source):
    before = source.read_bytes()
    entry, payload = info(before)
    assert not any(field.startswith(b'kp_compat=') for field in payload.split(b'\0'))
    expected, ranges, count, added = tool.legacy_lookup(before)
    output = args.output / f'unmarked-{index}.kpm'
    command = [sys.executable, str(tool_path), 'legacy-kp', str(source), '--output', str(output)]
    run_checked(command)
    after = output.read_bytes()
    assert after == expected and count == 1
    assert info(after) == (entry, payload)
    (check_absent if added else check_present)(source, output)
    receipt = json.loads(Path(str(output) + '.compat.json').read_text())
    assert receipt['parent_sha256'] == digest(before) and receipt['sha256'] == digest(after)
    assert receipt['modified_ranges'] == ranges
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert output.read_bytes() == after and source.read_bytes() == before
    repeated = [*command[:3], str(output), '--output', str(args.output / f'unmarked-repeat-{index}.kpm')]
    assert subprocess.run(repeated, capture_output=True).returncode != 0
    assert not (args.output / f'unmarked-repeat-{index}.kpm').exists()
    layout = Path(str(source) + '.json')
    if layout.exists():
        old = json.loads(layout.read_text())
        new = json.loads(Path(str(output) + '.json').read_text())
        assert new['sha256'] == digest(after) and new['parent_sha256'] == digest(before)
        assert {k: v for k, v in new.items() if k not in ('sha256', 'parent_sha256', 'kpm')} == {
            k: v for k, v in old.items() if k not in ('sha256', 'parent_sha256', 'kpm')}
    return {'name': source.name, 'parent_sha256': digest(before), 'sha256': digest(after),
            'pointer_import_added': added, 'metadata': 'unchanged', 'checks': 'PASS'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clang', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    tool_path = root / 'patch_offsets.py'
    spec = importlib.util.spec_from_file_location('legacy_tool', tool_path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    sources = sorted(p for p in args.build.glob('*.kpm') if '_legacy' not in p.name)
    assert len(sources) == 4
    tagged = [add_metadata(args, source, index) for index, source in enumerate(sources)]
    augmented = add_pointer_import(args, tagged[0])
    results = [check_conversion(args, tool, tool_path, index, source)
               for index, source in enumerate([*tagged, augmented])]
    check_metadata(tool, tagged)
    unmarked_pointer = add_pointer_import(args, sources[0])
    unmarked = [check_unmarked_conversion(args, tool, tool_path, index, source)
                for index, source in enumerate([*sources, unmarked_pointer])]
    (args.output / 'results.json').write_text(json.dumps({
        'scope': 'Developer Tier-3; original Oracle helpers unchanged', 'results': results,
        'metadata_cases': '3 byte-preserving inputs; 3 malformed inputs rejected',
        'unmarked_results': unmarked,
    }, indent=2) + '\n')
    print('PASS: 4 ordinary KPMs + existing pointer import; original ABI Oracle; exact metadata and receipt; '
          'static layouts; output protection; 6 metadata cases; 5 unmarked conversions')


if __name__ == '__main__':
    main()
