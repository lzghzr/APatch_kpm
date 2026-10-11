#!/usr/bin/env python3
"""Developer 自检：缺失原名指针导入的追加、共享字符串表及调用重定位。"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from test_legacy_kp_adapter import OLD, POINTER, inspect, pointer_call_model


def fixture():
    # 符号名和节名共用同一表；局部节符号在 global 函数导入之前。
    names = b'\0.strtab\0.text\0.symtab\0.rela.text\0' + OLD + b'\0'
    syms = bytes(24) + struct.pack('<IBBHQQ', 0, 3, 0, 2, 0, 0)
    syms += struct.pack('<IBBHQQ', names.index(OLD), 0x10, 0, 0, 0, 0)
    blocks = [(b'.strtab', 3, 0, names, 0, 0, 1, 0),
              (b'.text', 1, 6, struct.pack('<II', 0x94000000, 0xd65f03c0), 0, 0, 4, 0),
              (b'.symtab', 2, 0, syms, 1, 2, 8, 24),
              (b'.rela.text', 4, 0, struct.pack('<QQq', 0, 2 << 32 | 283, 0), 3, 2, 8, 24)]
    data = bytearray(64)
    entries = [bytes(64)]
    for name, kind, flags, payload, link, info, alignment, entry_size in blocks:
        data.extend(bytes((-len(data)) % alignment))
        entries.append(struct.pack('<IIQQQQIIQQ', names.index(name + b'\0'), kind, flags, 0,
                                   len(data), len(payload), link, info, alignment, entry_size))
        data.extend(payload)
    data.extend(bytes((-len(data)) % 8))
    start = len(data)
    data.extend(b''.join(entries))
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9), 1, 183, 1, 0, 0,
                            start, 0, 64, 0, 0, 64, len(entries), 1)
    return bytes(data)


def check(source, output):
    before, after = source.read_bytes(), output.read_bytes()
    entries, sections, old_symbols = inspect(before)
    new_entries, new_sections, new_symbols = inspect(after)
    assert not any(s[0] == POINTER for s in old_symbols)
    old = next(s for s in old_symbols if s[0] == OLD)
    table_index = old[6]
    table, new_table = entries[table_index], new_entries[table_index]
    assert new_table[6:] == table[6:] and new_table[5] == table[5] + 24
    assert new_table[4] >= len(before) and new_table[4] % 8 == 0
    assert len(new_symbols) == len(old_symbols) + 1
    pointer = new_symbols[-1]
    assert pointer[:8] == (POINTER, 0x11, 0, 0, 0, 0, table_index, len(old_symbols))
    text_index, text = new_sections[b'.text.kpm_legacy_lookup']
    assert text[1:3] == (1, 6) and text[5] == 12 and text[8] == 4
    for left, right in zip(old_symbols, new_symbols):
        expected = (OLD, left[1] & 0xf0 | 2, left[2], text_index, 0, 12, *left[6:8]) if left[0] == OLD else left[:8]
        assert right[:8] == expected
        assert right[8] == new_table[4] + left[7] * 24
    _, rela = new_sections[b'.rela.text.kpm_legacy_lookup']
    assert rela[1] == 4 and rela[6:10] == (table_index, text_index, 8, 24)
    assert struct.unpack_from('<QQqQQq', after, rela[4]) == (0, pointer[7] << 32 | 275, 0,
                                                          4, pointer[7] << 32 | 286, 0)
    string_index = table[6]
    strings, new_strings = entries[string_index], new_entries[string_index]
    assert after[new_strings[4]:new_strings[4] + new_strings[5]].startswith(
        before[strings[4]:strings[4] + strings[5]] + POINTER + b'\0')
    assert all(left == right for i, (left, right) in enumerate(zip(before, after)) if i not in (*range(40, 48), 60, 61))
    for name, (index, entry) in sections.items():
        if index in (table_index, string_index, struct.unpack_from('<H', before, 62)[0]):
            continue
        assert new_sections[name] == sections[name]
    receipt = json.loads(Path(str(output) + '.compat.json').read_text())
    assert receipt['pointer_import_added'] is True
    assert receipt['parent_sha256'] == hashlib.sha256(before).hexdigest()
    assert receipt['sha256'] == hashlib.sha256(after).hexdigest()
    ranges = receipt['modified_ranges']
    assert ranges == [{'offset': 40, 'size': 8}, {'offset': 60, 'size': 2},
                      {'offset': len(before), 'size': len(after) - len(before)}]
    pointer_call_model(after[text[4]:text[4] + text[5]])
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identities', type=Path, required=True)
    parser.add_argument('--previous-results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    tool = Path(__file__).resolve().parents[2] / 'patch_offsets.py'

    def call(source, output, ok=True):
        result = subprocess.run([sys.executable, str(tool), 'legacy-kp', str(source), '--output', str(output)],
                                capture_output=True, text=True)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    synthetic = args.output / 'shared.kpm'
    synthetic.write_bytes(fixture())
    output = args.output / 'shared-adapter.kpm'
    call(synthetic, output)
    check(synthetic, output)
    source_hash = hashlib.sha256(synthetic.read_bytes()).hexdigest()
    output_hash = hashlib.sha256(output.read_bytes()).hexdigest()
    call(synthetic, synthetic, ok=False)
    call(synthetic, output, ok=False)
    call(output, args.output / 'repeat.kpm', ok=False)
    assert hashlib.sha256(synthetic.read_bytes()).hexdigest() == source_hash
    assert hashlib.sha256(output.read_bytes()).hexdigest() == output_hash

    # KP 只选第一张 symtab；追加第二张并保留有效 ELF，确认工具明确拒绝。
    data = bytearray(fixture())
    start = struct.unpack_from('<Q', data, 40)[0]
    data.extend(data[start + 3 * 64:start + 4 * 64])
    struct.pack_into('<H', data, 60, 6)
    multiple = args.output / 'multiple-symtab.kpm'
    multiple.write_bytes(data)
    call(multiple, args.output / 'multiple-output.kpm', ok=False)
    assert not (args.output / 'multiple-output.kpm').exists()

    previous = {r['parent_sha256']: r for r in json.loads(args.previous_results.read_text())}
    results = []
    for i, row in enumerate(json.loads(args.identities.read_text())):
        source = Path(row['parent_path'])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == row['parent_sha256']
        output = args.output / f'actual-{i}.kpm'
        call(source, output)
        if row['module'] == 'run_cmd_demo':
            receipt = check(source, output)
        else:
            assert output.read_bytes() == Path(previous[row['parent_sha256']]['adapter_path']).read_bytes()
            receipt = json.loads(Path(str(output) + '.compat.json').read_text())
            assert receipt['pointer_import_added'] is False
        call(source, output, ok=False)
        call(output, args.output / f'duplicate-{i}.kpm', ok=False)
        assert hashlib.sha256(output.read_bytes()).hexdigest() == receipt['sha256']
        results.append(dict(row, adapter_sha256=receipt['sha256'], adapter_path=str(output),
                            pointer_import_added=receipt['pointer_import_added'], checks='PASS'))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'PASS: {len(results)} actual KPMs, shared string table, local/global boundary, relocation indices, '
          'existing adapters byte-identical, output protection, multi-symtab rejection')


if __name__ == '__main__':
    main()
