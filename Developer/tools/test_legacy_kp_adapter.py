#!/usr/bin/env python3
"""Developer 自检：ELF 转接、指针调用契约、静态布局及输出保护。"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


OLD = b"kallsyms_lookup_name_by_suffix"
POINTER = b"kallsyms_lookup_name"


def inspect(data):
    start = struct.unpack_from("<Q", data, 40)[0]
    width, count, names_index = struct.unpack_from("<HHH", data, 58)
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, start + i * width) for i in range(count)]
    names = entries[names_index]
    strings = data[names[4]:names[4] + names[5]]
    sections = {strings[e[0]:strings.index(0, e[0])]: (i, e) for i, e in enumerate(entries)}
    symbols = []
    for table_index, entry in enumerate(entries):
        if entry[1] != 2:
            continue
        strings = entries[entry[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        for i in range(entry[5] // 24):
            at = entry[4] + i * 24
            name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", data, at)
            symbols.append((names[name:names.index(0, name)], info, other, index, value, size, table_index, i, at))
    return entries, sections, symbols


def check(source, output):
    before, after = source.read_bytes(), output.read_bytes()
    entries, sections, old_symbols = inspect(before)
    _, new_sections, new_symbols = inspect(after)
    old = next(s for s in old_symbols if s[0] == OLD)
    pointer = next(s for s in old_symbols if s[0] == POINTER)
    text_index, text = new_sections[b".text.kpm_legacy_lookup"]
    _, rela = new_sections[b".rela.text.kpm_legacy_lookup"]
    assert text[1:3] == (1, 6) and text[8] == 4 and text[5] == 12
    assert rela[1] == 4 and rela[6:8] == (old[6], text_index) and rela[9] == 24
    assert struct.unpack_from("<QQqQQq", after, rela[4]) == (0, pointer[7] << 32 | 275, 0,
                                                             4, pointer[7] << 32 | 286, 0)
    for left, right in zip(old_symbols, new_symbols):
        if left[0] == OLD:
            assert right == (OLD, left[1] & 0xf0 | 2, left[2], text_index, 0, 12, *left[6:])
        else:
            assert right == left
    for name, (_, entry) in sections.items():
        if entry[1] in (0, 2, 8) or name == b".shstrtab":
            continue
        assert new_sections[name] == sections[name]
        assert after[entry[4]:entry[4] + entry[5]] == before[entry[4]:entry[4] + entry[5]]
    receipt = json.loads(Path(str(output) + ".compat.json").read_text())
    assert receipt['parent_sha256'] == hashlib.sha256(before).hexdigest()
    assert receipt['sha256'] == hashlib.sha256(after).hexdigest()
    ranges = receipt['modified_ranges']
    assert all(any(r['offset'] <= i < r['offset'] + r['size'] for r in ranges)
               for i, (left, right) in enumerate(zip(before, after)) if left != right)
    assert any(r['offset'] == len(before) and r['size'] == len(after) - len(before) for r in ranges)
    return after[text[4]:text[4] + text[5]], receipt


def pointer_call_model(code):
    # 装入两个不同的指针目标，按指令字段复算 ADRP/LDR/BR 的落点。
    adrp, ldr, branch = struct.unpack('<III', code)
    assert adrp & 0x9f00001f == 0x90000010
    assert ldr & 0xffc003ff == 0xf9400210
    assert branch == 0xd61f0200
    for page_delta in (-64, 71):
        pc = 0xffff000012345000
        pointer_address = pc + page_delta * 4096 + 0x3a8
        imm = page_delta & 0x1fffff
        relocated = adrp | (imm & 3) << 29 | (imm >> 2) << 5
        loaded = ldr | (0x3a8 // 8) << 10
        encoded = (relocated >> 29 & 3) | (relocated >> 5 & 0x7ffff) << 2
        signed = encoded - (1 << 21) if encoded & (1 << 20) else encoded
        address = (pc & ~4095) + signed * 4096 + (loaded >> 10 & 4095) * 8
        assert address == pointer_address
        for function in (pc + 0x12300, pc - 0x4000):
            memory = {pointer_address: function}
            assert memory[address] == function and memory[address] != pointer_address


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identities', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clang', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    tool = Path(__file__).resolve().parents[2] / 'patch_offsets.py'
    asm = args.output / 'adapter.S'
    asm.write_text('.text\n.global adapter\nadapter:\nadrp x16, kallsyms_lookup_name\n'
                   'ldr x16, [x16, :lo12:kallsyms_lookup_name]\nbr x16\n')
    obj = args.output / 'adapter.o'
    subprocess.run([str(args.clang), '--target=aarch64-linux-gnu', '-c', str(asm), '-o', str(obj)], check=True)
    data = obj.read_bytes()
    _, sections, _ = inspect(data)
    entry = sections[b'.text'][1]
    assembled = data[entry[4]:entry[4] + entry[5]]
    pointer_call_model(assembled)
    results = []
    for index, identity in enumerate(json.loads(args.identities.read_text())):
        source = Path(identity['parent_path'])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == identity['parent_sha256']
        output = args.output / f'actual-{index}.kpm'
        cmd = [sys.executable, str(tool), 'legacy-kp', str(source), '--output', str(output)]
        subprocess.run(cmd, check=True, capture_output=True)
        code, receipt = check(source, output)
        assert code == assembled
        pointer_call_model(code)
        repeated = subprocess.run(cmd, capture_output=True)
        assert repeated.returncode != 0 and hashlib.sha256(output.read_bytes()).hexdigest() == receipt['sha256']
        duplicate = subprocess.run([*cmd[:3], str(output), '--output', str(args.output / f'duplicate-{index}.kpm')],
                                   capture_output=True)
        assert duplicate.returncode != 0
        if Path(str(source) + '.json').exists():
            old_layout = json.loads(Path(str(source) + '.json').read_text())
            new_layout = json.loads(Path(str(output) + '.json').read_text())
            assert new_layout['sha256'] == receipt['sha256']
            assert {k: v for k, v in new_layout.items() if k not in ('sha256', 'kpm', 'parent_sha256')} == {
                k: v for k, v in old_layout.items() if k not in ('sha256', 'kpm', 'parent_sha256')}
        results.append(dict(identity, adapter_sha256=receipt['sha256'], adapter_path=str(output), checks='PASS'))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'PASS: {len(results)} actual KPMs; assembler, pointer model, unchanged original sections, output protection')


if __name__ == '__main__':
    main()
