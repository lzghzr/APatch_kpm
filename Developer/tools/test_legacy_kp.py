#!/usr/bin/env python3
"""Developer 自检：旧 KP 导入替换的字节范围、输出保护与布局衔接。"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


OLD = b"kallsyms_lookup_name_by_suffix"
NEW = b"kallsyms_lookup_name"


def inspect(data):
    start = struct.unpack_from("<Q", data, 40)[0]
    width, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, start + index * width) for index in range(count)]
    names, ranges = [], []
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, info, _, index, _, _ = struct.unpack_from("<IBBHQQ", data, offset)
            at = strings[4] + name
            end = data.index(0, at, strings[4] + strings[5])
            value = data[at:end]
            names.append((value, info, index))
            if value == OLD:
                ranges.append((at, end + 1))
    return names, ranges


def fixture(*, defined=False, shared=False, static=False):
    strings = b"\0" + OLD + b"\0" + NEW + b"\0ordinary\0"
    symbols = bytes(24) + struct.pack("<IBBHQQ", 1, 0x10, 0, 2 if defined else 0, 0, 0)
    symbols += struct.pack("<IBBHQQ", len(OLD) + 2, 0x10, 0, 0, 0, 0)
    if shared:
        symbols += struct.pack("<IBBHQQ", 1 + len(b"kallsyms_lookup_name"), 0x10, 0, 0, 0, 0)
    blocks = [(".shstrtab", 3, 0, b"", 0, 0), (".text", 1, 6, b"\xc0\x03\x5f\xd6", 0, 0),
              (".rodata", 1, 2, OLD + b"\0", 0, 0), (".strtab", 3, 0, strings, 0, 0),
              (".symtab", 2, 0, symbols, 4, 24)]
    if static:
        blocks.append((".data.re_offsets", 1, 3, struct.pack("<hhh", 0x20, 4, 6), 0, 0))
    shstrings = b"\0" + b"".join(name.encode() + b"\0" for name, *_ in blocks)
    blocks[0] = (".shstrtab", 3, 0, shstrings, 0, 0)
    data = bytearray(64)
    headers = [bytes(64)]
    for name, kind, flags, payload, link, entry_size in blocks:
        data.extend(bytes((-len(data)) % 8))
        headers.append(struct.pack("<IIQQQQIIQQ", shstrings.index(name.encode() + b"\0"), kind, flags, 0,
                                   len(data), len(payload), link, 0, 8, entry_size))
        data.extend(payload)
    data.extend(bytes((-len(data)) % 8))
    start = len(data)
    data.extend(b"".join(headers))
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 1, 183, 1, 0, 0,
                            start, 0, 64, 0, 0, 64, len(headers), 1)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="新的空目录")
    parser.add_argument("--kpm", type=Path, action="append", default=[], help="只读核对实际候选，可重复指定")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    tool = Path(__file__).resolve().parents[2] / "patch_offsets.py"

    def call(*values, ok=True):
        result = subprocess.run([sys.executable, str(tool), *map(str, values)], capture_output=True, text=True)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    def check(source, output):
        before, after = source.read_bytes(), output.read_bytes()
        old_symbols, ranges = inspect(before)
        new_symbols, _ = inspect(after)
        assert new_symbols == [(NEW if name == OLD else name, info, index) for name, info, index in old_symbols]
        assert len(before) == len(after)
        assert all(any(start <= index < end for start, end in ranges)
                   for index, (left, right) in enumerate(zip(before, after)) if left != right)
        receipt = json.loads(Path(str(output) + ".compat.json").read_text())
        assert receipt["parent_sha256"] == hashlib.sha256(before).hexdigest()
        assert receipt["sha256"] == hashlib.sha256(after).hexdigest()
        assert receipt["lookup_mode"] == "exact" and receipt["kind"] == "binary-port"
        assert receipt["imports_changed"] == sum(name == OLD for name, _, _ in old_symbols)
        assert receipt["modified_ranges"] == [{"offset": start, "size": end - start}
                                                for start, end in sorted(set(ranges))]
        return receipt

    dynamic = args.output / "dynamic.kpm"
    dynamic.write_bytes(fixture())
    output = args.output / "dynamic-legacy.kpm"
    call("legacy-kp", dynamic, "--output", output)
    check(dynamic, output)
    assert not Path(str(output) + ".json").exists()
    assert OLD + b"\0" in output.read_bytes()  # 相同的 rodata 字符串保留。
    protected = output.read_bytes()
    call("legacy-kp", dynamic, "--output", output, ok=False)
    assert output.read_bytes() == protected

    allocated = bytearray(fixture())
    headers = struct.unpack_from("<Q", allocated, 40)[0]
    struct.pack_into("<Q", allocated, headers + 4 * 64 + 8, 2)
    overlapping = bytearray(fixture())
    at, end = inspect(overlapping)[1][0]
    struct.pack_into("<QQ", overlapping, headers + 2 * 64 + 24, at, end - at)
    for name, data in (("defined", fixture(defined=True)), ("shared", fixture(shared=True)),
                       ("allocated", allocated), ("overlapping", overlapping),
                       ("truncated", fixture()[:64]), ("already", output.read_bytes())):
        source = args.output / f"{name}.kpm"
        source.write_bytes(data)
        destination = args.output / f"{name}-refused.kpm"
        call("legacy-kp", source, "--output", destination, ok=False)
        assert not destination.exists() and not Path(str(destination) + ".compat.json").exists()

    conflict = args.output / "conflict.kpm"
    sentinel = Path(str(conflict) + ".compat.json")
    sentinel.write_text("existing receipt")
    call("legacy-kp", dynamic, "--output", conflict, ok=False)
    assert not conflict.exists() and sentinel.read_text() == "existing receipt"

    baseline = args.output / "baseline.kpm"
    baseline.write_bytes(fixture(static=True))
    source = args.output / "re_offsets.c"
    source.write_text("struct struct_offset { int16_t genl_family_id; int16_t genl_family_n_mcgrps_size; "
                      "int16_t binder_release_abi; };\n")
    layout = Path(str(baseline) + ".json")
    call("baseline", baseline, "--source", source, "--output", layout)
    static_output = args.output / "static-legacy.kpm"
    call("legacy-kp", baseline, "--output", static_output)
    check(baseline, static_output)
    old_layout = json.loads(layout.read_text())
    new_layout = json.loads(Path(str(static_output) + ".json").read_text())
    for field in ("fields", "offsets", "table_offset", "table_size", "binder_abi", "schema"):
        assert new_layout[field] == old_layout[field]
    call("dump", static_output, "--output", args.output / "static.bin")
    old_layout["sha256"] = "0" * 64
    layout.write_text(json.dumps(old_layout))
    refused = args.output / "bad-layout.kpm"
    call("legacy-kp", baseline, "--output", refused, ok=False)
    assert not refused.exists()

    actual = []
    for index, kpm in enumerate(args.kpm):
        output = args.output / f"actual-{index}.kpm"
        call("legacy-kp", kpm, "--output", output)
        actual.append(check(kpm, output))
    (args.output / "actual-receipts.json").write_text(json.dumps(actual, indent=2) + "\n")
    print(f"PASS: import-only changes, shared-string/defined/malformed rejection, output protection, "
          f"static layout roundtrip; {len(actual)} actual KPMs")


if __name__ == "__main__":
    main()
