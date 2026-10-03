#!/usr/bin/env python3
"""离线替换 KPM 的 .data.re_offsets；只依赖 Python 标准库。"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sections(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected ELF64 little-endian KPM")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1:3] != (1, 183):
        raise ValueError("expected ARM64 relocatable KPM")
    start, entry_size, count, names_index = header[6], header[11], header[12], header[13]
    if entry_size != 64 or not count or names_index >= count or start + count * 64 > len(data):
        raise ValueError("invalid section table")
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, start + i * 64) for i in range(count)]
    names = entries[names_index]
    if names[1] != 3 or names[4] + names[5] > len(data):
        raise ValueError("invalid section names")
    strings = data[names[4]:names[4] + names[5]]
    result = {}
    for index, entry in enumerate(entries):
        if entry[0] >= len(strings):
            raise ValueError("invalid section name")
        end = strings.find(b"\0", entry[0])
        if end < 0:
            raise ValueError("unterminated section name")
        name = strings[entry[0]:end].decode("ascii")
        if name in (".data.re_offsets", ".rodata.re_abi"):
            if name in result or entry[1] != 1 or entry[4] + entry[5] > len(data):
                raise ValueError("invalid configuration section")
            result[name] = (entry[4], entry[5], index, entry[2])
    for name in (".data.re_offsets", ".rodata.re_abi"):
        if name not in result:
            raise ValueError(f"missing {name}")
    offset, size, index, flags = result[".data.re_offsets"]
    if flags & 3 != 3 or size == 0 or size % 2:
        raise ValueError("invalid writable offset table")
    if any(entry[1] in (4, 9) and entry[7] == index and entry[5] for entry in entries):
        raise ValueError("offset table must not contain relocations")
    abi_offset, abi_size, _, _ = result[".rodata.re_abi"]
    if abi_size != 4:
        raise ValueError("invalid Binder ABI tag")
    abi = struct.unpack_from("<I", data, abi_offset)[0]
    if abi not in (3, 4, 5, 6):
        raise ValueError("unknown Binder ABI")
    return offset, size, abi


def source_fields():
    source = Path(__file__).resolve().parents[1] / "re_offsets.c"
    text = source.read_text()
    body = re.search(r"struct struct_offset\s*\{([^}]+)\};", text).group(1)
    fields = re.findall(r"int16_t\s+(\w+)\s*;", body)
    if re.sub(r"int16_t\s+\w+\s*;", "", body).strip() or len(set(fields)) != len(fields):
        raise ValueError("offset schema must contain only unique int16_t fields")
    return fields


def read_layout(path, data, offset, size, abi):
    layout = json.loads(path.read_text())
    fields = layout["fields"]
    if (layout["schema"] != 1 or layout["sha256"] != sha256(data)
            or layout["binder_abi"] != abi or layout["table_offset"] != offset
            or layout["table_size"] != size or len(fields) * 2 != size
            or not all(isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)):
        raise ValueError("layout does not match this KPM")
    return layout


def table_values(data, offset, size, fields):
    values = struct.unpack_from(f"<{size // 2}h", data, offset)
    return {field: hex(value) if value >= 0 else value for field, value in zip(fields, values)}


def encode_offsets(path, fields):
    values = json.loads(path.read_text())
    if "offsets" in values:
        values = values["offsets"]
    if set(values) != set(fields):
        missing = sorted(set(fields) - set(values))
        extra = sorted(set(values) - set(fields))
        raise ValueError(f"offset fields differ: missing={missing}, extra={extra}")
    numbers = []
    for field in fields:
        value = values[field]
        if isinstance(value, str):
            value = int(value, 0)
        if type(value) is not int or not -32768 <= value <= 32767:
            raise ValueError(f"{field} must fit int16_t")
        numbers.append(value)
    return struct.pack(f"<{len(numbers)}h", *numbers)


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run(args):
    data = args.kpm.read_bytes()
    offset, size, abi = sections(data)
    if args.command == "baseline":
        fields = source_fields()
        if len(fields) * 2 != size:
            raise ValueError("source fields do not match offset table size")
        layout = {
            "schema": 1,
            "kpm": args.kpm.name,
            "sha256": sha256(data),
            "binder_abi": abi,
            "table_offset": offset,
            "table_size": size,
            "fields": fields,
            "offsets": table_values(data, offset, size, fields),
        }
        write_json(args.output, layout)
        return {"binder_abi": abi, "table_bytes": size, "sha256": layout["sha256"]}

    layout_path = args.layout or Path(str(args.kpm) + ".json")
    layout = read_layout(layout_path, data, offset, size, abi)
    if args.command == "dump":
        with args.output.open("xb") as stream:
            stream.write(data[offset:offset + size])
        return {"binder_abi": abi, "bytes": size, "sha256": sha256(data[offset:offset + size])}

    payload = args.blob.read_bytes() if args.blob else encode_offsets(args.offsets, layout["fields"])
    if len(payload) != size:
        raise ValueError(f"offset blob must be exactly {size} bytes")
    # 工具端核对编码宽度；不在模块中加入运行时偏移推导或检查。
    count_index = layout["fields"].index("genl_family_n_mcgrps_size")
    if struct.unpack_from("<h", payload, count_index * 2)[0] not in (1, 2, 4):
        raise ValueError("genl_family_n_mcgrps_size must be 1, 2 or 4")
    for field, allowed in (("work_offq_pool_shift", (5, 6)),):
        if field in layout["fields"]:
            value = struct.unpack_from("<h", payload, layout["fields"].index(field) * 2)[0]
            if value not in allowed:
                raise ValueError(f"{field} must be 5 or 6 for this work prefix")
    if "work_cpu_unbound" in layout["fields"]:
        value = struct.unpack_from("<h", payload, layout["fields"].index("work_cpu_unbound") * 2)[0]
        if value <= 0:
            raise ValueError("work_cpu_unbound must be the positive target NR_CPUS")
    patched = data[:offset] + payload + data[offset + size:]
    output_layout = Path(str(args.output) + ".json")
    if args.output.exists() or output_layout.exists():
        raise FileExistsError("output KPM or layout already exists; choose a new path")
    receipt = dict(layout, kpm=args.output.name, parent_sha256=sha256(data), sha256=sha256(patched),
                   offsets=table_values(patched, offset, size, layout["fields"]))
    with args.output.open("xb") as stream:
        stream.write(patched)
    try:
        write_json(output_layout, receipt)
    except Exception:
        args.output.unlink()
        raise
    return {"binder_abi": abi, "table_bytes": size, "sha256": receipt["sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("baseline", "dump", "patch"):
        subparser = commands.add_parser(command)
        subparser.add_argument("kpm", type=Path)
        subparser.add_argument("--output", type=Path, required=True)
        if command != "baseline":
            subparser.add_argument("--layout", type=Path)
        if command == "patch":
            source = subparser.add_mutually_exclusive_group(required=True)
            source.add_argument("--offsets", type=Path, help="完整偏移表 JSON，也可使用基准版 JSON 的 offsets")
            source.add_argument("--blob", type=Path, help="按基准版 fields 顺序排列的 int16 小端二进制")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), ensure_ascii=False))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
