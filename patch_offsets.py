#!/usr/bin/env python3
"""离线替换 KPM 偏移表或生成旧 KP 函数指针转接兼容件；只依赖 Python 标准库。"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def elf_sections(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected ELF64 little-endian KPM")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1:3] != (1, 183):
        raise ValueError("expected ARM64 relocatable KPM")
    start, entry_size, count, names_index = header[6], header[11], header[12], header[13]
    if entry_size != 64 or not count or names_index >= count or start + count * 64 > len(data):
        raise ValueError("invalid section table")
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, start + i * 64) for i in range(count)]
    return entries, names_index


def sections(data):
    entries, names_index = elf_sections(data)
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
    if ".data.re_offsets" not in result:
        raise ValueError("missing .data.re_offsets")
    offset, size, index, flags = result[".data.re_offsets"]
    if flags & 3 != 3 or size == 0 or size % 2:
        raise ValueError("invalid writable offset table")
    if any(entry[1] in (4, 9) and entry[7] == index and entry[5] for entry in entries):
        raise ValueError("offset table must not contain relocations")
    abi = None
    if ".rodata.re_abi" in result:
        abi_offset, abi_size, _, _ = result[".rodata.re_abi"]
        if abi_size != 4:
            raise ValueError("invalid Binder ABI tag")
        abi = struct.unpack_from("<I", data, abi_offset)[0]
        if abi not in (3, 4, 5, 6):
            raise ValueError("unknown Binder ABI")
    return offset, size, abi


def source_fields(source):
    text = source.read_text()
    body = re.search(r"struct struct_offset\s*\{([^}]+)\};", text).group(1)
    fields = re.findall(r"int16_t\s+(\w+)\s*;", body)
    if re.sub(r"int16_t\s+\w+\s*;", "", body).strip() or len(set(fields)) != len(fields):
        raise ValueError("offset schema must contain only unique int16_t fields")
    return fields


def table_abi(data, offset, size, fields, fixed_abi):
    if fixed_abi is not None:
        if "binder_release_abi" in fields:
            raise ValueError("fixed ABI baseline cannot select another release ABI")
        return fixed_abi
    if "binder_release_abi" not in fields:
        return None
    if fields[-1] != "binder_release_abi":
        raise ValueError("unified baseline requires binder_release_abi as the last field")
    abi = struct.unpack_from("<h", data, offset + size - 2)[0]
    if abi not in (3, 4, 5, 6):
        raise ValueError("binder_release_abi must be 3, 4, 5 or 6")
    return abi


def read_layout(path, data, offset, size, fixed_abi):
    layout = json.loads(path.read_text())
    fields = layout["fields"]
    abi = table_abi(data, offset, size, fields, fixed_abi)
    schema = 3 if abi is None else (1 if fixed_abi is not None else 2)
    if (any(type(layout.get(key)) is not int for key in ("schema", "table_offset", "table_size"))
            or (abi is not None and type(layout.get("binder_abi")) is not int)
            or layout["schema"] != schema or layout["sha256"] != sha256(data)
            or layout["table_offset"] != offset
            or layout["table_size"] != size or len(fields) * 2 != size
            or not isinstance(fields, list) or not all(isinstance(field, str) and field for field in fields)
            or len(set(fields)) != len(fields)):
        raise ValueError("layout does not match this KPM")
    if layout.get("binder_abi") != abi:
        raise ValueError("layout release ABI does not match this KPM")
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


def elf_symbols(data):
    entries, _ = elf_sections(data)
    result = []
    for index, entry in enumerate(entries):
        if entry[1] != 2:
            continue
        if entry[9] != 24 or entry[5] % 24 or entry[4] + entry[5] > len(data) or entry[6] >= len(entries):
            raise ValueError("invalid symbol table")
        strings = entries[entry[6]]
        if strings[1] != 3 or strings[4] + strings[5] > len(data):
            raise ValueError("invalid symbol strings")
        names = data[strings[4]:strings[4] + strings[5]]
        for at in range(entry[4], entry[4] + entry[5], 24):
            name, info, _, section, _, _ = struct.unpack_from("<IBBHQQ", data, at)
            end = names.find(b"\0", name)
            if name >= len(names) or end < 0:
                raise ValueError("invalid symbol name")
            result.append((index, (at - entry[4]) // 24, names[name:end], info, section, strings[4] + name, entry[6]))
    return result


def legacy_lookup(data):
    # KP 导出的原名查找是函数指针变量；本地转接必须先取出指针。
    entries, names_index = elf_sections(data)
    if sum(entry[1] == 2 for entry in entries) != 1:
        raise ValueError("KP lookup adapter requires exactly one symbol table")
    symbols = elf_symbols(data)
    targets = [symbol for symbol in symbols if symbol[2] == b"kallsyms_lookup_name_by_suffix"]
    pointers = [symbol for symbol in symbols if symbol[2] == b"kallsyms_lookup_name"]
    if len(targets) != 1 or len(pointers) > 1:
        raise ValueError("requires one suffix function import and at most one lookup pointer import")
    target = targets[0]
    if any(symbol[4] or symbol[3] >> 4 != 1 for symbol in targets + pointers) or any(
            pointer[0] != target[0] for pointer in pointers):
        raise ValueError("lookup adapter requires undefined global imports in the same symbol table")
    if len(entries) + 2 >= 0xff00:
        raise ValueError("extended section indices are not supported")
    names = entries[names_index]
    if names[1] != 3 or names[4] + names[5] > len(data):
        raise ValueError("invalid section names")
    strings = data[names[4]:names[4] + names[5]]
    text_name = b".text.kpm_legacy_lookup\0"
    rela_name = b".rela.text.kpm_legacy_lookup\0"
    if text_name in strings:
        raise ValueError("lookup adapter already exists")
    patched = bytearray(data)

    def append(payload, alignment):
        patched.extend(bytes((-len(patched)) % alignment))
        offset = len(patched)
        patched.extend(payload)
        return offset

    entries = [list(entry) for entry in entries]
    if pointers:
        pointer_index = pointers[0][1]
    else:
        # 追加全局导入，保留既有符号索引及 sh_info 的局部符号边界。
        symtab = entries[target[0]]
        strtab = entries[symtab[6]]
        pointer_index = symtab[5] // 24
        pointer_name = strtab[5]
        symbol_names = data[strtab[4]:strtab[4] + strtab[5]] + b"kallsyms_lookup_name\0"
        symbol_data = data[symtab[4]:symtab[4] + symtab[5]] + struct.pack("<IBBHQQ", pointer_name, 0x11, 0, 0, 0, 0)
        if symtab[6] == names_index:
            strings = symbol_names
        else:
            strtab[4:6] = [append(symbol_names, 1), len(symbol_names)]
        symtab[4:6] = [append(symbol_data, 8), len(symbol_data)]

    text_index = len(entries)
    text = struct.pack("<III", 0x90000010, 0xf9400210, 0xd61f0200)  # adrp x16; ldr x16; br x16
    text_offset = append(text, 4)
    relas = struct.pack("<QQqQQq", 0, pointer_index << 32 | 275, 0, 4, pointer_index << 32 | 286, 0)
    rela_offset = append(relas, 8)
    names_offset = append(strings + text_name + rela_name, 1)
    entries[names_index][4:6] = [names_offset, len(strings + text_name + rela_name)]
    entries.append([len(strings), 1, 6, 0, text_offset, len(text), 0, 0, 4, 0])
    entries.append([len(strings + text_name), 4, 0, 0, rela_offset, len(relas), target[0], text_index, 8, 24])
    # 原调用仍指向同一符号索引；将函数导入定义为本地可执行转接。
    symbol_offset = entries[target[0]][4] + target[1] * 24
    name, info, other, _, _, _ = struct.unpack_from("<IBBHQQ", patched, symbol_offset)
    struct.pack_into("<IBBHQQ", patched, symbol_offset, name, info & 0xf0 | 2, other, text_index, 0, len(text))
    section_offset = append(b"".join(struct.pack("<IIQQQQIIQQ", *entry) for entry in entries), 8)
    struct.pack_into("<Q", patched, 40, section_offset)
    struct.pack_into("<H", patched, 60, len(entries))
    ranges = [{"offset": 40, "size": 8}, {"offset": 60, "size": 2}]
    if symbol_offset < len(data):
        ranges.append({"offset": symbol_offset, "size": 24})
    ranges.append({"offset": len(data), "size": len(patched) - len(data)})
    return bytes(patched), ranges, 1, not pointers


def legacy_kp(args, data):
    patched, ranges, count, pointer_added = legacy_lookup(data)
    layout_path = args.layout or Path(str(args.kpm) + ".json")
    layout = None
    if args.layout or layout_path.exists():
        offset, size, fixed_abi = sections(data)
        layout = read_layout(layout_path, data, offset, size, fixed_abi)
    receipt_path = Path(str(args.output) + ".compat.json")
    layout_output = Path(str(args.output) + ".json")
    if args.output.exists() or receipt_path.exists() or layout_output.exists():
        raise FileExistsError("output KPM or receipt/layout already exists; choose a new path")
    receipt = {"schema": 1, "kind": "binary-port", "kpm": args.output.name,
               "parent_kpm": args.kpm.name, "parent_sha256": sha256(data), "sha256": sha256(patched),
               "lookup_mode": "exact", "import_from": "kallsyms_lookup_name_by_suffix",
               "pointer_import": "kallsyms_lookup_name", "pointer_import_added": pointer_added,
               "adapter": "adrp-ldr-br-x16",
               "imports_resolved": count, "modified_ranges": ranges}
    created = []
    try:
        with args.output.open("xb") as stream:
            created.append(args.output)
            stream.write(patched)
        if layout is not None:
            with layout_output.open("x") as stream:
                created.append(layout_output)
                json.dump(dict(layout, kpm=args.output.name, parent_sha256=sha256(data), sha256=sha256(patched)),
                          stream, indent=2)
                stream.write("\n")
        with receipt_path.open("x") as stream:
            created.append(receipt_path)
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
    except Exception:
        for path in reversed(created):
            path.unlink()
        raise
    return receipt


def run(args):
    data = args.kpm.read_bytes()
    if args.command == "legacy-kp":
        return legacy_kp(args, data)
    offset, size, fixed_abi = sections(data)
    if args.command == "baseline":
        fields = source_fields(args.source)
        if len(fields) * 2 != size:
            raise ValueError("source fields do not match offset table size")
        abi = table_abi(data, offset, size, fields, fixed_abi)
        layout = {
            "schema": 3 if abi is None else (1 if fixed_abi is not None else 2),
            "kpm": args.kpm.name,
            "sha256": sha256(data),
            "table_offset": offset,
            "table_size": size,
            "fields": fields,
            "offsets": table_values(data, offset, size, fields),
        }
        if abi is not None:
            layout["binder_abi"] = abi
        write_json(args.output, layout)
        return {"binder_abi": abi, "table_bytes": size, "sha256": layout["sha256"]}

    layout_path = args.layout or Path(str(args.kpm) + ".json")
    layout = read_layout(layout_path, data, offset, size, fixed_abi)
    abi = layout.get("binder_abi")
    if args.command == "dump":
        with args.output.open("xb") as stream:
            stream.write(data[offset:offset + size])
        return {"binder_abi": abi, "bytes": size, "sha256": sha256(data[offset:offset + size])}

    payload = args.blob.read_bytes() if args.blob else encode_offsets(args.offsets, layout["fields"])
    if len(payload) != size:
        raise ValueError(f"offset blob must be exactly {size} bytes")
    abi = table_abi(payload, 0, size, layout["fields"], fixed_abi)
    # 工具端核对编码宽度；不在模块中加入运行时偏移推导或检查。
    if "genl_family_n_mcgrps_size" in layout["fields"]:
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
    if abi is not None:
        receipt["binder_abi"] = abi
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
    for command in ("baseline", "dump", "patch", "legacy-kp"):
        help_text = "旧 KP 缺少后缀查找导出时，生成原名函数指针转接兼容件" if command == "legacy-kp" else None
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("kpm", type=Path)
        subparser.add_argument("--output", type=Path, required=True)
        if command == "baseline":
            subparser.add_argument("--source", type=Path, required=True, help="同一构建提交的模块偏移表源文件")
        else:
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
