#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""检查当次编译 KPM 与配套布局，生成提交绑定的产物清单和 SHA256SUMS。"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path


def elf_sections(data):
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("需要 ELF64 little-endian")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1:4] != (1, 183, 1) or header[8] != 64:
        raise ValueError("需要 AArch64 ET_REL")
    start, width, count, names_index = header[6], header[11], header[12], header[13]
    if width != 64 or not count or names_index >= count or start < 64 or start + count * width > len(data):
        raise ValueError("节表越界或无效")
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, start + i * width) for i in range(count)]
    names = entries[names_index]
    if names[1] != 3 or names[4] + names[5] > len(data):
        raise ValueError("节名表无效")
    strings = data[names[4]:names[4] + names[5]]
    sections = {}
    for entry in entries:
        end = strings.find(b"\0", entry[0])
        if entry[0] >= len(strings) or end < 0:
            raise ValueError("节名越界或未终止")
        name = strings[entry[0]:end].decode("ascii")
        if name and name in sections:
            raise ValueError("节名重复")
        if entry[1] != 8 and entry[4] + entry[5] > len(data):
            raise ValueError("节内容越界")
        if name:
            sections[name] = (entry, data[entry[4]:entry[4] + entry[5]] if entry[1] != 8 else b"")
    return sections


def inspect_kpm(path):
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.kpm", path.name):
        raise ValueError("产物文件名无效")
    data = path.read_bytes()
    sections = elf_sections(data)
    info = {}
    section, raw = sections.get(".kpm.info", (None, b""))
    if section is None or section[1] != 1 or not raw.endswith(b"\0"):
        raise ValueError("缺少有效 .kpm.info")
    for item in raw.split(b"\0"):
        if not item:
            continue
        key, separator, value = item.decode("utf-8").partition("=")
        if not separator or key in info or not value:
            raise ValueError("KPM 字段无效或重复")
        info[key] = value
    for key, limit in (("name", 32), ("version", 32), ("license", 32), ("author", 32), ("description", 512)):
        if key not in info or len(info[key].encode()) >= limit:
            raise ValueError(f"KPM 字段 {key} 缺失或过长")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", info["name"]):
        raise ValueError("模块名无效")
    for name in (".kpm.init", ".kpm.exit"):
        section, raw = sections.get(name, (None, b""))
        if section is None or section[1] != 1 or len(raw) != 8:
            raise ValueError(f"缺少有效 {name}")
    if not path.name.startswith(info["name"] + "_"):
        raise ValueError("产物文件名与模块注册名不一致")
    version = re.sub(r"_(n|d|nd|network|debug|network_debug)$", "", info["version"])
    prefix = info["name"] + "_" + version
    if not path.name.startswith(prefix) or path.name[len(prefix):len(prefix) + 1] not in ("_", "."):
        raise ValueError("产物文件名与内嵌版本不一致")
    mode = info.get("offset_mode")
    if mode is not None:
        if mode not in ("static", "dynamic"):
            raise ValueError("偏移模式无效")
        debug = info["version"].endswith("_d")
        expected = prefix + ("_baselines" if mode == "static" else "") + ("_debug" if debug else "") + ".kpm"
        if path.name != expected:
            raise ValueError("产物文件名与偏移模式不一致")
    return {"file": path.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "info": info}, sections


def inspect_layout(path, kpm, sections):
    layout = json.loads(path.read_text())
    offset_section, raw = sections[".data.re_offsets"]
    fields = layout["fields"]
    if (any(type(layout.get(key)) is not int for key in ("schema", "table_offset", "table_size"))
            or layout.get("schema") not in (1, 2, 3) or layout.get("kpm") != kpm["file"]
            or layout.get("sha256") != kpm["sha256"]
            or layout.get("table_offset") != offset_section[4]
            or layout.get("table_size") != len(raw) or not raw or len(raw) % 2
            or offset_section[1] != 1 or offset_section[2] & 3 != 3
            or not isinstance(fields, list) or not all(isinstance(f, str) and f for f in fields)
            or len(fields) != len(set(fields)) or len(fields) * 2 != len(raw)):
        raise ValueError("布局字段与 KPM 字节不一致")
    if layout["schema"] in (1, 2):
        if type(layout.get("binder_abi")) is not int or layout["binder_abi"] not in (3, 4, 5, 6):
            raise ValueError("Binder 布局必须记录有效释放 ABI")
    elif (kpm["info"]["name"] in ("re_kernel", "re_kernel_x") or "binder_abi" in layout
          or "binder_release_abi" in fields or ".rodata.re_abi" in sections):
        raise ValueError("普通偏移布局不能代替 Binder ABI 布局")
    values = dict(zip(fields, struct.unpack(f"<{len(fields)}h", raw)))
    if layout["schema"] == 1:
        abi_section, abi_raw = sections[".rodata.re_abi"]
        filename = re.fullmatch(r"re_kernel_x_(.+)_abi([3-6])(_debug)?\.kpm", kpm["file"])
        if (not filename or int(filename[2]) != layout["binder_abi"]
                or kpm["info"]["version"] != filename[1] + ("_d" if filename[3] else "")
                or abi_section[1] != 1 or len(abi_raw) != 4
                or layout["binder_abi"] != struct.unpack("<I", abi_raw)[0]
                or "binder_release_abi" in fields):
            raise ValueError("固定 ABI 产物文件名、标记或布局不一致")
    elif layout["schema"] == 2:
        version = kpm["info"]["version"]
        debug = version.endswith("_d")
        mode = kpm["info"].get("offset_mode")
        name = kpm["info"]["name"] + "_" + (version[:-2] if debug else version)
        name += ("_baselines" if mode == "static" else "") + ("_debug" if debug else "") + ".kpm"
        if (".rodata.re_abi" in sections or fields[-1] != "binder_release_abi"
                or values["binder_release_abi"] != layout["binder_abi"] or kpm["file"] != name):
            raise ValueError("统一基线文件名或配置中的 Binder 释放 ABI 不一致")
    recorded = layout["offsets"]
    if not isinstance(recorded, dict) or set(recorded) != set(values):
        raise ValueError("布局偏移字段集合不一致")
    for field, value in recorded.items():
        number = int(value, 0) if isinstance(value, str) else value
        if type(number) is not int or number != values[field]:
            raise ValueError("布局偏移值与 KPM 字节不一致")
    return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def validate(directory, expected=()):
    files = sorted(directory.glob("*.kpm"))
    if not files:
        raise ValueError("没有编译产物")
    artifacts, modules, layouts = [], set(), set()
    for path in files:
        artifact, sections = inspect_kpm(path)
        module = artifact["info"]["name"]
        modules.add(module)
        layout_path = Path(str(path) + ".json")
        mode = artifact["info"].get("offset_mode")
        if mode == "dynamic" and layout_path.exists():
            raise ValueError("动态产物不应附带静态布局")
        if mode == "static" or (module == "re_kernel_x" and mode is None) or layout_path.exists():
            artifact["layout"] = inspect_layout(layout_path, artifact, sections)
            layouts.add(layout_path.name)
        artifacts.append(artifact)
    if {p.name for p in directory.glob("*.kpm.json")} != layouts:
        raise ValueError("存在孤立的 KPM 布局文件")
    if expected and modules != set(expected):
        raise ValueError(f"编译模块集合不一致：需要 {sorted(expected)}，得到 {sorted(modules)}")
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--modules", type=Path, help="当次构建选择的模块清单")
    args = parser.parse_args()
    try:
        expected = args.modules.read_text().splitlines() if args.modules else []
        if args.modules and not expected:
            raise ValueError("构建模块清单为空")
        artifacts = validate(args.directory, expected)
        repo = Path(__file__).resolve().parent.parent
        def commit(directory):
            return subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
        manifest = {"schema": 1, "source_commit": commit(repo), "kernelpatch_commit": commit(repo / "KernelPatch"),
                    "artifacts": artifacts}
        (args.directory / "BUILD_MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        names = {"BUILD_MANIFEST.json"}
        for item in artifacts:
            names.add(item["file"])
            if "layout" in item:
                names.add(item["layout"]["file"])
        sums = "".join(f"{hashlib.sha256((args.directory / name).read_bytes()).hexdigest()}  {name}\n" for name in sorted(names))
        (args.directory / "SHA256SUMS").write_text(sums)
        print(f"产物门禁通过：{len(artifacts)} 份 KPM，{len(names)} 份文件哈希已记录")
    except (OSError, ValueError, KeyError, TypeError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f"产物门禁失败：{error}\n")


if __name__ == "__main__":
    main()
