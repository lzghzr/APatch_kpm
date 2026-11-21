#!/usr/bin/env python3
"""核对已发布的配套 ZIP：字节身份必须与已验收实例一致，可执行必须能在目标 Android 上加载。

发版后（或替换 Release 资产后）对下载到的 ZIP 跑一次独立核对。
判据来源 DEV-117：CI 曾用 NDK 出件，arm64 可执行在 Android 17 被 Bionic 的 TLS 段对齐检查
（`alignment is 8, needs to be at least 64`）直接 abort；审计过的 Zig/musl 件不受该检查约束。
"""
import argparse
import hashlib
import json
import struct
import sys
import zipfile

BIONIC_TLS_ALIGN_MIN = 64


def elf_facts(data):
    """返回 (PT_TLS 对齐, 是否动态链接, 是否 Bionic 链接)；非 ELF64-LE 返回 None。"""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    entsize = struct.unpack_from("<H", data, 0x36)[0]
    count = struct.unpack_from("<H", data, 0x38)[0]
    tls, dynamic = None, False
    for i in range(count):
        off = phoff + i * entsize
        kind = struct.unpack_from("<I", data, off)[0]
        if kind == 7:
            tls = struct.unpack_from("<Q", data, off + 48)[0]
        elif kind in (2, 3):
            dynamic = True
    bionic = dynamic or b"BIONIC" in data or b"bionic" in data
    return tls, dynamic, bionic


def main():
    ap = argparse.ArgumentParser(description="核对发布 ZIP 的身份与可加载性")
    ap.add_argument("zip")
    ap.add_argument("--metadata", default="metadata/modules/nomount.json")
    ap.add_argument("--binary", default="bin/nm")
    args = ap.parse_args()

    problems, notes = [], []
    try:
        record = json.load(open(args.metadata, encoding="utf-8"))
    except OSError:
        record = {"packages": []}
    packages = [p for p in record.get("packages", []) if p.get("kind") == "companion-zip"]
    accepted = {p["inner_bin"]["sha256"]: p for p in packages if (p.get("inner_bin") or {}).get("sha256")}
    tested = {h: p for h, p in accepted.items() if p.get("status") == "device-tested"}

    zf = zipfile.ZipFile(args.zip)
    names = zf.namelist()
    payload = zf.read(args.binary) if args.binary in names else b""
    if not payload:
        problems.append(f"ZIP 内缺少 {args.binary}")
    else:
        digest = hashlib.sha256(payload).hexdigest()
        if digest in tested:
            notes.append(f"{args.binary} 与已验收实例 {tested[digest].get('instance_id')} 逐字节一致")
        elif digest in accepted:
            problems.append(f"{args.binary} 属已登记但未经真机验证的实例 {accepted[digest].get('instance_id')}")
        else:
            problems.append(f"{args.binary} 的 sha256 {digest[:16]}… 不是任何已登记实例的内层二进制"
                            f"（已登记：{', '.join(sorted(h[:16] + '…' for h in accepted))}）")
        facts = elf_facts(payload)
        if facts is None:
            problems.append(f"{args.binary} 不是 ELF64-LE 可执行")
        else:
            tls, dynamic, bionic = facts
            notes.append(f"PT_TLS 对齐 {tls}，{'动态' if dynamic else '静态'}链接，"
                         f"{'Bionic 链接' if bionic else '非 Bionic'}")
            if bionic and tls is not None and tls < BIONIC_TLS_ALIGN_MIN:
                problems.append(f"Bionic 链接的可执行 TLS 段对齐 {tls} < {BIONIC_TLS_ALIGN_MIN}："
                                "Android 会以 'TLS segment is underaligned' abort（DEV-117）")

    prop = zf.read("module.prop").decode("utf-8", "replace") if "module.prop" in names else ""
    version = next((l.split("=", 1)[1].strip() for l in prop.splitlines() if l.startswith("version=")), "")
    versions = {p.get("version") for p in packages if p.get("version")}
    if version and versions and version.removeprefix("v") not in versions:
        problems.append(f"module.prop 版本 {version} 不在已登记的配套版本 {sorted(versions)} 中")
    counts = {p.get("zip_entries") for p in packages if p.get("zip_entries")}
    if counts and len(names) not in counts:
        problems.append(f"条目数 {len(names)} 与已登记 {sorted(counts)} 不一致")
    notes.append(f"module.prop 版本 {version or '(缺失)'}；条目数 {len(names)}")

    print(f"ZIP: {args.zip}")
    print(f"sha256: {hashlib.sha256(open(args.zip, 'rb').read()).hexdigest()}")
    for note in notes:
        print(f"  · {note}")
    if problems:
        print("结论：不通过")
        for p in problems:
            print(f"  ! {p}")
        return 1
    print("结论：通过（字节与已验收实例一致，可在目标 Android 上加载）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
