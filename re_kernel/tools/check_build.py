#!/usr/bin/env python3
"""Developer 自检：核对探索 KPM 的导入和 ARM64 操作数，不代替运行端导出及独立审计。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--kp", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    exports = set()
    for path in (args.kp / "kernel").rglob("*"):
        if path.suffix not in (".c", ".h", ".S"):
            continue
        source = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(errors="replace"), flags=re.S)
        for kind, name in re.findall(r"KP_EXPORT_SYMBOL\(\s*(kfunc|kvar)\((\w+)\)\s*\)", source):
            exports.add(("kf_" if kind == "kfunc" else "kv_") + name)
        exports.update(re.findall(r"KP_EXPORT_SYMBOL\(\s*(\w+)\s*\)", source))
    results = []
    files = sorted(args.build.glob("*.kpm"))
    if not files:
        raise SystemExit("没有 KPM 产物")
    for path in files:
        imports = re.findall(r"\bU (\w+)", subprocess.check_output(
            [str(args.llvm_bin / "llvm-nm"), "-u", str(path)], text=True))
        missing = sorted(set(imports) - exports)
        disassembly = subprocess.check_output(
            [str(args.llvm_bin / "llvm-objdump"), "-d", "--no-show-raw-insn", str(path)], text=True)
        bad = []
        for line in disassembly.splitlines():
            match = re.match(r"\s*[0-9a-f]+:\s*(\S+)\s*(.*)", line)
            if not match:
                continue
            # 只匹配操作数，指令地址如 b0、d0 不是浮点寄存器。
            operands = match[2].split("<", 1)[0]
            if re.search(r"\b[vdqsbhzp][0-9]+\b|\b[wx]18\b", operands):
                bad.append(line)
        assert not missing, (path.name, missing)
        assert not bad, (path.name, bad)
        assert not set(imports) & {"kf_get_task_ext", "memset", "memcpy"}, (path.name, imports)
        results.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "size": path.stat().st_size, "imports": imports, "missing_sdk_exports": missing,
                        "unexpected_registers": bad,
                        "disassembly_sha256": hashlib.sha256(disassembly.encode()).hexdigest()})
        print(path.name, len(imports), "SDK exports; no FP/SIMD/SVE/x18 operands")
    with args.output.open("x") as stream:
        json.dump({"scope": "Developer selfcheck against SDK source; not device export proof",
                   "results": results}, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
