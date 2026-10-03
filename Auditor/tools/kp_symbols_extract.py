#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""平台符号快照：从 KernelPatch submodule 提取 KPM 可用的运行时符号。

来源（两份，互为补充）:
  1. KernelPatch/lkm/kpm/symbols.c 的 kp_kpm_symbols[]（LKM 侧兼容符号表）
  2. KernelPatch/kernel/** 的 KP_EXPORT_SYMBOL(...)（内核侧导出）

输出: Auditor/snapshots/kp_runtime_symbols-<commit12>.json

独立性：本工具只读 KernelPatch 平台源码，不读模块源码、不调用 tools/identity.py、
不调用 kernel_img/offset_harness。快照一旦生成即固定，模块重新构建不会改变它。
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KERNELPATCH = os.path.join(REPO, "KernelPatch")

KVAR_RE = re.compile(r"KP_EXPORT_SYMBOL\s*\(\s*kvar\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)")
KFUNC_RE = re.compile(r"KP_EXPORT_SYMBOL\s*\(\s*kfunc\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)")
PLAIN_RE = re.compile(r"KP_EXPORT_SYMBOL\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
LKM_ENTRY_RE = re.compile(r'\{\s*"([^"]+)"\s*,')


def git(args, cwd=REPO):
    try:
        return subprocess.run(["git", "-C", cwd] + args, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def extract_lkm_symbols():
    path = os.path.join(KERNELPATCH, "lkm", "kpm", "symbols.c")
    if not os.path.isfile(path):
        return {}
    text = open(path, encoding="utf-8", errors="replace").read()
    start = text.find("kp_kpm_symbols[]")
    if start < 0:
        return {}
    body = text[start:]
    end = body.find("};")
    if end > 0:
        body = body[:end]
    return {name: "lkm/kpm/symbols.c" for name in LKM_ENTRY_RE.findall(body)}


def extract_kernel_symbols():
    symbols = {}
    for dirpath, dirs, names in os.walk(KERNELPATCH):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for name in names:
            if not name.endswith((".c", ".h")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, REPO)
            text = open(path, encoding="utf-8", errors="replace").read()
            if "KP_EXPORT_SYMBOL" not in text:
                continue
            for match in KVAR_RE.finditer(text):
                symbols[f"kv_{match.group(1)}"] = rel
            for match in KFUNC_RE.finditer(text):
                symbols[f"kf_{match.group(1)}"] = rel
            for match in PLAIN_RE.finditer(text):
                symbols[match.group(1)] = rel
    return symbols


def main():
    ap = argparse.ArgumentParser(description="提取 KernelPatch KPM 运行时符号快照")
    ap.add_argument("--out-dir", default=os.path.join(REPO, "Auditor", "snapshots"))
    args = ap.parse_args()

    if not os.path.isdir(KERNELPATCH):
        print("error: KernelPatch submodule 不存在，先 git submodule update --init", file=sys.stderr)
        return 2

    commit = git(["rev-parse", "HEAD"], cwd=KERNELPATCH)
    version = ""
    version_file = os.path.join(KERNELPATCH, "version")
    if os.path.isfile(version_file):
        version = open(version_file, encoding="utf-8", errors="replace").read().strip()

    lkm = extract_lkm_symbols()
    kernel = extract_kernel_symbols()
    symbols = {}
    for name in sorted(set(lkm) | set(kernel)):
        symbols[name] = sorted({s for s in (lkm.get(name), kernel.get(name)) if s})

    snapshot = {
        "source": "KernelPatch (lkm/kpm/symbols.c + kernel/**/KP_EXPORT_SYMBOL)",
        "kernelpatch_commit": commit,
        "kernelpatch_version": version,
        "extracted_at": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "extracted_by": "Auditor/tools/kp_symbols_extract.py",
        "count": len(symbols),
        "symbols": symbols,
    }
    os.makedirs(args.out_dir, exist_ok=True)
    out = os.path.join(args.out_dir, f"kp_runtime_symbols-{commit[:12] or 'unknown'}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"snapshot: {os.path.relpath(out, REPO)}")
    print(f"KernelPatch {version} @ {commit[:12]}，{len(symbols)} 个符号（lkm {len(lkm)}，kernel {len(kernel)}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
