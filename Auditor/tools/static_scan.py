#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""边界扫描 + 安全评估（启发式静态扫描）。

产出的是**审查点**，不是结论：每条命中都要 Auditor 人工确认或标为未验证。
本工具不调用实现方脚本、不读实现方的偏移结论；只读模块源码文本。

扫描的 pattern（见 Auditor/reports 中的说明）:
  1. free_without_null       释放后未把静态/全局指针置空（释放后使用/双重释放风险）
  2. user_input_no_auth      处理 netlink/用户输入的函数里没有任何 uid/cred 校验
  3. sleep_in_callback       hook/tracepoint 回调路径里出现可能睡眠的操作（需人工确认上下文）
  4. unbounded_copy          无界拷贝/格式化（sprintf/strcpy/strcat，或长度来自结构体字段）
  5. bounded_loop_field      以结构体字段为界的循环写入固定缓冲（需核对边界）
  6. sentinel_use            IZERO/UZERO 等哨兵的使用点（核对「未设置」与「全部」语义）
  7. unchecked_shift         对结构体字段做移位/算术后直接使用（如 th->doff << 2）

用法:
  python3 Auditor/tools/static_scan.py re_kernel
  python3 Auditor/tools/static_scan.py re_kernel --json Auditor/reports/data/<name>.json
  python3 Auditor/tools/static_scan.py re_kernel --strict     # free_without_null 命中时返回 1
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FREE_CALLS = ("proc_remove", "remove_proc_entry", "netlink_kernel_release", "kfree(", "kvfree(",
              "kfree_skb", "release_firmware")
AUTH_MARKERS = ("task_uid", "cred", "uid", "from_kuid", "NETLINK_CB", "current_uid", "kuid_t")
SLEEP_MARKERS = ("GFP_KERNEL", "memdup_user", "kmalloc(", "kzalloc(", "vmalloc(", "proc_mkdir",
                 "proc_create", "netlink_kernel_create", "kstrdup(", "kasprintf(", "sprintf(")
UNBOUNDED_CALLS = ("sprintf(", "strcpy(", "strcat(", "vsprintf(", "gets(")
FIELD_LOOP_RE = re.compile(r"for\s*\([^;]*;[^;]*(?:->|\.)\w+\s*[<>]=?[^;]*;")
SHIFT_RE = re.compile(r"(?:->|\.)(\w+)\s*(?:<<|>>)\s*(\d+)")
SENTINEL_RE = re.compile(r"\b(IZERO|UZERO|izero|uzero)\b")


def strip_comments(text):
    """去掉注释与字符串字面量，保留行号结构。"""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
        elif ch in "\"'":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def functions(text):
    """粗粒度函数切分：返回 [(name, start_line, body)]。"""
    lines = text.splitlines()
    result = []
    depth = 0
    name = None
    start = 0
    buf = []
    header = re.compile(r"^[A-Za-z_][\w \t\*]*\b(\w+)\s*\([^;]*\)\s*\{?\s*$")
    for lineno, line in enumerate(lines, 1):
        if depth == 0:
            m = header.match(line.strip())
            if m and "(" in line and ";" not in line:
                name, start, buf = m.group(1), lineno, [line]
                depth += line.count("{") - line.count("}")
                if depth == 0 and "{" in line:
                    result.append((name, start, "\n".join(buf)))
                    name = None
                continue
        if name is not None:
            buf.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                result.append((name, start, "\n".join(buf)))
                name = None
                depth = 0
    return result


def scan_file(path):
    raw = open(path, encoding="utf-8", errors="replace").read()
    text = strip_comments(raw)
    lines = text.splitlines()
    rel = os.path.relpath(path, REPO)
    hits = []
    funcs = functions(text)

    # 1. free_without_null / 6. sentinel / 3. sleep_in_callback / 4. unbounded_copy
    for fname, start, body in funcs:
        for offset, line in enumerate(body.splitlines()):
            lineno = start + offset
            stripped = line.strip()

            for call in FREE_CALLS:
                if call not in line:
                    continue
                inner = re.search(re.escape(call.rstrip("(")) + r"\s*\(\s*([A-Za-z_]\w*)", line)
                if not inner:
                    continue
                target = inner.group(1)
                if target in ("NULL", "skb", "buffer", "t", "buf"):
                    continue
                # 局部变量不算（只有全局/静态指针的悬挂才影响卸载/二次释放）
                if re.search(rf"\b[A-Za-z_][\w \t\*]*\b{re.escape(target)}\s*(?:=|;|,|\[)", body):
                    continue
                # 该标识符在后面（或全文件任意位置）是否被置空
                tail = "\n".join(lines[lineno:])
                if not re.search(rf"\b{re.escape(target)}\s*=\s*(NULL|0)\b", tail):
                    hits.append({
                        "pattern": "free_without_null", "file": rel, "line": lineno,
                        "code": stripped,
                        "note": f"{call.rstrip('(')} 释放 {target} 后未置空；若该指针是全局/静态变量，卸载或二次释放会触发释放后使用",
                    })

            if re.search(r"\b(IZERO|UZERO)\b", line):
                hits.append({
                    "pattern": "sentinel_use", "file": rel, "line": lineno, "code": stripped,
                    "note": "哨兵值使用点：确认「未设置/未知」与「全部/最强」语义没有被混用",
                })

            if any(marker in line for marker in SLEEP_MARKERS):
                hits.append({
                    "pattern": "sleep_in_callback", "file": rel, "line": lineno, "code": stripped,
                    "note": f"函数 {fname} 内出现可能睡眠/分配操作；需确认调用路径是否持锁或在原子上下文",
                })

            for call in UNBOUNDED_CALLS:
                if call in line:
                    hits.append({
                        "pattern": "unbounded_copy", "file": rel, "line": lineno, "code": stripped,
                        "note": f"{call.rstrip('(')} 无长度上限；核对目标缓冲大小与来源长度",
                    })

            m = SHIFT_RE.search(line)
            if m and re.search(r"->", line):
                hits.append({
                    "pattern": "unchecked_shift", "file": rel, "line": lineno, "code": stripped,
                    "note": f"对字段 {m.group(1)} 做移位后直接使用；核对字段取值范围与溢出",
                })

    # 2. user_input_no_auth：含 netlink/nlmsghdr 的函数里没有 uid/cred 校验
    for fname, start, body in funcs:
        if not re.search(r"nlmsghdr|netlink|__user|copy_from_user", body):
            continue
        if not any(marker in body for marker in AUTH_MARKERS):
            first = next((start + i for i, l in enumerate(body.splitlines()) if re.search(r"nlmsghdr|netlink|__user", l)), start)
            hits.append({
                "pattern": "user_input_no_auth", "file": rel, "line": first,
                "code": f"函数 {fname}",
                "note": "处理用户输入（netlink/proc）但未见发送方身份校验；可达性取决于 netlink 协议号权限与 SELinux 策略，需真机确认",
            })

    # 5. bounded_loop_field：以结构体字段为界的循环写固定缓冲
    for fname, start, body in funcs:
        for offset, line in enumerate(body.splitlines()):
            if FIELD_LOOP_RE.search(line):
                hits.append({
                    "pattern": "bounded_loop_field", "file": rel, "line": start + offset, "code": line.strip(),
                    "note": "循环上界来自结构体字段；核对目标缓冲/索引的边界条件",
                })
    return hits


def main():
    ap = argparse.ArgumentParser(description="边界扫描 + 安全评估（启发式）")
    ap.add_argument("module")
    ap.add_argument("--json")
    ap.add_argument("--strict", action="store_true", help="free_without_null 命中时返回非零")
    args = ap.parse_args()

    mdir = os.path.join(REPO, args.module)
    if not os.path.isdir(mdir):
        print(f"error: 模块目录不存在 {args.module}", file=sys.stderr)
        return 2
    files = sorted(glob.glob(os.path.join(mdir, "**", "*.c"), recursive=True) +
                   glob.glob(os.path.join(mdir, "**", "*.h"), recursive=True))
    all_hits = []
    for path in files:
        all_hits.extend(scan_file(path))

    by_pattern = {}
    for h in all_hits:
        by_pattern.setdefault(h["pattern"], []).append(h)

    report = {
        "tool": "Auditor/tools/static_scan.py",
        "scanned_at": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "module": args.module,
        "files": [os.path.relpath(f, REPO) for f in files],
        "heuristic": True,
        "counts": {k: len(v) for k, v in sorted(by_pattern.items())},
        "hits": all_hits,
    }

    print(f"# 边界/安全静态扫描（启发式）：{args.module}")
    print()
    print(f"- 扫描文件：{', '.join(report['files'])}")
    print(f"- 命中统计：{report['counts'] or '无'}")
    print()
    for pattern in sorted(by_pattern):
        print(f"## {pattern}（{len(by_pattern[pattern])} 处）")
        print()
        for h in by_pattern[pattern]:
            print(f"- `{h['file']}:{h['line']}` {h['note']}")
            print(f"  ```c\n  {h['code']}\n  ```")
        print()
    print("> 本工具只给审查点，不给结论；每条需人工确认或写入「未验证清单」。")

    if args.json:
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"机器可读结果：{os.path.relpath(args.json, REPO)}")
    if args.strict and by_pattern.get("free_without_null"):
        print("strict: 存在 free_without_null 命中", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
