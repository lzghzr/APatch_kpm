#!/usr/bin/env python3
"""VFS 窗口的辅助源码检查（不证明完整读取边界）。

Developer 在 VFS 自检、提交交接前手动调用：
  python3 nomount/tools/check_vfs_windows.py
工具自身的正反夹具：
  python3 nomount/tools/test_vfs_window_scan.py

未接入共享门禁。窗口按本轮批准的文档口径固定为 27/13/47 条；同时检查
VFS 调度实际调用的两个旧识别器，不将包装函数的下标当作调用链的上界。
只比较函数体中直接 src[整数字面量] 的下标；不做控制流、别名、宏展开或
跨函数范围推导。变量下标、指针移动、地址逸出等会明确标为未覆盖。
退出码：0=仅此字面量检查通过；1=越界或源码解析失败；2=存在未覆盖项。
"""

import argparse
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
# 三个目标锚点；前两个包含仍在调用的旧识别器。
WINDOWS = (
    ("super_cache_count", "nm_find_super_cache_vfs", 27),
    ("super_cache_count", "nm_find_super_cache", 27),
    ("set_posix_acl", "nm_find_set_acl_vfs", 13),
    ("set_posix_acl", "nm_find_set_acl", 13),
    ("d_set_d_op", "nm_find_dentry_real", 47),
)
QUOTED = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'')
TOKEN = re.compile(r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[uUlL]*|[0-9]+[uUlL]*|"
                   r"\+\+|--|==|!=|<=|>=|<<=|>>=|[-+*/%&|^]=|[^\s]")
INTEGER = re.compile(r"(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\Z")


def masked(source):
    """屏蔽注释与字符串，保留位置及行号供定位。"""
    return QUOTED.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), source)


def function_body(source, name):
    clean = masked(source)
    # 本轮识别器均返回 int；要求声明前缀，避免将 if(matcher(...)) { 当作定义。
    pattern = r"\bint\s+" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{"
    matches = list(re.finditer(pattern, clean))
    if len(matches) != 1:
        raise ValueError(f"{name}: 预期唯一函数定义，实际 {len(matches)} 个")
    start = matches[0].end()
    depth = 1
    for end in range(start, len(clean)):
        depth += (clean[end] == "{") - (clean[end] == "}")
        if not depth:
            return clean[start:end], source.count("\n", 0, start) + 1
    raise ValueError(f"{name}: 函数体未闭合")


def scan_function(source, name, words, anchor="fixture"):
    body, first_line = function_body(source, name)
    tokens = list(TOKEN.finditer(body))
    literals, uncovered = [], []

    def note(token, reason, expression):
        uncovered.append({"line": first_line + body.count("\n", 0, token.start()),
                          "reason": reason, "expression": expression})

    # 不尝试解释预处理或行拼接，以免将未解析语法报告为通过。
    for special in re.finditer(r"(?m)^\s*#|\\\n", body):
        note(special, "预处理/行拼接未解析", special.group().strip())
    for i, token in enumerate(tokens):
        if token.group() != "src":
            continue
        if i + 1 >= len(tokens) or tokens[i + 1].group() != "[":
            note(token, "指针移动、基址传递或其它指针用法", "src")
            continue
        depth, j = 1, i + 2
        while j < len(tokens) and depth:
            depth += (tokens[j].group() == "[") - (tokens[j].group() == "]")
            j += 1
        if depth:
            raise ValueError(f"{name}: src 下标未闭合")
        expression = body[token.start():tokens[j - 1].end()]
        index = "".join(t.group() for t in tokens[i + 2:j - 1])
        literal = INTEGER.fullmatch(index)
        before = i - 1
        while before >= 0 and tokens[before].group() == "(":
            before -= 1
        if before >= 0 and tokens[before].group() == "&":
            note(token, "子窗口/地址逸出，不追踪辅助函数", expression)
        elif not literal:
            note(token, "变量或非字面下标", expression)
        else:
            value = literal.group(1)
            base = 16 if value.lower().startswith("0x") else (8 if value.startswith("0") else 10)
            try:
                literals.append(int(value, base))
            except ValueError as exc:
                raise ValueError(f"{name}: 无效 C 整数字面量 {value}") from exc
        # 写入与嵌套下标不在只读识别器的受支持语法内；不作通过结论。
        following = tokens[j].group() if j < len(tokens) else ""
        if (following in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "++", "--", "[")
                or (i and tokens[i - 1].group() in ("++", "--"))):
            note(token, "写入或嵌套访问未解析", expression)
    maximum = max(literals, default=None)
    violated = maximum is not None and maximum >= words
    if maximum is None:
        note(re.match(r"", body), "没有可比较的字面下标读取", "")
    status = "FAIL" if violated else ("UNCOVERED" if uncovered else "PASS_LITERAL_ONLY")
    return {"anchor": anchor, "function": name, "window_words": words,
            "max_literal_index": maximum, "literal_within_window": None if maximum is None else not violated,
            "status": status, "uncovered": uncovered}


def scan_source(source):
    results = []
    for anchor, name, words in WINDOWS:
        try:
            results.append(scan_function(source, name, words, anchor))
        except ValueError as exc:
            results.append({"anchor": anchor, "function": name, "window_words": words,
                            "status": "ERROR", "error": str(exc)})
    return results


def exit_code(results):
    if any(row["status"] in ("FAIL", "ERROR") for row in results):
        return 1
    return 2 if any(row["status"] == "UNCOVERED" for row in results) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=ROOT / "nomount/nm_offsets.c")
    parser.add_argument("--json", action="store_true", help="将完整定位结果输出到标准输出")
    args = parser.parse_args()
    try:
        results = scan_source(args.source.read_text())
    except (OSError, UnicodeError) as exc:
        parser.exit(1, f"ERROR: 无法读取源码（{type(exc).__name__}）\n")
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for row in results:
            print(f'[{row["status"]}] {row["anchor"]}: {row["function"]}')
            if "error" in row:
                print("  " + row["error"])
                continue
            maximum, words = row["max_literal_index"], row["window_words"]
            relation = "无字面下标可比较" if maximum is None else f'{maximum} < {words}: {maximum < words}'
            print("  字面下标最大值 / 声明窗口: " + relation)
            if row["uncovered"]:
                print("  该函数存在不可静态判定读取，本检查不覆盖；不判定通过。")
                # 相同表达式只显示首次；JSON 保留全部出现位置。
                examples = {}
                for item in row["uncovered"]:
                    examples.setdefault((item["reason"], item["expression"]), item)
                for item in list(examples.values())[:8]:
                    print(f'  L{item["line"]}: {item["reason"]}: {item["expression"]}')
                if len(examples) > 8:
                    print("  其余定位见 --json。")
        print("辅助检查：不分析执行路径、完整调用链或宏展开；不是完整边界证明。")
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
