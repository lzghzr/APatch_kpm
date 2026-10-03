#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""独立 kallsyms 提取：自解析裸 arm64 Image 的 kallsyms 表，判定「内核是否含 kallsyms」。

独立性声明（AUD-018 / O2）:
  * 不调用 `kernel_img/offset_harness`（任何脚本、任何输出），不导入 `tools/*`，不用第三方 ELF 库；
  * 只读裸 Image 的原始字节，用自己的签名扫描与解码实现；
  * 与实现方仅共享「同一份镜像文件」——镜像是审计对象，不是结论来源。

为什么要它：`coverage.md` 曾把 4.14 写成「镜像不含 kallsyms」，而支撑它的只有 Developer harness 的
提取失败。**工具失败 ≠ 内核没有该结构**。本工具用与 harness 无关的方法判定镜像里到底有没有自洽的 kallsyms 表。

判据链（四段互相独立，全部通过才算「含 kallsyms」）:
  1. `kallsyms_token_index`：256 个 u16、首元素 0、严格递增；由它反推 `kallsyms_token_table`
     起点，逐串校验长度/可打印/累计偏移。真实表与 index 之间可能有对齐零填充（4.4 实测 22 字节），
     故不要求紧邻；并排除「连续 NUL 退化」误报（≥128 个非空 token）。
  2. `kallsyms_markers`：token 表之前的非递减数组（u64 或 u32，允许对齐填充），首元素 0。
     markers[k] 是「第 k*256 个符号在 names 区内的字节偏移」——这是第 4 步的硬约束。
  3. `kallsyms_names` 起点：用「前 256 个符号恰好占 markers[1] 字节」定位，再要求
     **全部 markers 逐项等于解码出的块边界**（这是强判据，不靠"字符串可打印"）。
  4. 符号数与形状：非空名计数（空名即 names 区结束/填充），首个字符必须是 kallsyms 类型字符
     （nm 风格 t/T/d/D/b/B/r/R/a/A/w/W/v/V/n/N/u/U），其余字符 ∈ [A-Za-z0-9_.$]；
     形状合法率 < 99% 即判失败。附近若存在 `num_syms` 字段则一并报出（用于交叉核对，不作必需条件）。

用法:
  python3 Auditor/tools/kallsyms_extract.py --image local/extracted/4.14/4.14.356-Liberty/Image
  python3 Auditor/tools/kallsyms_extract.py --scan-local --json local/kallsyms_audit/result.json
"""

import argparse
import glob
import hashlib
import json
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKENS = 256
MAX_TOKEN_BYTES = 8192
MAX_NAME_LEN = 512
MIN_SYMBOLS = 5000
MAX_SYMBOLS = 2_000_000
MAX_PAD = 256                     # 表之间的对齐填充上限
TYPE_CHARS = set("tTdDbBrRaAwWvVnNuU")
BODY_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$")


def is_printable(blob, start, end):
    return all(0x20 <= b <= 0x7E for b in blob[start:end])


# ---------------------------------------------------------------- 1. token 表
def read_tokens(blob, tt, vals, ti_expected):
    tokens, pos = [], tt
    for j in range(TOKENS):
        want = vals[j + 1] - vals[j] - 1 if j < TOKENS - 1 else None
        end = blob.find(b"\x00", pos)
        if end < 0:
            return None, False
        length = end - pos
        if length > 255 or (want is not None and length != want):
            return None, False
        if length and not is_printable(blob, pos, end):
            return None, False
        tokens.append(blob[pos:end])
        pos = end + 1
    gap = ti_expected - pos
    if not 0 <= gap <= 64 or any(blob[pos:ti_expected]):
        return None, False
    if vals[TOKENS - 1] != sum(len(t) + 1 for t in tokens[:TOKENS - 1]):
        return None, False
    if sum(1 for t in tokens if t) < 128 or sum(len(t) for t in tokens) < 128:
        return None, False
    return tokens, True


def find_token_table(blob):
    start = 0
    while True:
        i = blob.find(b"\x00\x00", start)
        if i < 0:
            return None, None, None
        start = i + 1
        if i + 512 > len(blob):
            return None, None, None
        v1 = struct.unpack_from("<H", blob, i + 2)[0]
        if not 1 <= v1 <= 256:
            continue
        vals = struct.unpack_from("<256H", blob, i)
        if vals[0] != 0 or any(vals[k] >= vals[k + 1] for k in range(TOKENS - 1)):
            continue
        for total in range(vals[255] + 1, vals[255] + 257 + 64):
            tt = i - total
            if tt < 0:
                break
            tokens, ok = read_tokens(blob, tt, vals, i)
            if ok:
                return tt, i, tokens
    return None, None, None


# ---------------------------------------------------------------- 2. markers
def find_markers(blob, tt):
    """返回 (start, width, values)；markers 结束于 token 表前的填充之前。"""
    best = None
    for pad in range(0, MAX_PAD + 1, 4):
        end = tt - pad
        if end <= 0 or any(blob[end:tt]):
            continue
        for width, fmt in ((8, "<Q"), (4, "<I")):
            vals, pos = [], end - width
            while pos >= 0 and len(vals) < (1 << 20):
                (v,) = struct.unpack_from(fmt, blob, pos)
                if vals and v > vals[-1]:
                    break
                vals.append(v)
                pos -= width
            if len(vals) >= 8 and vals[-1] == 0 and vals[0] > 1000:
                vals.reverse()
                # 反向收集会把 markers 之前的对齐零也读成元素：只保留一个前导 0
                while len(vals) > 1 and vals[0] == 0 and vals[1] == 0:
                    vals.pop(0)
                # markers[k] 是第 k*256 个符号的偏移：首元素 0，其后必须**严格**递增
                # （非严格递增会让"多一个前导 0"的错误起点也通过，实测 4.4 踩到过）
                if all(vals[k] < vals[k + 1] for k in range(len(vals) - 1)):
                    cand = (pos + width, width, vals)
                    if best is None or len(vals) > len(best[2]):
                        best = cand
    return best if best else (None, 0, None)


# ------------------------------------------------------- 3/4. names 与符号数
def entry_len(blob, pos, big):
    ln = blob[pos]
    pos += 1
    if big and (ln & 0x80):
        ln = (ln & 0x7F) | (blob[pos] << 7)
        pos += 1
    return ln, pos


def decode_one(blob, pos, tokens, big):
    """返回 (name, next_pos) 或 (None, pos)。空名（len=0）返回 ("", next_pos)。"""
    ln, pos = entry_len(blob, pos, big)
    if ln == 0:
        return "", pos
    if ln > MAX_NAME_LEN or pos + ln > len(blob):
        return None, pos
    out = bytearray()
    for k in range(ln):
        out += tokens[blob[pos + k]]
    pos += ln
    if not out or not all(0x20 <= b <= 0x7E for b in out):
        return None, pos
    return out.decode("ascii"), pos


def shape_ok(name):
    return bool(name) and name[0] in TYPE_CHARS and all(c in BODY_CHARS for c in name[1:])


def consume(blob, start, count, big):
    pos = start
    for _ in range(count):
        ln, pos = entry_len(blob, pos, big)
        pos += ln
    return pos - start


def verify_names(blob, start, markers_vals, tokens, big):
    """全量解码并逐项核对 markers；返回 (count, names, ok, reason)。"""
    blocks = len(markers_vals)
    names, boundaries, pos = [], [], start
    while True:
        if len(names) % 256 == 0 and len(names) // 256 < blocks:
            boundaries.append(pos - start)
        name, nxt = decode_one(blob, pos, tokens, big)
        if name is None:
            return 0, None, False, f"第 {len(names)} 个符号解码失败"
        if name == "":
            break
        names.append(name)
        pos = nxt
        if len(names) > MAX_SYMBOLS:
            return 0, None, False, "符号数超出上限"
    if not names:
        return 0, None, False, "names 区为空"
    got = list(boundaries)
    if got != list(markers_vals[:len(got)]) or len(got) != blocks:
        return 0, None, False, f"块边界与 markers 不吻合（解出 {len(got)} 块，markers {blocks} 块）"
    ratio = sum(1 for n in names if shape_ok(n)) / len(names)
    if ratio < 0.99:
        return 0, None, False, f"符号名形状合法率仅 {ratio:.1%}"
    return len(names), names, True, None


def find_names(blob, markers_start, markers_vals, tokens):
    blocks = len(markers_vals)
    need = markers_vals[1] if blocks > 1 else None
    lo = max(0, markers_start - (markers_vals[-1] * 2 + (1 << 16)))
    # 先按 4 字节对齐扫（快）；再用 1 字节兜底，但把窗口收窄，避免退化成本
    for step, low, limit in ((4, lo, 24), (1, max(lo, markers_start - (1 << 20)), 4)):
        base = low + ((step - low % step) % step)      # 保证起点与 step 对齐
        cands = []
        for start in range(base, markers_start, step):
            name, _ = decode_one(blob, start, tokens, False)   # 廉价预筛
            if not shape_ok(name or ""):
                continue
            if blocks > 1 and consume(blob, start, 256, False) != need:
                continue
            cands.append(start)
            if len(cands) >= limit:
                break
        for start in cands:
            for big in (False, True):
                count, names, ok, reason = verify_names(blob, start, markers_vals, tokens, big)
                if ok:
                    return start, count, names, ("big" if big else "plain"), None
        if cands:
            return None, 0, None, None, f"{len(cands)} 个候选起点均未通过 markers 逐项核对"
    return None, 0, None, None, "未找到满足 markers[1] 约束的 names 起点"


def find_num_syms(blob, names_off, count):
    """查附近的 num_syms 字段（u32/u64），仅用于交叉核对。"""
    lo = max(0, names_off - 4096)
    for p in range(names_off, lo, -1):
        for width, fmt in ((4, "<I"), (8, "<Q")):
            if p - width < 0:
                continue
            (v,) = struct.unpack_from(fmt, blob, p - width)
            if v == count:
                return p - width, width
    return None, 0


# ---------------------------------------------------------------- 审计入口
def audit_image(path):
    blob = open(path, "rb").read()
    facts = {
        "image": os.path.relpath(path, REPO),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "arm64_magic_at_0x38": blob[0x38:0x3C] == b"ARM\x64",
    }
    tt, ti, tokens = find_token_table(blob)
    if tt is None:
        facts.update({"has_kallsyms": False, "symbols": 0, "mode": None,
                      "reason": "未找到自洽的 kallsyms_token_table + token_index 签名"})
        return facts
    facts["token_table_off"] = tt
    facts["token_index_off"] = ti
    markers_start, width, markers_vals = find_markers(blob, tt)
    if markers_start is None:
        facts.update({"has_kallsyms": True, "symbols": 0, "mode": "token 表自洽，markers 未定位",
                      "reason": "未定位 kallsyms_markers（token 表前无自洽的非递减数组）"})
        return facts
    facts["markers_off"] = markers_start
    facts["markers_width"] = width
    facts["marker_blocks"] = len(markers_vals)
    names_off, count, names, mode, reason = find_names(blob, markers_start, markers_vals, tokens)
    if names_off is None:
        facts.update({"has_kallsyms": True, "symbols": 0, "mode": "token 表 + markers 自洽，names 未解码",
                      "reason": reason})
        return facts
    num_off, num_width = find_num_syms(blob, names_off, count)
    sample = names[:3] + names[-1:]
    facts.update({
        "has_kallsyms": True, "symbols": count, "names_off": names_off,
        "mode": f"token 压缩/{mode}/markers 逐项吻合",
        "num_syms_field": ({"off": num_off, "width": num_width} if num_off else None),
        "sample_names": sample,
        "reason": None,
    })
    return facts


def main():
    ap = argparse.ArgumentParser(description="独立 kallsyms 提取（AUD-018 / O2）")
    ap.add_argument("--image")
    ap.add_argument("--scan-local", action="store_true", help="扫 local/extracted/**/Image")
    ap.add_argument("--json")
    args = ap.parse_args()

    images = []
    if args.image:
        images.append(args.image)
    if args.scan_local:
        images += sorted(glob.glob(os.path.join(REPO, "local", "extracted", "**", "Image"),
                                   recursive=True))
    if not images:
        print("error: 用 --image <裸 Image> 或 --scan-local", file=sys.stderr)
        return 2

    results = [audit_image(p) for p in images]
    print("# 独立 kallsyms 提取（Auditor 自有实现，不调用 harness）")
    print()
    print("| 镜像 | 大小 | 含 kallsyms | 符号数 | 提取模式 | token 表 | num_syms 字段 | 失败原因 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for f in results:
        ns = f.get("num_syms_field")
        print(f"| `{f['image']}` | {f['size']} | {'是' if f['has_kallsyms'] else '否'} | "
              f"{f['symbols'] or '—'} | {f['mode'] or '—'} | "
              f"{('0x%x' % f['token_table_off']) if f.get('token_table_off') else '—'} | "
              f"{('0x%x/u%d' % (ns['off'], ns['width'])) if ns else '—'} | "
              f"{f['reason'] or '—'} |")
    print()
    for f in results:
        if f.get("sample_names"):
            print(f"- `{f['image']}` 抽样符号：{', '.join(f['sample_names'])}")
    if args.json:
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"tool": "Auditor/tools/kallsyms_extract.py", "results": results},
                      fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"\n机器可读结果：{os.path.relpath(args.json, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())