#!/usr/bin/env python3
"""re_kernel offset harness.

把用户放在 `kernel_img/` 下的 img 解包成裸 arm64 Image，离线复现
`re_kernel/re_offsets.c` 的 `calculate_offsets()`，输出「版本 × 偏移」矩阵。

目录约定（见 layout.py）:
  kernel_img/<major>/<sub>/boot.img    用户放置的原始 img（不进 git）
  kernel_img/boot_flat.img             平铺镜像：标签按内嵌内核版本自动推导
  local/extracted/<major>/<sub>/Image  提取出的裸 kernel（不进 git）
  local/kernel_offset/<major>/<sub>/trace.log        与 CONFIG_DEBUG logkm 同格式的推导过程
  local/kernel_offset/<major>/<sub>/struct_offset.c  该内核的 C 初始化器（re_vmlinux.c 格式）
  local/kernel_offset/<major>/<sub>/<anchor>.asm     锚函数反汇编（capstone）
  local/kernel_offset/report.md                      状态表 + ver4/5/6 判定 + 偏移矩阵
  local/kernel_offset/offsets.json                   机器可读结果

用法:
  python3 extract_kernel.py                      # 先提取裸 kernel 到 local/
  python3 run.py                                 # 全量分析
  python3 run.py --image B2N-416G_boot.img       # 只处理指定镜像（文件名/stem/标签/子串）
  python3 run.py --image 4.14                    # 也认上次提取出的标签别名（4.14/4.14.356-Liberty）
  python3 run.py --pick                          # 有多个镜像时交互式挑一个（TTY）
  python3 run.py --list                          # 只列出有什么，不分析
  python3 run.py --kernel 4.9/miui --kernel 4.4  # 按标签精确挑选（等价写法）
  python3 run.py --trace-insn                    # 每条指令的 trace（巨大，排错用）
  python3 run.py --out /tmp/offset               # 输出改到别处（默认 local/kernel_offset，属用户数据不入库）

本 harness 与设备上的 C 代码同源：结论只算 Developer 自检，不是独立审计。
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import bootimg
import layout
from kernel_image import KernelImage
from kallsyms import Kallsyms
from offsets_calc import ANCHORS, FIELDS, CalcError, OffsetCalculator

HERE = Path(__file__).resolve().parent

SYMBOL_EXTS = {".i64", ".kallsyms", ".txt", ".md", ".json", ".log"}

# reference values quoted in re_offsets.c CONFIG_DEBUG comments (from manual RE
# on one specific kernel) — a cross-check column, not a universal expectation
REFERENCE = {
    "binder_transaction_from": 0x20,
    "binder_transaction_to_proc": 0x30,
    "binder_transaction_buffer": 0x50,
    "binder_transaction_code": 0x58,
    "binder_transaction_flags": 0x5C,
    "binder_node_lock": 0x4,
    "binder_node_ptr": 0x58,
    "binder_node_cookie": 0x60,
    "binder_node_has_async_transaction": 0x6B,
    "binder_node_async_todo": 0x70,
    "binder_proc_outstanding_txns": 0x6C,
    "binder_proc_is_frozen": 0x71,
    "task_struct_jobctl": 0x580,
    "binder_proc_context": 0x240,
    "binder_proc_inner_lock": 0x248,
    "binder_proc_outer_lock": 0x24C,
    "binder_proc_alloc": 0x1A8,
    "binder_alloc_pid": 0x84,
    "binder_alloc_buffer_size": 0x78,
    "binder_alloc_free_async_space": 0x68,
    "binder_alloc_buffer": 0x40,
    "task_struct_pid": 0x5D8,
    "task_struct_tgid": 0x5DC,
    "task_struct_group_leader": 0x618,
    "binder_stats_deleted_transaction": 0xCC,
    "sk_buff_len": 0x70,
    "sk_buff_network_header": 0xB4,
    "sk_buff_tail": 0xC8,
    "sk_buff_head": 0xD0,
    "sk_buff_data": 0xD8,
}

SANITY_RANGE = {
    "task_struct_pid": (0x100, 0x1000),
    "task_struct_tgid": (0x100, 0x1000),
    "task_struct_group_leader": (0x100, 0x1100),
    "task_struct_jobctl": (0x300, 0x800),
    "sk_buff_len": (0x10, 0x200),
    "sk_buff_transport_header": (0x10, 0x200),
    "sk_buff_network_header": (0x10, 0x200),
    "sk_buff_tail": (0x10, 0x200),
    "sk_buff_head": (0x10, 0x200),
    "sk_buff_data": (0x10, 0x200),
    "binder_transaction_from": (0x08, 0x100),
    "binder_transaction_to_proc": (0x08, 0x100),
    "binder_transaction_buffer": (0x08, 0x100),
    "binder_transaction_code": (0x08, 0x100),
    "binder_transaction_flags": (0x08, 0x100),
    "binder_node_lock": (0x01, 0x100),
    "binder_node_ptr": (0x01, 0x100),
    "binder_node_cookie": (0x01, 0x100),
    "binder_node_has_async_transaction": (0x01, 0x100),
    "binder_node_async_todo": (0x01, 0x100),
    "binder_proc_alloc": (0x08, 0x400),
    "binder_proc_context": (0x100, 0x400),
    "binder_proc_inner_lock": (0x100, 0x400),
    "binder_proc_is_frozen": (0x08, 0x400),
    "binder_proc_outer_lock": (0x100, 0x400),
    "binder_proc_outstanding_txns": (0x08, 0x400),
    "binder_alloc_pid": (0x10, 0x100),
    "binder_alloc_buffer": (0x10, 0x100),
    "binder_alloc_free_async_space": (0x10, 0x100),
    "binder_alloc_buffer_size": (0x10, 0x100),
    "binder_stats_deleted_transaction": (0xC0, 0xE0),
}


def discover(img_root):
    """扫描 img 目录；返回 [(label|None, entry)]（排序后）。"""
    return layout.scan(img_root)


def symbol_candidates(entry):
    """同一目录里用户提供的符号表，按优先级排列（带真实地址的优先）。"""
    cands = []
    for p in entry.symbols:
        cands.append(p)
    return cands


def extract_kernel(entry, result, local_root):
    """需要时把裸 kernel 落到 local/extracted/<label>/Image；返回 (路径, 说明)。"""
    if not result.extracted:
        return entry.image, "源文件本身就是裸 Image，不写 local/"
    target = layout.extracted_path(entry.label, local_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        old = hashlib.sha256(target.read_bytes()).hexdigest()
        if old == result.kernel_sha256:
            return target, "已存在同哈希提取结果，复用"
    target.write_bytes(result.data)
    return target, f"写入 {target}"


def capstone_available():
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


def dump_asm(image, ks, label, out_dir):
    try:
        import capstone
    except ImportError:
        return False
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    text_base = ks.lookup("_text") or 0
    out_dir.mkdir(parents=True, exist_ok=True)
    for fn in ANCHORS:
        addr = ks.lookup(fn)
        if addr is None:
            continue
        off = addr - text_base
        if off < 0 or off >= image.size:
            continue
        data = image.read(off, 0x400)
        lines = [f"; {fn}  file_off=0x{off:x}  (kallsyms addr 0x{addr:x}, _text-relative)"]
        count = 0
        for insn in md.disasm(data, addr):
            lines.append(f"  {addr + count * 4:08x}:  {insn.bytes.hex():<8}  {insn.mnemonic}\t{insn.op_str}")
            count += 1
            if insn.mnemonic == "ret" or count >= 0x400:
                break
        (out_dir / f"{fn}.asm").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def emit_c(so, path):
    lines = ["struct struct_offset struct_offset = {"]
    for f in FIELDS:
        v = so[f]
        lines.append(f"    .{f} = {'-' if v < 0 else ''}0x{abs(v):x},")
    lines.append("};")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def select_symbols(label, image, cands, out_dir):
    """Pick a usable symbol table: real-address dumps first, then embedded
    extraction from the Image (address-stripped /proc/kallsyms dumps are only
    good as a name cross-check)."""
    import kallsyms_extract
    from kallsyms_extract import ExtractedKallsyms

    notes = []
    names_only = None
    for path in cands:
        ks = Kallsyms.parse(path)
        if not ks.order:
            continue
        nonzero = sum(1 for a, _t, _n in ks.order if a != 0)
        if nonzero >= len(ks.order) * 0.9:
            return ks, path.name, notes
        notes.append(f"{path.name}: only {nonzero}/{len(ks.order)} symbols carry "
                     "addresses (address-stripped dump); kept as name cross-check")
        if names_only is None:
            names_only = [n for _a, _t, n in ks.order]

    syms, mode = kallsyms_extract.extract(image.data)
    if syms is None:
        # 用户提供的内核可能根本不含 kallsyms（CONFIG_KALLSYMS=n / 表被裁掉），这是正常情况：
        # 该内核不参与偏移推导（SKIP），不算失败，也不算产品缺陷。
        return None, "no-kallsyms", notes + [f"本 harness 的提取方法在该镜像上失败（{mode}）；"
                                            "**未定性内核是否含 kallsyms**（定性需独立提取，见 AUD-018）"]
    ks = ExtractedKallsyms(syms)
    if names_only is not None:
        have = set(n for _a, _t, n in ks.order)
        hit = sum(1 for n in names_only if n in have)
        pct = 100 * hit // max(1, len(names_only))
        notes.append(f"name cross-check with address-stripped dump: "
                     f"{hit}/{len(names_only)} ({pct}%) match")
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = out_dir / "kallsyms_extracted.txt"
    with open(cache, "w", encoding="utf-8") as f:
        for a, t, n in ks.order:
            f.write(f"{a:08x} {t} {n}\n")
    return ks, f"extracted from image ({mode}) -> {cache.name}", notes


def analyze(label, image_path, source, ks, image):
    result = {"label": label, "image": layout.display_path(image_path) if image_path else "",
              "symbols": source}
    result["image_size"] = image.size
    result["num_symbols"] = len(ks.order)

    text_base = ks.lookup("_text")
    end = ks.lookup("_end")
    result["_text"] = text_base
    result["_end"] = end
    notes = []
    trace = []
    calc = None
    if text_base is None:
        result["status"] = "FAIL"
        result["error"] = "no _text symbol in kallsyms dump"
        return result, notes, trace, ks, image
    if end is not None and end - text_base > image.size:
        notes.append(f"WARNING _end-_text=0x{end - text_base:x} > image size 0x{image.size:x}: "
                     "kallsyms dump may not match this image")
    missing = [a for a in ANCHORS if ks.lookup(a) is None]
    if missing:
        notes.append(f"missing symbols: {', '.join(missing)}")

    calc = OffsetCalculator(image, ks, trace_insn=False)
    try:
        so = calc.run()
        result["status"] = "PASS"
        result["offsets"] = so
        result["ver"] = {"buffer_release_ver6": calc.ver6,
                         "buffer_release_ver5": calc.ver5,
                         "buffer_release_ver4": calc.ver4}
        result["func_addr"] = calc.func_addr
        result["fallbacks"] = calc.fallbacks
        for f in FIELDS:
            if f not in SANITY_RANGE:
                continue
            lo, hi = SANITY_RANGE[f]
            v = so[f]
            if not (lo <= v <= hi):
                notes.append(f"WARNING {f}=0x{v & 0xFFFFFFFFFFFFFFFF:x} outside plausible "
                             f"[0x{lo:x}, 0x{hi:x}]")
    except CalcError as e:
        result["status"] = "FAIL"
        result["error"] = f"rc={e.code}: {e.msg}"
        result["offsets"] = calc.struct_offset
        result["ver"] = {"buffer_release_ver6": calc.ver6,
                         "buffer_release_ver5": calc.ver5,
                         "buffer_release_ver4": calc.ver4}
        result["func_addr"] = calc.func_addr
        result["fallbacks"] = calc.fallbacks

    trace = list(calc.trace)
    return result, notes, trace, ks, image


def main():
    ap = argparse.ArgumentParser(description="re_kernel offline offset harness")
    ap.add_argument("--img-root", "--corpus", dest="img_root", default=str(layout.DEFAULT_IMG_ROOT),
                    help="用户放置 img 的目录（默认 kernel_img/）")
    ap.add_argument("--out", default=str(layout.DEFAULT_OUT_ROOT),
                    help="分析输出目录（默认 local/kernel_offset；名字只是建议，输出属用户数据不进版本库）")
    ap.add_argument("--local", default=str(layout.DEFAULT_LOCAL_ROOT),
                    help="本地文件目录：提取出的裸 kernel 放这里（默认仓库根 local/）")
    ap.add_argument("--kernel", action="append", help="只跑指定标签（如 4.9/miui、4.4）")
    ap.add_argument("--image", action="append",
                    help="按文件名/stem/标签/子串挑选镜像（如 B2N-416G_boot.img、4.14）")
    ap.add_argument("--pick", action="store_true", help="有多个镜像时交互式挑选（仅 TTY）")
    ap.add_argument("--list", action="store_true", help="列出 kernel_img/ 下的条目后退出")
    ap.add_argument("--trace-insn", action="store_true", help="逐指令 trace（巨大，排错用）")
    ap.add_argument("--no-asm", action="store_true")
    args = ap.parse_args()

    img_root = Path(args.img_root)
    out_root = Path(args.out)
    local_root = Path(args.local)
    out_root.mkdir(parents=True, exist_ok=True)

    try:
        entries = discover(img_root)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not entries:
        print(f"没有在 {img_root} 发现镜像或符号表。")
        print("放一个 img 到 kernel_img/<大版本>/<小版本>/ 或 kernel_img/ 下（见 kernel_img/README.md）")
        return 2
    entries = layout.annotate_from_index(entries, local_root)

    if args.list:
        for entry in entries:
            print(layout.describe(entry))
        return 0

    selectors = (args.kernel or []) + (args.image or [])
    if selectors:
        entries, problems = layout.resolve(entries, selectors)
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            print("kernel_img/ 下可用条目：", file=sys.stderr)
            for entry in layout.annotate_from_index(discover(img_root), local_root):
                print(f"  - {layout.describe(entry)}", file=sys.stderr)
            return 2
    elif args.pick:
        candidates = [e for e in entries if e.image is not None]
        if len(candidates) > 1:
            if not sys.stdin.isatty():
                print("error: --pick 需要交互终端；非交互环境下请用 --image <名字> 指定"
                      "（--list 查看候选）", file=sys.stderr)
                return 2
            print("kernel_img/ 下有多个镜像，请选择要处理的一个：")
            picked = layout.pick(candidates)
            if picked is None:
                print("未选择；未做任何分析", file=sys.stderr)
                return 2
            entries = [e for e in entries if e.image is None and False] + [picked]

    have_capstone = capstone_available()
    if not have_capstone:
        print("capstone not installed -> .asm dumps skipped (pip install capstone)")

    results = []
    for entry in entries:
        if entry.image is None:
            print(f"== {entry.label} ==")
            print("   SKIP: 只有符号表，没有镜像（用于跨版本符号核对，不推导偏移）")
            results.append({"label": entry.label, "status": "SKIP",
                            "error": "symbols-only entry, no kernel image",
                            "symbols_files": [layout.display_path(p) for p in entry.symbols]})
            continue

        print(f"== {entry.stem} ==")
        try:
            unpacked = bootimg.unpack_file(entry.image)
        except Exception as exc:
            print(f"   FAIL — 解包失败: {exc}")
            results.append({"label": entry.label or entry.stem, "status": "FAIL",
                            "error": f"unpack failed: {exc}",
                            "image": layout.display_path(entry.image)})
            continue

        label = entry.label
        if label is None:
            if unpacked.major and unpacked.release:
                label = f"{unpacked.major}/{layout.safe_label(layout.short_release(unpacked.release))}"
            else:
                label = layout.safe_label(entry.stem)
        entry.label = label
        print(f"   label={label}  [{unpacked.format}] release={unpacked.release or '?'}")
        for w in unpacked.warnings:
            print(f"   warn: {w}")
        kernel_path, how = extract_kernel(entry, unpacked, local_root)
        print(f"   kernel: {layout.display_path(kernel_path)}  ({how})")

        image = KernelImage.load(kernel_path)
        image.data = unpacked.data          # 与解包结果严格一致（含 --no-extract 语义）
        kd = out_root / label
        cands = symbol_candidates(entry)
        ks, source, notes = select_symbols(label, image, cands, kd)
        if ks is None:
            skip = source == "no-kallsyms"
            status = "SKIP" if skip else "FAIL"
            reason = ("本 harness 的提取方法在该镜像上失败（未定性内核是否含 kallsyms）；"
                      "该内核不参与偏移推导" if skip
                      else f"embedded kallsyms extraction failed: {source}")
            print(f"   {status} — {reason}")
            for n in notes:
                print(f"   {n}")
            results.append({"label": label, "status": status, "error": reason,
                            "image": layout.display_path(entry.image),
                            "kernel": layout.display_path(kernel_path),
                            "kernel_sha256": unpacked.kernel_sha256,
                            "source_image": layout.display_path(entry.image),
                            "release": unpacked.release, "major": unpacked.major})
            continue

        r, notes2, trace, _ks, _image = analyze(label, entry.image, source, ks, image)
        r["symbols"] = source
        r["kernel"] = layout.display_path(kernel_path)
        r["kernel_sha256"] = unpacked.kernel_sha256
        r["source_image"] = layout.display_path(entry.image)
        r["source_sha256"] = unpacked.source_sha256
        r["source_format"] = unpacked.format
        r["release"] = unpacked.release
        r["major"] = unpacked.major
        results.append(r)
        print(f"   {r['status']}" + (f" — {r['error']}" if r.get("error") else ""))
        for n in notes + notes2:
            print(f"   {n}")
        if r["status"] == "PASS":
            print(f"   symbols={r['num_symbols']} image=0x{r['image_size']:x} "
                  f"fallbacks={r['fallbacks'] or 'none'}")

        kd.mkdir(parents=True, exist_ok=True)
        (kd / "trace.log").write_text("\n".join(trace) + "\n", encoding="utf-8")
        if "offsets" in r:
            emit_c(r["offsets"], kd / "struct_offset.c")
        if not args.no_asm and have_capstone:
            dump_asm(image, ks, label, kd)

    # ---- report ------------------------------------------------------------
    passed = [r for r in results if r["status"] == "PASS"]
    failed = [r for r in results if r["status"] == "FAIL"]
    skipped = [r for r in results if r["status"] == "SKIP"]

    md = ["# re_kernel offset harness report", ""]
    md.append(f"img 目录: `{layout.display_path(img_root)}` — {len(passed)} pass / "
              f"{len(failed)} fail / {len(skipped)} skipped")
    md.append("")
    md.append("标签规则：`<major>/<sub>`；目录里的镜像用目录名作 sub，平铺镜像用内嵌内核版本。")
    md.append("")
    md.append("状态含义（harness 报告口径，与覆盖矩阵的取值集不同）：`PASS` 推导通过；"
              "`SKIP` **本 harness 取不到符号表**（镜像提取失败，或只有符号表没有镜像）——"
              "**未覆盖，不等于内核不含 kallsyms**；`FAIL` 有符号表但解包/推导出错。SKIP 不算失败。")
    md.append("")
    md.append("| 标签 | 状态 | release | 源镜像 | kernel sha256 | 说明 |")
    md.append("|---|---|---|---|---|---|")
    for r in results:
        note = r.get("error", "")
        if r["status"] == "PASS":
            fb = r.get("fallbacks") or []
            note = "fallback: " + ", ".join(fb) if fb else ""
        sha = (r.get("kernel_sha256") or "")[:12]
        src = Path(r["source_image"]).name if r.get("source_image") else ""
        md.append(f"| {r['label']} | {r['status']} | {r.get('release', '')} | {src} | "
                  f"`{sha}` | {note} |")
    md.append("")

    md.append("## 版本判定标志 (binder_transaction_buffer_release)")
    md.append("")
    md.append("ver4/ver5/ver6 决定运行时调用哪个参数个数的变体 (IZERO=已判定)")
    md.append("")
    md.append("| 标签 | ver6 | ver5 | ver4 |")
    md.append("|---|---|---|---|")
    for r in results:
        if "ver" not in r:
            continue
        ver = r["ver"]
        def fmt(v):
            return "✓" if v == (1 << 0x10) else ("UZERO" if v == (1 << 0x20) else hex(v))
        md.append(f"| {r['label']} | {fmt(ver['buffer_release_ver6'])} | "
                  f"{fmt(ver['buffer_release_ver5'])} | {fmt(ver['buffer_release_ver4'])} |")
    md.append("")

    md.append("## 偏移矩阵")
    md.append("")
    md.append("列为各内核推导值 (十六进制)；「参考」列为 re_offsets.c 注释中的参考内核值，"
              "仅用于对照，不同内核本就允许不同。")
    md.append("")
    cols = [r["label"] for r in results if "offsets" in r]
    md.append("| 偏移 | 参考 | " + " | ".join(cols) + " |")
    md.append("|---|---|" + "---|" * len(cols))
    for f in FIELDS:
        row = [f"0x{REFERENCE[f]:x}" if f in REFERENCE else ""]
        vals = []
        for r in results:
            if "offsets" not in r:
                continue
            v = r["offsets"][f]
            vals.append(f"0x{v & 0xFFFFFFFFFFFF:x}" if v > 0 else "**0**")
        md.append(f"| {f} | {row[0]} | " + " | ".join(vals) + " |")
    md.append("")

    md.append("## 锚函数解析地址 (_text 相对)")
    md.append("")
    cols = [r["label"] for r in results if "func_addr" in r]
    if cols:
        md.append("| anchor | " + " | ".join(cols) + " |")
        md.append("|---|" + "---|" * len(cols))
        for a in ANCHORS:
            row = []
            for r in results:
                if "func_addr" not in r:
                    continue
                v = r["func_addr"].get(a)
                row.append(f"0x{v:x}" if v is not None else "—")
            md.append(f"| {a} | " + " | ".join(row) + " |")
        md.append("")

    (out_root / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out_root / "offsets.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8")

    print(f"\nreport: {out_root / 'report.md'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
