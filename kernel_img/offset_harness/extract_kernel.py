#!/usr/bin/env python3
"""从用户放置的 img 提取裸 kernel 到 `local/`（不进 git）。

    python3 extract_kernel.py                        # 扫描 kernel_img/，提取全部
    python3 extract_kernel.py --list                 # 只列出有什么（文件名 → 标签）
    python3 extract_kernel.py --image B2N-416G_boot.img   # 只处理指定的一个（可用文件名/stem/标签/子串）
    python3 extract_kernel.py --pick                 # 有多个镜像时交互式挑一个（TTY）
    python3 extract_kernel.py --img ../x.img --label 4.9/miui   # 单个文件 + 显式标签
    python3 extract_kernel.py --force                # 覆盖已提取的文件

提取结果:
    local/extracted/<label>/Image      裸 arm64 Image
    local/extracted/index.json         标签 → 源 img / 版本 / 哈希 的索引

注意: 原始 img 与提取出的裸 kernel 都不进版本库；`local/` 整体被 .gitignore 忽略。
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import bootimg
import layout

HERE = Path(__file__).resolve().parent


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def label_for(entry, result):
    """目录标签优先；平铺镜像用内嵌内核版本 <major>/<release>。"""
    if entry.label:
        return entry.label
    if result.major and result.release:
        return f"{result.major}/{layout.safe_label(layout.short_release(result.release))}"
    return layout.safe_label(entry.stem)


def write_image(data, label, local_root, force):
    target = layout.extracted_path(label, local_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not force:
        old = sha256_file(target)
        new = hashlib.sha256(data).hexdigest()
        if old == new:
            return target, "already-extracted"
        return target, "exists-different(需 --force 覆盖)"
    target.write_bytes(data)
    return target, "written"


def process(entry, local_root, force):
    if entry.image is None:
        return {"label": entry.label, "status": "SYMBOL-ONLY", "symbols": [str(p) for p in entry.symbols],
                "note": entry.labels_hint}
    result = bootimg.unpack_file(entry.image)
    label = label_for(entry, result)
    record = {
        "label": label,
        "source": layout.display_path(entry.image),
        "source_sha256": result.source_sha256,
        "format": result.format,
        "detail": result.detail,
        "release": result.release,
        "major": result.major,
        "kernel_sha256": result.kernel_sha256,
        "kernel_size": result.size,
        "warnings": result.warnings,
    }
    if result.extracted:
        target, how = write_image(result.data, label, local_root, force)
        record["kernel_path"] = layout.display_path(target)
        record["status"] = how
    else:
        record["kernel_path"] = layout.display_path(entry.image)
        record["status"] = "source-is-raw-image"
    return record


def main():
    ap = argparse.ArgumentParser(description="从 img 提取裸 kernel 到 local/")
    ap.add_argument("--img-root", default=str(layout.DEFAULT_IMG_ROOT))
    ap.add_argument("--local", default=str(layout.DEFAULT_LOCAL_ROOT))
    ap.add_argument("--img", action="append", help="直接指定镜像文件路径（可重复）")
    ap.add_argument("--image", action="append",
                    help="按文件名/stem/标签/子串挑选 kernel_img 下的镜像（可重复）")
    ap.add_argument("--pick", action="store_true", help="有多个镜像时交互式挑选（仅 TTY）")
    ap.add_argument("--label", help="配合 --img 使用：显式标签，如 4.9/miui")
    ap.add_argument("--out", help="提取目录（默认 <local>/extracted）")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的提取文件")
    ap.add_argument("--list", action="store_true", help="只列出，不写入")
    args = ap.parse_args()

    local_root = Path(args.local).resolve()
    if args.out:
        local_root = Path(args.out).resolve().parent
    entries = []
    if args.img:
        for img in args.img:
            p = Path(img).resolve()
            if not p.is_file():
                print(f"error: 不存在 {p}", file=sys.stderr)
                return 2
            entries.append(layout.Entry(label=args.label, stem=p.stem, directory=p.parent, image=p))
    else:
        entries = [e for e in layout.annotate_from_index(layout.scan(args.img_root), local_root)
                   if e.image is not None]
        if args.image:
            entries, problems = layout.resolve(entries, args.image)
            if problems:
                for problem in problems:
                    print(f"error: {problem}", file=sys.stderr)
                print("可用镜像：", file=sys.stderr)
                for entry in layout.annotate_from_index(layout.scan(args.img_root), local_root):
                    if entry.image is not None:
                        print(f"  - {layout.describe(entry)}", file=sys.stderr)
                return 2
        elif args.pick and len(entries) > 1:
            if not sys.stdin.isatty():
                print("error: --pick 需要交互终端；非交互环境下请用 --image <名字> 指定"
                      "（--list 查看候选）", file=sys.stderr)
                return 2
            print("kernel_img/ 下有多个镜像，请选择要提取的一个：")
            picked = layout.pick(entries)
            if picked is None:
                print("未选择；未做任何处理", file=sys.stderr)
                return 2
            entries = [picked]
    if not entries:
        print(f"没有在 {args.img_root} 找到镜像（放一个 *.img 到 kernel_img/<大版本>/<小版本>/ 或 kernel_img/ 下）")
        return 2

    records = []
    for entry in entries:
        if args.list:
            print(layout.describe(entry))
            continue
        try:
            record = process(entry, local_root, args.force)
        except Exception as exc:
            print(f"error: {entry.image}: {exc}", file=sys.stderr)
            return 1
        records.append(record)
        if record.get("kernel_path"):
            print(f"{record['label']:24s} <- {os.path.basename(record['source'])}  "
                  f"[{record['format']}] release={record['release'] or '?'}  {record['status']}")
            for w in record.get("warnings", []):
                print(f"    warn: {w}")

    if args.list:
        return 0

    index_dir = (Path(args.out).resolve() if args.out else local_root / "extracted")
    index_dir.mkdir(parents=True, exist_ok=True)
    index_path = index_dir / "index.json"

    # 合并旧索引：只更新本次处理的标签，保留其它条目（源文件已删除的条目丢弃）
    merged = {}
    if index_path.is_file():
        try:
            for record in json.loads(index_path.read_text(encoding="utf-8")).get("entries", []):
                label = record.get("label")
                source = record.get("source")
                if label and (not source or layout.resolve_path(source).exists()):
                    merged[label] = record
        except Exception:
            merged = {}
    for record in records:
        if record.get("label"):
            merged[record["label"]] = record

    index = {
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "kernel_img/offset_harness/extract_kernel.py",
        "img_root": layout.display_path(args.img_root),
        "entries": sorted(merged.values(), key=lambda r: r.get("label", "")),
    }
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n索引: {layout.display_path(index_path)}（已合并，共 {len(index['entries'])} 条）")
    print("提示: 原始 img 与 local/ 都不进版本库（见 .gitignore）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
