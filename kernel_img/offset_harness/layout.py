#!/usr/bin/env python3
"""输入发现与标签推导（`extract_kernel.py` 与 `run.py` 共用）。

`kernel_img/` 是**用户数据**：结构不强制，下面的布局只是建议，任意层数/任意目录名都能工作；
`local/` 里的目录名同样只是建议（用 `--local` / `--out` 可改）。

建议布局
--------
```text
kernel_img/                    用户放置原始 img / 符号表（不进 git）
  4.9/                         ← 大版本（内核 major.minor）
    default/boot.img           ← 子版本（机型 / 完整版本号 / 变体名）
    miui/{boot.img,kallsyms.txt}
  boot_flat.img               ← 平铺文件：标签自动取内嵌内核版本 <major>/<release>
local/                         运行产生的本地文件（不进 git）
  extracted/<major>/<sub>/Image
  extracted/index.json
local/kernel_offset/           分析输出（不进 git；与提取产物一起放在 local/）
  <major>/<sub>/{trace.log,struct_offset.c,*.asm}
  report.md  offsets.json
```

标签推导（label）:
  * 目录里的镜像 → 标签 = 相对 `kernel_img/` 的目录路径（`4.9/miui`、`5.15`、`my_device/2024-05`）；
  * 同一目录多个镜像 → 标签再加上文件名（`4.9/miui/boot2`）；
  * 平铺在 `kernel_img/` 下的镜像 → 解包后取内核版本，标签 = `<major>/<release>`；
    取不到版本时退回文件名 `<stem>`。
"""

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_IMG_ROOT = HERE.parent              # kernel_img/
DEFAULT_LOCAL_ROOT = HERE.parent.parent / "local"
DEFAULT_OUT_ROOT = DEFAULT_LOCAL_ROOT / "kernel_offset"   # 输出也算用户数据；名字只是建议，--out 可改

IMAGE_SUFFIXES = {".img", ".image", ".bin", ".kernel"}
IMAGE_NAMES = {"image", "kernel", "vmlinux", "image.gz", "image.lz4", "image.xz"}
SYMBOL_SUFFIXES = {".kallsyms"}
SYMBOL_NAME_RE = re.compile(r"^(kallsyms_.*|.*_kallsyms)\.txt$", re.I)
SKIP_DIRS = {"offset_harness", "out", "__pycache__", ".git"}


@dataclass
class Entry:
    label: str | None          # 目录给出的标签；None 表示需要按内核版本自动推导
    stem: str                  # 镜像文件名（去扩展名），自动标签的兜底
    directory: Path            # 所在目录
    image: Path | None = None  # 原始 img / 裸 Image
    symbols: list = field(default_factory=list)   # 用户提供的符号表
    labels_hint: str = ""      # 说明文字，进报告
    aliases: set = field(default_factory=set)     # 来自 local/extracted/index.json 的别名（如 4.14/4.14.356-Liberty）

    @property
    def is_flat(self):
        return self.label is None


def _is_image(p: Path):
    return p.suffix.lower() in IMAGE_SUFFIXES or p.name.lower() in IMAGE_NAMES


def _is_symbol(p: Path):
    return p.suffix.lower() in SYMBOL_SUFFIXES or bool(SYMBOL_NAME_RE.match(p.name))


def scan(img_root=None):
    """扫描 img_root，返回 Entry 列表（按标签排序）。"""
    root = Path(img_root or DEFAULT_IMG_ROOT)
    if not root.is_dir():
        raise FileNotFoundError(f"镜像目录不存在: {root}")

    entries = []
    for directory in sorted([root] + [p for p in root.rglob("*") if p.is_dir()]):
        rel = directory.relative_to(root)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue
        files = sorted(p for p in directory.iterdir() if p.is_file() and not p.name.startswith("."))
        images = [p for p in files if _is_image(p)]
        symbols = [p for p in files if _is_symbol(p)]
        if not images and not symbols:
            continue
        base = str(rel).replace("\\", "/") if rel.parts else None
        base = None if base in (".", "") else base
        if not images:
            entries.append(Entry(label=base or "unknown", stem="", directory=directory, symbols=symbols,
                                 labels_hint="只有符号表，没有镜像（无法推导偏移，可作跨版本符号核对）"))
            continue
        for image in images:
            stem = image.stem
            if base and len(images) > 1:
                label = f"{base}/{stem}"
            else:
                label = base
            entries.append(Entry(label=label, stem=stem, directory=directory, image=image, symbols=symbols,
                                 labels_hint="" if base else "平铺镜像：标签按解包后内嵌内核版本推导"))
    return sorted(entries, key=lambda e: (e.label or f"~{e.stem}"))


def describe(entry):
    """一行描述，用于 --list 与「请挑一个」提示。"""
    if entry.image is None:
        return f"(仅符号表)  {entry.label}  ← {entry.directory}"
    if entry.label:
        label = entry.label
    elif entry.aliases:
        label = "/".join(sorted(entry.aliases)) + "（上次提取）"
    else:
        label = "(按内嵌版本自动推导)"
    return f"{entry.image.name}  →  标签 {label}"


def resolve(entries, selectors):
    """按用户给的名字挑镜像。

    支持：文件名（`B2N-416G_boot.img`）、去扩展名的 stem（`B2N-416G_boot`）、
    标签（`4.9/miui`）、以及它们的大小写不敏感子串。
    返回 (matched, problems)；problems 里是「没找到 / 匹配到多个」的说明，供上层提示用户。
    """
    matched, problems = [], []
    for selector in selectors:
        sel = selector.strip().lower()
        exact, fuzzy = [], []
        for entry in entries:
            names = {entry.stem.lower()}
            if entry.image is not None:
                names.add(entry.image.name.lower())
            if entry.label:
                names.add(entry.label.lower())
            names |= {a.lower() for a in entry.aliases}
            names.discard("")
            if sel in names:
                exact.append(entry)
            elif sel and any(sel in n for n in names):
                fuzzy.append(entry)
        hits = exact or fuzzy
        if not hits:
            problems.append(f"没找到匹配 {selector!r} 的镜像/符号表")
        elif len(hits) > 1:
            problems.append(f"{selector!r} 匹配到 {len(hits)} 个，需要明确指定："
                            + "；".join(describe(h) for h in hits))
        else:
            if hits[0] not in matched:
                matched.append(hits[0])
    return matched, problems


def pick(entries, prompt="选择要处理的镜像编号: "):
    """交互式挑选（仅在 TTY 下询问）；返回选中的 Entry 或 None。"""
    if not entries:
        return None
    if not sys.stdin.isatty():
        return None
    for i, entry in enumerate(entries, 1):
        print(f"  {i:2d}) {describe(entry)}")
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not raw:
        return None
    try:
        idx = int(raw)
    except ValueError:
        print(f"  {raw!r} 不是编号")
        return None
    if 1 <= idx <= len(entries):
        return entries[idx - 1]
    print(f"  编号超出范围 1..{len(entries)}")
    return None


def load_index(local_root=None):
    """读取 local/extracted/index.json（若存在）：[{label, source, kernel_path, release, ...}]。"""
    path = Path(local_root or DEFAULT_LOCAL_ROOT) / "extracted" / "index.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    return data.get("entries", [])


def annotate_from_index(entries, local_root=None):
    """把上次提取得到的标签（如 4.14/4.14.356-Liberty）作为别名挂到对应条目上，
    这样用户可以直接用标签或版本号（4.14）来挑镜像。
    """
    index = load_index(local_root)
    if not index:
        return entries
    by_source = {}
    for record in index:
        source = Path(record.get("source", "")).name.lower()
        if source:
            by_source.setdefault(source, set()).add(record.get("label", ""))
    for entry in entries:
        if entry.image is None:
            continue
        labels = by_source.get(entry.image.name.lower(), set()) | by_source.get(entry.image.stem.lower(), set())
        entry.aliases |= {x for x in labels if x}
    return entries


def extracted_path(label, local_root=None):
    """裸 kernel 的本地落点：local/extracted/<label>/Image。"""
    root = Path(local_root or DEFAULT_LOCAL_ROOT)
    return root / "extracted" / label / "Image"


GIT_HASH_RE = re.compile(r"^g?[0-9a-f]{7,}$", re.I)


def short_release(release, limit=40):
    """把完整 release 截成适合做目录名的短标签。

    5.15.189-android13-8-00016-g51bba4309aac-ab14546557 -> 5.15.189-android13-8-00016
    4.4.192-perf+ -> 4.4.192-perf+
    """
    if not release:
        return ""
    keep = [release.split("-")[0]]
    for seg in release.split("-")[1:]:
        if GIT_HASH_RE.match(seg):
            break
        if len("-".join(keep + [seg])) > limit:
            break
        keep.append(seg)
    return "-".join(keep)[:limit].rstrip("-._")


def display_path(path, base=None):
    """能相对仓库根表示就相对表示（输出可能被粘贴进报告，避免泄露本机绝对路径）。"""
    try:
        return str(Path(path).resolve().relative_to(base or HERE.parent.parent))
    except Exception:
        return str(path)


def resolve_path(path, base=None):
    """把 display_path 产生的仓库相对路径还原成绝对路径。"""
    p = Path(path)
    if p.is_absolute():
        return p
    return (base or HERE.parent.parent) / p


def safe_label(text, fallback="unknown"):
    text = re.sub(r"[^A-Za-z0-9._+-]+", "_", (text or "").strip())
    return text.strip("._-") or fallback
