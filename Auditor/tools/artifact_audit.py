#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""产物独立审计：自解析 .kpm 字节，校验身份、结构、符号可解析性与跨版本内核符号依赖。

独立性声明:
  * 本工具自带 ELF64 解析（不使用 tools/identity.py、不导入 pyelftools）；
  * 不调用 kernel_img/offset_harness，也不读模块源码里的偏移结论；
  * 平台符号快照来自 KernelPatch submodule（Auditor/tools/kp_symbols_extract.py）；
  * 语料内核符号表来自本地输入（kernel_img/**）与 harness 输出（local/kernel_offset/**），
    属**同源风险**：这些语料由使用者/Developer 提供，报告必须声明来源与是否在场。

用法:
  python3 Auditor/tools/artifact_audit.py --module re_kernel
  python3 Auditor/tools/artifact_audit.py --module re_kernel --build-id <id>
  python3 Auditor/tools/artifact_audit.py --module re_kernel --json Auditor/reports/data/<name>.json

审计对象枚举（P3/AUD-010）:
  默认除登记表里的产物外，还**独立扫描** `artifacts/**/*.kpm`（可用 `--artifacts-dir` 改/加目录），
  报出「未登记产物」「字节与已登记产物相同的副本」「登记了但不在场」。登记表是维护方的记录，
  不能反过来决定审计覆盖范围；`--strict-unregistered` 时存在未登记字节即返回非零。
"""

import argparse
import glob
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ELF_MAGIC = b"\x7fELF"
ET_REL = 1
EM_AARCH64 = 183
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_STRTAB = 3
SHN_UNDEF = 0

# AArch64 静态重定位类型白名单（KPM 为 ET_REL，由 KP 加载器处理）
AARCH64_RELOC_NAMES = {
    # 取值由审计对象自身的重定位节与 llvm-readelf 的命名交叉确认（见 Auditor/reports）
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    259: "R_AARCH64_ABS16",
    260: "R_AARCH64_PREL64",
    261: "R_AARCH64_PREL32",
    262: "R_AARCH64_PREL16",
    273: "R_AARCH64_LD_PREL_LO19",
    274: "R_AARCH64_ADR_PREL_LO21",
    275: "R_AARCH64_ADR_PREL_PG_HI21",
    276: "R_AARCH64_ADR_PREL_PG_HI21_NC",
    277: "R_AARCH64_ADD_ABS_LO12_NC",
    278: "R_AARCH64_LDST8_ABS_LO12_NC",
    279: "R_AARCH64_TSTBR14",
    280: "R_AARCH64_CONDBR19",
    281: "R_AARCH64_JUMP26",
    282: "R_AARCH64_ADR_GOT_PAGE",
    283: "R_AARCH64_CALL26",
    284: "R_AARCH64_LDST16_ABS_LO12_NC",
    285: "R_AARCH64_LDST32_ABS_LO12_NC",
    286: "R_AARCH64_LDST64_ABS_LO12_NC",
    287: "R_AARCH64_LDST128_ABS_LO12_NC",
    311: "R_AARCH64_MOVW_UABS_G0",
    312: "R_AARCH64_MOVW_UABS_G0_NC",
    313: "R_AARCH64_MOVW_UABS_G1",
    314: "R_AARCH64_MOVW_UABS_G1_NC",
}
R_ADR_PREL_PG_HI21 = 275
R_ADD_ABS_LO12_NC = 277
R_CALL26 = 283
LOOKUP_SYMBOLS = ("kallsyms_lookup_name_by_suffix", "kallsyms_lookup_name", "kallsyms_on_each_symbol")
REQUIRED_INFO_FIELDS = ("name", "version", "license", "author", "description")
REQUIRED_SECTIONS = (".kpm.info", ".kpm.init", ".kpm.ctl0", ".kpm.exit")
# 加载器（KernelPatch/kernel/patch/module/module.c:221）只查 .kp.symbol 表；
# LKM 加载器（lkm/kpm/module.c:390）额外有 kallsyms 兜底。
LKM_KALLSYMS_FALLBACK = True


class Elf:
    """最小 ELF64 little-endian 解析器（自带实现，用于独立审计）。"""

    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.errors = []
        self._parse_header()
        self._parse_sections()
        self._parse_symbols()
        self._parse_relocations()

    def _parse_header(self):
        d = self.data
        if len(d) < 64 or d[:4] != ELF_MAGIC:
            raise ValueError("不是 ELF 文件")
        self.elfclass, self.encoding = d[4], d[5]
        self.etype, self.emachine = struct.unpack_from("<HH", d, 16)
        self.e_shoff, = struct.unpack_from("<Q", d, 0x28)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)
        if self.elfclass != 2 or self.encoding != 1:
            self.errors.append("非 ELF64 little-endian")
        if self.etype != ET_REL:
            self.errors.append(f"e_type={self.etype} 不是 ET_REL")
        if self.emachine != EM_AARCH64:
            self.errors.append(f"e_machine={self.emachine} 不是 AArch64")
        if self.e_shoff == 0 or self.e_shoff + self.e_shnum * self.e_shentsize > len(d):
            self.errors.append("节表超出文件范围")

    def _parse_sections(self):
        d = self.data
        self.sections = []
        raw = []
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            name, stype, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(
                "<IIQQQQIIQQ", d, base)
            if offset + size > len(d) and stype != 8:  # SHT_NOBITS 无内容
                self.errors.append(f"节 #{i} 内容超出文件范围")
            raw.append((name, stype, flags, addr, offset, size, link, info, align, entsize))
        shstr = raw[self.e_shstrndx] if self.e_shstrndx < len(raw) else None
        shstr_data = d[shstr[4]:shstr[4] + shstr[5]] if shstr else b""
        for (name, stype, flags, addr, offset, size, link, info, align, entsize) in raw:
            end = shstr_data.find(b"\x00", name)
            self.sections.append({
                "name": shstr_data[name:end].decode("utf-8", "replace"),
                "type": stype, "flags": flags, "offset": offset, "size": size,
                "link": link, "info": info, "entsize": entsize,
                "content": d[offset:offset + size] if stype != 8 else b"",
            })

    def section(self, name):
        return next((s for s in self.sections if s["name"] == name), None)

    def _parse_symbols(self):
        self.symbols = []
        symtab = next((s for s in self.sections if s["type"] == SHT_SYMTAB), None)
        if not symtab:
            self.errors.append("缺少 .symtab")
            return
        strtab = self.sections[symtab["link"]] if symtab["link"] < len(self.sections) else None
        data = strtab["content"] if strtab else b""
        count = symtab["size"] // 24
        for i in range(count):
            nameoff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", symtab["content"], i * 24)
            end = data.find(b"\x00", nameoff)
            name = data[nameoff:end].decode("utf-8", "replace") if nameoff < len(data) else ""
            self.symbols.append({"name": name, "info": info, "shndx": shndx, "value": value, "size": size,
                                 "type": info & 0xF, "bind": info >> 4})

    def _parse_relocations(self):
        self.relocations = []
        for sec in self.sections:
            if sec["type"] != SHT_RELA:
                continue
            target = self.sections[sec["info"]] if sec["info"] < len(self.sections) else None
            count = sec["size"] // 24 if sec["entsize"] in (0, 24) else sec["size"] // sec["entsize"]
            for i in range(count):
                offset, info, addend = struct.unpack_from("<QQq", sec["content"], i * 24)
                symidx, rtype = info >> 32, info & 0xFFFFFFFF
                self.relocations.append({
                    "section": sec["name"], "target": target["name"] if target else "?",
                    "target_size": target["size"] if target else 0,
                    "offset": offset, "type": rtype, "symidx": symidx, "addend": addend,
                    "sym": self.symbols[symidx]["name"] if symidx < len(self.symbols) else "?",
                    "sym_section": self._sym_section(symidx),
                })

    def _sym_section(self, symidx):
        """符号所属节名（LLVM 的 STT_SECTION 符号无名字，只能按 shndx 还原）。"""
        if symidx >= len(self.symbols):
            return "?"
        shndx = self.symbols[symidx]["shndx"]
        if shndx < len(self.sections):
            return self.sections[shndx]["name"]
        return "?"

    def undefined_symbols(self):
        return sorted({s["name"] for s in self.symbols if s["shndx"] == SHN_UNDEF and s["name"]})

    def strings(self, min_len=4):
        out = set()
        for sec in self.sections:
            if sec["type"] != 1:
                continue
            for match in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{2,63}", sec["content"]):
                text = match.group().decode()
                if len(text) >= min_len:
                    out.add(text)
        return out


def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def parse_kpm_info(blob):
    info = {}
    for field in blob.split(b"\x00"):
        if b"=" in field:
            k, _, v = field.partition(b"=")
            info[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
    return info


def load_snapshot(path=None):
    if path is None:
        candidates = sorted(glob.glob(os.path.join(REPO, "Auditor", "snapshots", "kp_runtime_symbols-*.json")))
        if not candidates:
            return None, None
        path = candidates[-1]
    snapshot = json.load(open(path, encoding="utf-8"))
    return snapshot, path


DEFAULT_CORPUS_ROOTS = (
    os.path.join(REPO, "kernel_img"),   # 用户放置的符号表（不进 git）
    os.path.join(REPO, "local"),        # 提取出的裸 kernel 与 harness 输出（不进 git）
)


CONTAINER_DIRS = {"offset_harness", "out", "kernel_offset", "extracted", "corpus", "cache", "local"}


def _label_from(path, root):
    """kernel_img/4.9/miui/kallsyms.txt -> 4.9/miui。

    同时剥掉工具/输出目录前缀，使 kernel_img/** 与 offset_harness/out/** 里的
    同一内核归到同一个 <major>/<sub> 标签（多来源取并集）。
    """
    parts = [p for p in os.path.relpath(os.path.dirname(path), root).split(os.sep) if p not in ("", ".")]
    while parts and parts[0] in CONTAINER_DIRS:
        parts.pop(0)
    if not parts:
        stem = os.path.basename(path)
        for prefix in ("kallsyms_", "kernel_"):
            if stem.startswith(prefix):
                stem = stem[len(prefix):]
        return os.path.splitext(stem)[0]
    return "/".join(parts)


def corpus_symbols(roots):
    """扫描本地语料：返回 ({label: set(names)}, [来源说明])。"""
    corpus, sources = {}, []
    py_suffix = (".i64", ".md", ".json", ".log", ".py", ".pyc")
    for root in roots:
        if not os.path.isdir(root):
            sources.append(f"{os.path.relpath(root, REPO)} (不在场)")
            continue
        count = 0
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git"}]
            for name in names:
                if name.endswith(py_suffix) or name.startswith("."):
                    continue
                is_kallsyms = name.endswith(".kallsyms") or (
                    name.endswith(".txt") and ("kallsyms" in name.lower()))
                if not is_kallsyms:
                    continue
                path = os.path.join(dirpath, name)
                names_set = set()
                for line in open(path, encoding="utf-8", errors="replace"):
                    tokens = line.split()
                    if len(tokens) >= 3 and len(tokens[1]) == 1:
                        names_set.add(tokens[2])
                    elif len(tokens) == 2 and len(tokens[1]) > 1 and tokens[1][0].isalpha():
                        names_set.add(tokens[1][1:])
                if not names_set:
                    continue
                label = _label_from(path, root)
                corpus.setdefault(label, set()).update(names_set)
                count += 1
        sources.append(f"{os.path.relpath(root, REPO)} ({count} 个符号表)")
    return corpus, sources


def audit_artifact(path, record, snapshot, snapshot_path, corpus, makefile_version, expected_build_id=None):
    elf = Elf(path)
    findings = []
    facts = {
        "path": os.path.relpath(path, REPO),
        "name": os.path.basename(path),
        "sha256": sha256_file(path),
        "size": os.path.getsize(path),
    }

    # 结构
    facts["structure_errors"] = elf.errors
    for name in REQUIRED_SECTIONS:
        sec = elf.section(name)
        if sec is None:
            findings.append(("error", "missing_section", f"缺少必需节 {name}"))
        elif sec["size"] == 0:
            findings.append(("error", "empty_section", f"节 {name} 为空"))
    for name in (".kpm.init", ".kpm.ctl0", ".kpm.exit"):
        sec = elf.section(name)
        if sec is not None and sec["size"] not in (0, 8):
            findings.append(("review", "entry_size", f"入口节 {name} 大小为 {sec['size']}，预期 8"))

    # 内嵌元信息
    info_sec = elf.section(".kpm.info")
    info = parse_kpm_info(info_sec["content"]) if info_sec else {}
    facts["embedded"] = info
    miss = [f for f in REQUIRED_INFO_FIELDS if f not in info]
    if miss:
        findings.append(("error", "info_fields", f".kpm.info 缺字段 {miss}"))
    expected_ver = makefile_version
    if record and expected_build_id:
        for build in record.get("builds", []):
            if build.get("build_id") == expected_build_id:
                if build.get("version"):
                    expected_ver = build.get("version")
                break
    if expected_ver:
        norm = re.sub(r"_(n|d|nd|network|debug|network_debug)$", "", info.get("version", ""))
        if norm and norm != expected_ver:
            findings.append(("error", "version_mismatch",
                             f"内嵌 version={info.get('version')} 与构建声明 {expected_ver} 不一致"))
    if record and info.get("name") and info["name"] != record.get("module") and record.get("module") != f"{info['name']}_static":
        findings.append(("error", "name_mismatch", f"内嵌 name={info['name']} 与模块记录 {record.get('module')} 不符"))

    # 身份复算
    if record:
        declared = None
        norm_path = os.path.normpath(facts["path"])
        for build in record.get("builds", []):
            if expected_build_id and build.get("build_id") != expected_build_id:
                continue
            for art in build.get("artifacts", []):
                if art.get("path") and os.path.normpath(art["path"]) == norm_path:
                    declared = (build["build_id"], art["sha256"])
                    break
                elif art.get("name") == facts["name"] and declared is None:
                    declared = (build["build_id"], art["sha256"])
        if declared is None:
            findings.append(("error", "not_recorded", "该产物未在 metadata 中登记（身份缺失）"))
        elif declared[1] != facts["sha256"]:
            findings.append(("error", "hash_mismatch",
                             f"产物哈希与元数据不符（记录 {declared[1][:16]}…，实算 {facts['sha256'][:16]}…）"))
        else:
            facts["build_id"] = declared[0]

    # 未定义符号可解析性
    und = elf.undefined_symbols()
    facts["undefined_symbols"] = und
    kp_symbols = set(snapshot.get("symbols", {})) if snapshot else set()
    facts["kp_symbols_source"] = os.path.relpath(snapshot_path, REPO) if snapshot_path else None
    resolved, unresolved = [], []
    for name in und:
        if name in kp_symbols:
            resolved.append(name)
        else:
            unresolved.append(name)
    facts["unresolved_symbols"] = unresolved
    for name in unresolved:
        hint = ""
        if name.startswith(("kf_", "kv_")):
            hint = "（KP 运行时可解析符号；内核态 KP 只查 .kp.symbol 表，LKM 态才有 kallsyms 兜底）"
        findings.append(("error", "symbol_unresolved",
                         f"未定义符号 {name} 不在平台符号快照中{hint}"))

    # 重定位自洽
    reloc_types = {}
    bad_relocs = 0
    for r in elf.relocations:
        reloc_types[r["type"]] = reloc_types.get(r["type"], 0) + 1
        if r["symidx"] >= len(elf.symbols):
            bad_relocs += 1
        if r["target_size"] and r["offset"] + 8 > r["target_size"] and r["type"] not in (257,):
            bad_relocs += 1
        if r["type"] not in AARCH64_RELOC_NAMES:
            findings.append(("review", "reloc_type", f"未在预期白名单内的重定位类型 {r['type']}（{r['section']}）"))
    facts["relocations"] = {
        "count": len(elf.relocations),
        "bad": bad_relocs,
        "types": {AARCH64_RELOC_NAMES.get(t, f"type_{t}"): c for t, c in sorted(reloc_types.items())},
    }
    if bad_relocs:
        findings.append(("error", "relocation_bounds", f"{bad_relocs} 条重定位越界或符号索引非法"))

    # 跨版本内核符号依赖：从产物字符串里取“在语料符号表中出现过的名字”
    lookups = lookup_names(elf)
    facts["lookup_names"] = [n for n, _, _ in lookups]
    facts["lookup_kinds"] = {n: k for n, k, _ in lookups}
    facts["kernel_symbol_dependencies"] = cross_version_dependencies(
        {n for n, _, _ in lookups}, corpus)
    for name, dep in sorted(facts["kernel_symbol_dependencies"].items()):
        if not dep["missing"]:
            continue
        kind = facts["lookup_kinds"].get(name, "?")
        if kind == "exact":
            hard = ("取 kallsyms_lookup_name 函数指针后间接调用：无法从产物区分 lookup_name（缺失即 init 返回 -21）"
                    "与 lookup_name_continue（容忍缺失、可能带回退），需核对源码确认")
        else:
            hard = ("经 kallsyms_lookup_name_by_suffix 后缀查找：缺失时指针为 NULL，"
                    "是否安全取决于调用点有无空指针保护")
        findings.append(("review", "kernel_symbol_gap",
                         f"{name} 在语料 {', '.join(dep['missing'])} 的符号表中不存在；{hard}"))

    return facts, findings


def lookup_names(elf):
    """提取 kallsyms_lookup_name[_by_suffix](<字符串>) 的实际实参。

    产物里有两种取符号的形态（LLVM/Clang，-fno-PIC）：
      * 直接调用：CALL26 -> kallsyms_lookup_name_by_suffix；
      * 间接调用：ADR_PREL_PG_HI21 + LDST64 取 kallsyms_lookup_name（KP 导出的函数指针）后 BLR。
    两种形态都先用 ADR_PREL_PG_HI21 + ADD_ABS_LO12_NC 把字符串地址装进寄存器，
    因此策略是：找“字符串取址”指令对，再看其后方窗口里是否出现 lookup 引用。
    """
    relocs = [r for r in elf.relocations if r["section"] == ".rela.text"]
    str_secs = {s["name"]: s for s in elf.sections if s["type"] == 1 and s["name"].startswith(".rodata")}
    found = []
    for adrp in relocs:
        if adrp["type"] != R_ADR_PREL_PG_HI21 or adrp["sym_section"] not in str_secs:
            continue
        add = next((r for r in relocs if r["type"] == R_ADD_ABS_LO12_NC
                    and adrp["offset"] < r["offset"] <= adrp["offset"] + 8
                    and r["sym_section"] == adrp["sym_section"]), None)
        if add is None:
            continue
        offset = (adrp["addend"] & ~0xFFF) | (add["addend"] & 0xFFF)
        content = str_secs[adrp["sym_section"]]["content"]
        if offset >= len(content):
            continue
        end = content.find(b"\x00", offset)
        text = content[offset:end].decode("utf-8", "replace")
        if not text or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{1,127}", text):
            continue
        refs = [r for r in relocs
                if adrp["offset"] < r["offset"] <= adrp["offset"] + 64
                and ((r["type"] == R_CALL26 and r["sym"] in LOOKUP_SYMBOLS) or r["sym"] in LOOKUP_SYMBOLS)]
        if not refs:
            continue
        # CALL26 -> kallsyms_lookup_name_by_suffix（软：找不到为 NULL，由代码自行处理）
        # 其余 -> 取 kallsyms_lookup_name 函数指针后 BLR（硬：lookup_name 宏找不到就 return -21）
        kind = "suffix" if any(r["type"] == R_CALL26 and r["sym"].endswith("_by_suffix") for r in refs) else "exact"
        found.append((text, kind, adrp["offset"]))
    seen, unique = set(), []
    for name, kind, offset in sorted(found, key=lambda x: x[2]):
        if name not in seen:
            seen.add(name)
            unique.append((name, kind, offset))
    return unique


def cross_version_dependencies(names, corpus):
    """给定的内核符号名在语料符号表里的存在矩阵。"""
    if not corpus:
        return {}
    labels = sorted(corpus)
    deps = {}
    for name in sorted(names):
        present = [label for label in labels if name in corpus[label]]
        if not present:
            continue
        deps[name] = {
            "present": present,
            "missing": [label for label in labels if label not in present],
        }
    return deps


def registered_artifact_index(record):
    """登记表里的产物：规范化相对路径 -> (build_id, sha256)。"""
    index = {}
    for build in record.get("builds", []):
        for art in build.get("artifacts", []):
            index[os.path.normpath(art["path"])] = (build.get("build_id"), art.get("sha256"))
    return index


def scan_artifact_dirs(dirs, index):
    """独立枚举磁盘上的 .kpm 字节，报出登记表覆盖不到的产物（P3/AUD-010）。

    审计对象若只来自维护方的登记表，未登记的产物字节就永远不进审计视野。这里不采信登记表，
    自己走目录；命中登记表只用于分类，不用于「跳过检查」。
    """
    findings, seen, roots = [], [], []
    for d in dirs:
        root = d if os.path.isabs(d) else os.path.join(REPO, d)
        roots.append(os.path.normpath(os.path.relpath(root, REPO)))
        for path in sorted(glob.glob(os.path.join(root, "**", "*.kpm"), recursive=True)):
            rel = os.path.relpath(path, REPO)
            seen.append(os.path.normpath(rel))
            if os.path.normpath(rel) in index:
                continue
            digest = sha256_file(path)
            size = os.path.getsize(path)
            same = sorted(r for r, (_, sha) in index.items() if sha and sha == digest)
            if same:
                findings.append(("review", "duplicate_artifact_bytes",
                                 f"{rel}（{size} 字节）字节与已登记产物 {same[0]} 相同：不构成新的审计对象，"
                                 "但说明归档目录里存在登记表之外的副本"))
            else:
                findings.append(("review", "unregistered_artifact",
                                 f"{rel}（sha256={digest[:16]}…，{size} 字节）不在登记表内："
                                 "无法绑定 commit/Build ID，此前对审计不可见"))
    for rel in sorted(index):
        if not any(rel == r or rel.startswith(r.rstrip("/") + "/") for r in roots):
            continue
        if rel not in seen and not os.path.isfile(os.path.join(REPO, rel)):
            findings.append(("review", "registered_artifact_missing",
                             f"登记表里的 {rel} 不在场：该实例的产物哈希无法复算"))
    return findings, seen, roots


def main():
    ap = argparse.ArgumentParser(description="KPM 产物独立审计")
    ap.add_argument("--module", required=True)
    ap.add_argument("--build-id")
    ap.add_argument("--manifest", help="交接清单或自定义登记表路径（若未导入 metadata/modules）")
    ap.add_argument("--corpus", action="append",
                    help="符号表目录（可重复；默认 kernel_img/ 与 local/）")
    ap.add_argument("--snapshot")
    ap.add_argument("--json")
    ap.add_argument("--artifacts-dir", action="append",
                    help="独立扫描的产物目录（可重复；默认 artifacts/）")
    ap.add_argument("--strict-unregistered", action="store_true",
                    help="存在未登记产物时返回非零（默认只报 review）")
    args = ap.parse_args()

    record = None
    record_path = os.path.join(REPO, "metadata", "modules", f"{args.module}.json")
    if os.path.isfile(record_path):
        record = json.load(open(record_path, encoding="utf-8"))
    elif args.manifest and os.path.isfile(args.manifest):
        record_path = args.manifest
        record = json.load(open(record_path, encoding="utf-8"))
    else:
        candidates = [args.module, args.module.replace("_", "-")]
        handoffs = []
        for c in candidates:
            handoffs.extend(glob.glob(os.path.join(REPO, "Developer", "reports", "handoffs", f"*{c}*.json")))
        handoffs = [h for h in set(handoffs) if not h.endswith("-selfcheck.json")]
        candidate_handoffs = [h for h in handoffs if "candidate" in os.path.basename(h)]
        if candidate_handoffs:
            handoffs = sorted(candidate_handoffs, key=os.path.getmtime)
        else:
            handoffs = sorted(handoffs, key=os.path.getmtime)
        if handoffs:
            record_path = handoffs[-1]
            record = json.load(open(record_path, encoding="utf-8"))
            print(f"info: metadata 未导入，采用交接清单 {os.path.relpath(record_path, REPO)} 作为审计基准", file=sys.stderr)

    if record is None:
        print(f"error: 找不到 {os.path.relpath(record_path, REPO)}，亦无可用交接清单", file=sys.stderr)
        return 2

    makefile_version = None
    makefile = os.path.join(REPO, args.module, "Makefile")
    if os.path.isfile(makefile):
        m = re.search(r"^\s*MYKPM_VERSION\s*:?=\s*(\S+)", open(makefile, encoding="utf-8").read(), re.M)
        makefile_version = m.group(1) if m else None

    snapshot, snapshot_path = load_snapshot(args.snapshot)
    if snapshot is None:
        print("error: 缺少平台符号快照，先运行 Auditor/tools/kp_symbols_extract.py", file=sys.stderr)
        return 2
    corpus, corpus_sources = corpus_symbols(args.corpus or list(DEFAULT_CORPUS_ROOTS))

    registered = registered_artifact_index(record)
    scan_dirs = args.artifacts_dir or ["artifacts"]
    scan_findings, scanned_paths, scan_roots = scan_artifact_dirs(scan_dirs, registered)
    unregistered = [message for _, kind, message in scan_findings if kind == "unregistered_artifact"]

    targets = []
    for build in record.get("builds", []):
        if args.build_id and build["build_id"] != args.build_id:
            continue
        for art in build.get("artifacts", []):
            path = os.path.join(REPO, art["path"])
            if os.path.isfile(path):
                targets.append((build["build_id"], path))
    if not targets and not scan_findings:
        print("error: 没有可审计的产物（产物不在场？）", file=sys.stderr)
        return 2
    if not targets:
        print("warning: 登记表里没有在场产物，仅输出产物目录独立扫描结果", file=sys.stderr)

    report = {
        "auditor_tool": "Auditor/tools/artifact_audit.py",
        "audited_at": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "module": args.module,
        "kp_symbols_snapshot": os.path.relpath(snapshot_path, REPO),
        "kp_symbols_source_commit": snapshot.get("kernelpatch_commit"),
        "corpus_labels": sorted(corpus),
        "corpus_sources": corpus_sources,
        "lkm_kallsyms_fallback": LKM_KALLSYMS_FALLBACK,
        "artifact_scan": {
            "dirs": scan_roots,
            "kpm_on_disk": scanned_paths,
            "registered": sorted(registered),
        },
        "artifacts": [],
        "findings": [],
    }
    exit_code = 0
    for severity, kind, message in scan_findings:
        report["findings"].append({
            "severity": severity, "kind": kind, "artifact": "<artifacts-scan>", "message": message,
        })
    if args.strict_unregistered and unregistered:
        exit_code = 1
    for build_id, path in targets:
        facts, findings = audit_artifact(path, record, snapshot, snapshot_path, corpus, makefile_version, expected_build_id=build_id)
        facts["build_id"] = build_id
        report["artifacts"].append(facts)
        for severity, kind, message in findings:
            report["findings"].append({
                "severity": severity, "kind": kind, "artifact": facts["name"], "message": message,
            })
            if severity == "error":
                exit_code = 1

    print(f"# 产物独立审计：{args.module}")
    print()
    print(f"- 审计时间：{report['audited_at']}")
    print(f"- 平台符号快照：{report['kp_symbols_snapshot']}（KernelPatch {report['kp_symbols_source_commit']}）")
    print(f"- 语料来源：{'; '.join(corpus_sources)}")
    if corpus:
        print(f"- 语料内核：{len(corpus)} 个（{', '.join(sorted(corpus))}）")
    else:
        print("- 语料内核：0 个 —— 本地没有可用的符号表，跨版本符号矩阵本次未执行（报告须如实声明）")
    print()
    for facts in report["artifacts"]:
        print(f"## {facts['name']} ({facts.get('build_id')})")
        print()
        print(f"- sha256：`{facts['sha256']}`（{facts['size']} 字节）")
        print(f"- 内嵌：{facts['embedded']}")
        print(f"- 未定义符号 {len(facts['undefined_symbols'])} 个，未解析 {len(facts['unresolved_symbols'])} 个："
              f"{', '.join(facts['unresolved_symbols']) or '无'}")
        print(f"- 重定位 {facts['relocations']['count']} 条，越界 {facts['relocations']['bad']} 条；类型："
              f"{', '.join(f'{k}×{v}' for k, v in facts['relocations']['types'].items())}")
        deps = facts["kernel_symbol_dependencies"]
        if deps:
            partial = {k: v for k, v in deps.items() if v["missing"]}
            print(f"- 内核符号依赖 {len(deps)} 个（缺失项 {len(partial)} 个）")
            for name, dep in sorted(partial.items()):
                print(f"    - {name}: 缺 {', '.join(dep['missing'])}")
        print()
    print("## 产物目录独立扫描（不采信登记表）")
    print()
    print(f"- 扫描目录：{', '.join(scan_roots)}；磁盘上 .kpm {len(scanned_paths)} 个；登记表 {len(registered)} 条")
    scan_only = [f for f in report["findings"] if f["artifact"] == "<artifacts-scan>"]
    if not scan_only:
        print("- 磁盘上的 .kpm 与登记表一致（无未登记字节，也无登记后缺失的实例）")
    for f in scan_only:
        print(f"- [{f['severity']}] {f['kind']}: {f['message']}")
    print()
    print("## Findings")
    print()
    if not report["findings"]:
        print("- 无")
    for f in report["findings"]:
        print(f"- [{f['severity']}] {f['artifact']} {f['kind']}: {f['message']}")
    print()
    if exit_code:
        if any(f["severity"] == "error" for f in report["findings"]):
            print("结论：有阻塞性问题（error）")
        else:
            print("结论：阻塞 —— 存在未登记产物字节（--strict-unregistered）")
    else:
        print("结论：未发现阻塞性问题（仍有需人工确认的 review 项）")

    if args.json:
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"机器可读结果：{os.path.relpath(args.json, REPO)}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
