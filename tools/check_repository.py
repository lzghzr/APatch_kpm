#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""仓库门禁：结构 / CI 约定 / 文档链接 / 元数据 / 身份哈希 / 版本一致性 / 报告规范 / 审计独立性 / 公开文件卫生。

用法:
  python3 tools/check_repository.py            # 常规门禁（产物缺失只警告）
  python3 tools/check_repository.py --strict   # 验收/发布门禁（产物必须在场且哈希可复算）

门禁只检查可机检的事实；它不代替审计、不代替实机测试，也不产生交付结论。
"""

import argparse
import ast
import codecs
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)          # 仓库根（可被夹具改写）

# 注意：TOOLS_DIR 固定按本文件位置解析，不受 REPO 影响

REQUIRED_PATHS = [
    "AGENTS.md", "docs/README.md", "docs/coverage.md", "metadata/README.md", "metadata/identity.json",
    "docs/process/01-identity.md", "docs/process/02-roles.md", "docs/process/03-round-flow.md",
    "docs/process/04-issue-ticket.md", "docs/process/05-maintainer-acceptance.md",
    "docs/process/06-antipatterns.md", "docs/process/07-escalation-device.md",
    "tools/identity.py", "tools/build_candidate.py", "tools/selftest_tools.py", "tools/freeze_check.py",
    "tools/check_repository.py", "tools/artifact_gate.py", "tools/selftest_artifact_gate.py",
    ".github/workflows/build-kpm.yml",
    "Auditor/tools/artifact_audit.py", "Auditor/tools/static_scan.py",
    "Tester/tools/preflight.sh", "Tester/tools/run_test.sh", "Tester/tools/selftest_scripts.sh",
    "Developer/README.md", "Auditor/README.md", "Tester/README.md",
]
# 目录级：只要求存在（以及最低文件数），不再逐一点名模板/手册文件
REQUIRED_DIRS = [("docs/templates", ".md", 1), ("docs/process", ".md", 7), ("Auditor/tools", ".py", 2),
                 ("Tester/tools", ".sh", 3), ("metadata/modules", ".json", 1), ("Developer/reports", None, 0)]

TOP_LEVEL_DOCS = [
    "AGENTS.md",
    "README.md",
    "kernel_img/README.md",
    "kernel_img/offset_harness/README.md",
    "metadata/README.md",
    "Auditor/README.md",
    "Tester/README.md",
    "Developer/README.md",
]

AUDITOR_REPORT_REQUIRED = ["身份", "commit", "Build ID", "sha256", "同源风险", "未验证"]
TESTER_REPORT_REQUIRED = ["身份", "commit", "Build ID", "sha256", "环境事实", "未覆盖"]

HYGIENE_PATTERNS = [
    (re.compile(r"/(Users|Volumes|home)/[A-Za-z0-9._-]+"), "本机绝对路径"),
    (re.compile(r"(?i)\bsuperkey\s*=\s*[A-Za-z0-9]{4,}"), "疑似 superkey 明文"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "私钥内容"),
    (re.compile(r"(?i)\b(serial|serialno|serial_no)\s*=\s*[A-Za-z0-9]{6,}"), "明文设备序列号"),
]

TEXT_SUFFIX = (".md", ".json", ".py", ".sh", ".yml", ".yaml")
SCAN_ROOTS = ["AGENTS.md", "README.md", "docs", "metadata", "Auditor", "Tester", "Developer", "tools",
              "kernel_img/README.md", "kernel_img/offset_harness"]
SKIP_WALK_DIRS = {"__pycache__", ".git", "out"}


class Report:
    def __init__(self):
        self.failures = []
        self.warnings = []
        self.checks = []

    def check(self, name, ok, detail="", warn_only=False):
        status = "PASS" if ok else ("WARN" if warn_only else "FAIL")
        self.checks.append((name, status, detail))
        if not ok:
            (self.warnings if warn_only else self.failures).append(f"{name}: {detail}")

    def summary(self):
        width = max(len(n) for n, _, _ in self.checks) if self.checks else 10
        for name, status, detail in self.checks:
            print(f"[{status}] {name.ljust(width)}  {detail}")
        print()
        print(f"门禁结果：{len(self.checks)} 项检查，{len(self.failures)} 项失败，{len(self.warnings)} 项警告")
        for f in self.failures:
            print(f"  FAIL {f}")
        for w in self.warnings:
            print(f"  WARN {w}")
        return 1 if self.failures else 0


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def source_tree_sha256(paths):
    h = hashlib.sha256()
    for rel in paths:
        full = os.path.join(REPO, rel)
        if not os.path.isfile(full):
            return None
        h.update(f"{sha256_file(full)}  {rel}\n".encode())
    return h.hexdigest()


def is_git_ignored(path):
    try:
        out = subprocess.run(["git", "-C", REPO, "check-ignore", "-q", path],
                             capture_output=True, text=True)
        return out.returncode == 0
    except Exception:
        return False


def _looks_text(path, probe=65536):
    """文本判定：按 UTF-8 增量解码，容忍探测边界截断的多字节字符。

    早期实现用 `chunk.decode("utf-8")`，只要 8192 字节边界正好切开一个中文字符就抛
    UnicodeDecodeError，于是中文为主的报告被判成"非文本"而**被卫生检查整份跳过**
    （2026-10-11 发现 0.3.0 审计报告里的本机绝对路径因此长期未被拦下）。
    """
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(probe)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        decoder.decode(chunk)
    except UnicodeDecodeError:
        return False
    return True


def _tracked_or_new_files():
    """已跟踪文件 + 未忽略的新文件（比扩展名白名单更接近「会被公开的内容」）。"""
    try:
        tracked = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True,
                                 check=True).stdout.splitlines()
    except Exception:
        tracked = []
    try:
        untracked = subprocess.run(["git", "-C", REPO, "ls-files", "--others", "--exclude-standard"],
                                   capture_output=True, text=True, check=True).stdout.splitlines()
    except Exception:
        untracked = []
    return [p for p in tracked + untracked if p.strip()]


def iter_text_files():
    for rel in _tracked_or_new_files():
        if not any(rel == r or rel.startswith(r.rstrip("/") + "/") for r in SCAN_ROOTS):
            continue
        path = os.path.join(REPO, rel)
        if os.path.isfile(path) and _looks_text(path):
            yield path


# ---------------------------------------------------------------- 各项检查
def check_structure(rep):
    problems = [f"缺少 {p}" for p in REQUIRED_PATHS if not os.path.exists(os.path.join(REPO, p))]
    for rel, suffix, least in REQUIRED_DIRS:
        path = os.path.join(REPO, rel)
        if not os.path.isdir(path):
            problems.append(f"缺少目录 {rel}")
            continue
        if suffix is None:
            continue
        count = len([n for n in os.listdir(path) if n.endswith(suffix)])
        if count < least:
            problems.append(f"{rel} 下 {suffix} 文件仅 {count} 个（至少 {least}）")
    rep.check("structure", not problems,
              "; ".join(problems) if problems
              else f"{len(REQUIRED_PATHS)} 个关键路径 + {len(REQUIRED_DIRS)} 个目录齐备")


def submodule_paths():
    """返回**顶层**子模块路径（`.gitmodules` 中不带 `/` 的 path）。

    嵌套子模块（如 `nomount/nomount`）的**父目录**是本仓库的真实项目目录（有自己的 Makefile，
    CI 会构建它），因此不能因为 `.gitmodules` 里出现了 `nomount/...` 就把 `nomount` 排除。
    只有本身是顶层 gitlink 的目录才在 CI 选择中被排除（见 DEV-038）。
    """
    gm = os.path.join(REPO, ".gitmodules")
    if not os.path.isfile(gm):
        return set()
    paths = set()
    for line in open(gm, encoding="utf-8", errors="replace"):
        if line.strip().startswith("path"):
            raw = line.split("=", 1)[1].strip()
            if "/" not in raw:
                paths.add(raw)
    return paths


def check_ci_markers(rep):
    """CI 只构建「有 Makefile 且未被 archive 标记」的顶层目录。

    规则（.github/workflows/build-kpm.yml）:
      * 没有 Makefile 的目录天然跳过——文档/工具/用户数据/子模块不需要任何标记文件；
      * 有 Makefile 但不想进 CI 的模块目录，放一个空的 `archive`。

    门禁核对工作流里确实有这两条规则，并把 CI 的选择结果列出来供人工确认。
    """
    workflow = os.path.join(REPO, ".github", "workflows", "build-kpm.yml")
    problems = []
    if not os.path.isfile(workflow):
        problems.append("缺少 .github/workflows/build-kpm.yml")
    else:
        text = open(workflow, encoding="utf-8", errors="replace").read()
        if "archive" not in text:
            problems.append("CI 工作流缺少 archive 跳过规则")
        if "Makefile" not in text:
            problems.append("CI 工作流缺少「无 Makefile 则跳过」规则")

    subs = submodule_paths()
    build, archived, skipped = [], [], []
    for name in sorted(os.listdir(REPO)):
        path = os.path.join(REPO, name)
        if not os.path.isdir(path) or name.startswith(".") or name in ("artifacts", "target", "local") or name in subs:
            continue
        if os.path.isfile(os.path.join(path, "archive")):
            archived.append(name)
        elif os.path.isfile(os.path.join(path, "Makefile")):
            build.append(name)
        else:
            skipped.append(name)
    detail = (f"CI 将构建 {len(build)} 个目录"
              + (f"（{', '.join(build)}）" if build else "")
              + f"；archive 跳过 {len(archived)} 个" + (f"（{', '.join(archived)}）" if archived else "")
              + f"；无 Makefile 跳过 {len(skipped)} 个")
    rep.check("ci_build_selection", not problems, "; ".join(problems) if problems else detail)


def check_doc_links(rep):
    broken, total = [], 0
    link_re = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    files = list(TOP_LEVEL_DOCS)
    for dirpath, dirs, names in os.walk(os.path.join(REPO, "docs")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            if name.endswith(".md"):
                files.append(os.path.relpath(os.path.join(dirpath, name), REPO))
    for rel in files:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            broken.append(f"{rel}（文件不存在）")
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for target in link_re.findall(text):
            target = target.strip()
            if not target or re.match(r"^[a-z]+:", target) or target.startswith("/"):
                continue
            total += 1
            # 文件名本身可能含 '#'（如 Tester 运行报告 `...#1.md`）：先按整串找，再按片段剥离
            candidates = [target]
            if "#" in target:
                candidates.append(target.split("#")[0])
            if not any(os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), c)))
                       for c in candidates if c):
                broken.append(f"{rel} -> {target}")
    rep.check("doc_links", not broken, "; ".join(broken) if broken else f"{total} 个相对链接全部可解析")


def check_metadata_schema(rep):
    problems = []
    identity_path = os.path.join(REPO, "metadata", "identity.json")
    try:
        identity = json.load(open(identity_path, encoding="utf-8"))
    except Exception as exc:
        rep.check("metadata_schema", False, f"metadata/identity.json 解析失败: {exc}")
        return
    for key in ("process", "process_version", "gate", "ownership", "paths", "conventions"):
        if key not in identity:
            problems.append(f"identity.json 缺字段 {key}")
    for key, rel in identity.get("docs", {}).items():
        if not os.path.exists(os.path.join(REPO, rel)):
            problems.append(f"identity.json docs.{key} 指向不存在的文件 {rel}")

    modules_dir = os.path.join(REPO, "metadata", "modules")
    module_files = [f for f in sorted(os.listdir(modules_dir)) if f.endswith(".json")] if os.path.isdir(modules_dir) else []
    severities = set(identity.get("conventions", {}).get("severities", []))
    statuses = set(identity.get("conventions", {}).get("issue_statuses", []))
    owners = set(identity.get("conventions", {}).get("issue_owners", []))
    prefixes = tuple(identity.get("conventions", {}).get("issue_prefixes", []))
    frequencies = set(identity.get("conventions", {}).get("issue_frequencies", []))
    confidences = set(identity.get("conventions", {}).get("issue_confidences", []))
    issue_classes = set(identity.get("conventions", {}).get("issue_classes", []))
    seen_ids = set()
    for name in module_files:
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for key in ("module", "status", "version_declared", "version_sources", "builds", "issues"):
            if key not in record:
                problems.append(f"{name} 缺字段 {key}")
        for build in record.get("builds", []):
            for key in ("build_id", "instance_id", "source_commit", "source_tree_sha256",
                        "fingerprint_sha256", "toolchain", "kernelpatch_commit", "recipe",
                        "sources", "artifacts"):
                if key not in build:
                    problems.append(f"{name}:{build.get('build_id')} 缺字段 {key}")
            for art in build.get("artifacts", []):
                if not re.fullmatch(r"[0-9a-f]{64}", art.get("sha256", "")):
                    problems.append(f"{name}:{build.get('build_id')} 产物 {art.get('name')} 的 sha256 不合法")
        for issue in record.get("issues", []):
            for key in ("id", "severity", "owner", "status", "title", "evidence"):
                if key not in issue:
                    problems.append(f"{name}:{issue.get('id')} 缺字段 {key}")
            if issue.get("status") == "closed":
                if not (issue.get("resolution") or issue.get("closure")):
                    problems.append(f"{name}:{issue.get('id')} 已 closed 但既无 resolution 也无 closure")
            elif "closure" not in issue:
                problems.append(f"{name}:{issue.get('id')} 未关闭却缺 closure（关闭条件）")
            if issue.get("severity") not in severities:
                problems.append(f"{name}:{issue.get('id')} 严重度非法 {issue.get('severity')}")
            if issue.get("status") not in statuses:
                problems.append(f"{name}:{issue.get('id')} 状态非法 {issue.get('status')}")
            if issue.get("owner") not in owners:
                problems.append(f"{name}:{issue.get('id')} 归属非法 {issue.get('owner')}")
            if prefixes and not str(issue.get("id", "")).startswith(prefixes):
                problems.append(f"{name}:{issue.get('id')} 编号前缀非法")
            if issue.get("id") in seen_ids:
                problems.append(f"{name}:{issue.get('id')} 编号重复")
            seen_ids.add(issue.get("id"))
            if issue.get("status") == "closed":
                if not issue.get("closed_by"):
                    problems.append(f"{name}:{issue.get('id')} 已 closed 但缺 closed_by")
                elif issue.get("closed_by") == issue.get("owner"):
                    problems.append(f"{name}:{issue.get('id')} 由归属方自己关闭（需独立复核者）")
            if issue.get("frequency") and issue["frequency"] not in frequencies:
                problems.append(f"{name}:{issue.get('id')} frequency 非法 {issue['frequency']}")
            if issue.get("confidence") and issue["confidence"] not in confidences:
                problems.append(f"{name}:{issue.get('id')} confidence 非法 {issue['confidence']}")
            if issue.get("class") and issue_classes and issue["class"] not in issue_classes:
                problems.append(f"{name}:{issue.get('id')} 类别非法 {issue['class']}")
            if issue.get("status") == "closed" and issue.get("class") == "record" and not issue.get("reviews"):
                problems.append(f"{name}:{issue.get('id')} record 类已关闭但缺少一次独立确认记录（reviews[]）")
        # 实机复测必须绑定在册字节（把"身份绑定"做成事实判据，而不是查报告文风）
        artifacts_of = {b.get("instance_id"): {a.get("name"): a.get("sha256") for a in b.get("artifacts", [])}
                        for b in record.get("builds", [])}
        for test in record.get("device_tests", []) or []:
            if "retest" not in str(test.get("kind", "")):
                continue
            iid = test.get("instance_id")
            tested = test.get("tested_bytes") or {}
            if iid not in artifacts_of:
                problems.append(f"{name}: 复测条目指向不存在的实例 {iid}")
            elif tested.get("in_registry_match") is not True or tested.get("registered") is not True:
                problems.append(f"{name}: 复测条目 {iid} 未声明 tested_bytes 与在册字节一致")
            else:
                # 允许两种绑定：① 实例自身的产物字节；② 由该实例派生的二进制变换件（binary_ports，含 base 绑定）
                allowed = set(artifacts_of[iid].values())
                allowed |= {port.get("derived", {}).get("sha256") for port in record.get("binary_ports", []) or []
                            if port.get("base_instance_id") == iid}
                if tested.get("sha256") not in allowed:
                    problems.append(f"{name}: 复测条目 {iid} 的实测哈希 {str(tested.get('sha256'))[:12]} "
                                    "既不是该实例产物，也不是其登记的派生件")
    token_problems, tokens = identity_token_problems()
    problems.extend(token_problems)
    detail = "; ".join(problems) if problems else \
        f"{len(module_files)} 个模块记录结构合法，{tokens} 个结构化提交标识可解析"
    rep.check("metadata_schema", not problems, detail)


def load_module_from(relpath, name):
    """从本文件所在目录加载维护者工具模块（不受 REPO 夹具影响）。"""
    import importlib.util
    path = os.path.join(HERE, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_identity_module():
    """复用维护者工具里的核验实现（避免门禁与工具各写一套哈希逻辑）。"""
    return load_module_from("identity.py", "dsh_identity")


def check_identity_hashes(rep, strict):
    modules_dir = os.path.join(REPO, "metadata", "modules")
    if not os.path.isdir(modules_dir):
        rep.check("identity_hashes", False, "metadata/modules 不存在")
        return
    try:
        ident = load_identity_module()
    except Exception as exc:
        rep.check("identity_hashes", False, f"无法加载 tools/identity.py: {exc}")
        return
    mismatches, missing, retained_gaps, verified, instances = [], [], [], 0, set()
    for name in sorted(os.listdir(modules_dir)):
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for build in record.get("builds", []):
            iid = build.get("instance_id")
            if iid in instances:
                mismatches.append(f"instance_id 重复: {iid}")
            instances.add(iid)
            # `artifact_state=not-retained`：产物由负责人**有意不保留**（已登记原因），
            # 只列出告警，不作为完整性失败；未登记该状态的缺失仍判失败。
            not_retained = build.get("artifact_state") == "not-retained"
            profile = ("exploration" if not_retained
                       else "candidate" if strict and build.get("kind") != "exploration" else "exploration")
            result = ident.verify_build(build, profile=profile)
            for problem in result["problems"]:
                if problem.startswith("产物不在场"):
                    if not_retained:
                        retained_gaps.append(f"{iid}: {problem}")
                    else:
                        missing.append(f"{iid}: {problem}")
                else:
                    mismatches.append(f"{iid}: {problem}")
            verified += result.get("artifacts_verified", 0)
    detail = f"{len(record.get('builds', []))} 条构建记录 / 复算 {verified} 份产物"
    if mismatches:
        detail += "；" + "; ".join(mismatches[:3])
    if missing:
        detail += "；" + "; ".join(missing[:3])
    if retained_gaps:
        detail += f"；有意不保留 {len(retained_gaps)} 份（已登记 artifact_state）: " + "; ".join(retained_gaps[:2])
    if mismatches:
        rep.check("identity_hashes", False, detail)
    elif missing:
        rep.check("identity_hashes", False, detail, warn_only=not strict)
    elif retained_gaps:
        rep.check("identity_hashes", True, detail, warn_only=True)
    else:
        rep.check("identity_hashes", True, detail)


def normalize_version(text):
    return re.sub(r"_(n|d|nd|network|debug|network_debug)$", "", (text or "").strip())


def historical_runtime_name(build, module):
    """从历史构建绑定的提交读取注册名；读取失败或声明歧义均拒绝。"""
    commit = build.get("source_commit", "")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("历史构建缺少完整源码提交")
    names = []
    for source in build.get("sources", []):
        path = source.get("path", "")
        if not path.startswith(module + "/") or not path.endswith(".c"):
            continue
        result = subprocess.run(["git", "-C", REPO, "show", f"{commit}:{path}"],
                                capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"历史源码不可读取：{path}")
        names.extend(re.findall(r'^\s*KPM_NAME\s*\(\s*"([^"\n]+)"\s*\)\s*;',
                                result.stdout, re.M))
    if len(names) != 1:
        raise ValueError("历史源码必须有唯一的 KPM_NAME 字面量声明")
    return names[0]


def version_key(value):
    """版本号比较键：数字段按数值，其余按字典序，段数不同可比较。"""
    parts = []
    for chunk in re.split(r"[._-]", str(value)):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return parts


def build_versions_of(record):
    return {normalize_version(b.get("version") or "") for b in record.get("builds", [])} - {""}


def check_version_consistency(rep):
    """版本一致性：当前源码自洽 + 每条历史构建与**它自己的**版本核对。

    历史产物不参与「当前版本」比较（否则「保留历史」与「升级版本」必然冲突）；
    当前源码版本若还没有构建记录，只提示，不算失败。
    """
    modules_dir = os.path.join(REPO, "metadata", "modules")
    problems, notes = [], []
    if not os.path.isdir(modules_dir):
        rep.check("version_consistency", False, "metadata/modules 不存在")
        return
    for name in sorted(os.listdir(modules_dir)):
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        module = record["module"]
        archived = record.get("status") == "archived"
        if archived:
            successor = record.get("superseded_by", "")
            if os.path.lexists(os.path.join(REPO, module)):
                problems.append(f"{module}: 已归档模块的源码目录仍在工作树中")
            if (not re.fullmatch(r"[A-Za-z0-9_-]+", successor)
                    or successor == module
                    or not os.path.isfile(os.path.join(modules_dir, successor + ".json"))
                    or not os.path.isfile(os.path.join(REPO, successor, "Makefile"))):
                problems.append(f"{module}: 已归档模块缺少有效的现行替代模块")
        declared = normalize_version(record.get("version_declared", ""))
        makefile = os.path.join(REPO, module, "Makefile")
        source_versions = set()
        if os.path.isfile(makefile):
            m = re.search(r"^\s*MYKPM_VERSION\s*:?=\s*(\S+)", open(makefile, encoding="utf-8", errors="replace").read(), re.M)
            if not m:
                problems.append(f"{module}: Makefile 未找到 MYKPM_VERSION")
            else:
                source_versions.add(normalize_version(m.group(1)))
                if normalize_version(m.group(1)) != declared:
                    # 「元数据滞后于源码」是交接前的正常在途状态（声明字段由维护者同步），按提示处理；
                    # 「元数据高于源码」或该版本已有构建记录，就是事实矛盾，仍然失败。
                    lag = (version_key(m.group(1)) > version_key(declared)
                           and normalize_version(m.group(1)) not in build_versions_of(record))
                    text = (f"{module}: Makefile 版本 {m.group(1)} != 元数据 {declared}")
                    if lag and not source_versions.intersection(build_versions_of(record)):
                        notes.append(text + "（交接前在途：维护者需在验收/交付前同步 version_declared；角色不要自行改元数据）")
                    else:
                        problems.append(text)
        readme_heading = normalize_version(record.get("version_sources", {}).get("readme_heading", ""))
        if readme_heading and readme_heading != declared:
            # 文档标题属提示：版本事实由 Makefile ↔ version_declared 判定，不用文档措辞卡人
            notes.append(f"{module}: README 最新条目 {readme_heading} != 元数据 {declared}（文档层面提示）")

        build_versions = set()
        for build in record.get("builds", []):
            expected_name = module
            if archived:
                try:
                    expected_name = historical_runtime_name(build, module)
                except (OSError, ValueError, UnicodeError) as exc:
                    problems.append(f"{module}: {exc}")
                    expected_name = None
            bver = normalize_version(build.get("version") or "")
            if bver:
                build_versions.add(bver)
            for art in build.get("artifacts", []):
                embedded = normalize_version(art.get("embedded", {}).get("version", ""))
                # 与该构建自己的版本核对（缺 version 的历史条目退回当前声明）
                expected = bver or declared
                if embedded and expected and embedded != expected:
                    problems.append(f"{module}: 产物 {art['name']} 内嵌版本 {embedded} != 该构建版本 {expected}"
                                    f"（instance {build.get('instance_id')}）")
                embedded_name = art.get("embedded", {}).get("name", module)
                if expected_name is not None and (embedded_name != expected_name if archived
                                                 else embedded_name.casefold() != expected_name.casefold()):
                    problems.append(f"{module}: 产物 {art['name']} 内嵌 name={embedded_name}"
                                    f" != {'冻结源码注册名' if archived else '模块名'} {expected_name}")
        if record.get("builds") and declared and declared not in build_versions:
            notes.append(f"{module}: 当前源码版本 {declared} 还没有构建记录"
                         f"（已有：{', '.join(sorted(build_versions)) or '无'}）")
    detail = "; ".join(problems) if problems else "当前源码自洽；历史产物按各自构建版本核对"
    if notes and not problems:
        detail += "；" + "；".join(notes)
    rep.check("version_consistency", not problems, detail)


def check_acceptance(rep):
    """验收结论必须绑定具体实例：instance_id + source_commit + fingerprint + 产物哈希。"""
    modules_dir = os.path.join(REPO, "metadata", "modules")
    problems, checked = [], 0
    for name in sorted(os.listdir(modules_dir)) if os.path.isdir(modules_dir) else []:
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for acceptance in load_identity_module().acceptance_records(record):
            checked += 1
            for key in ("instance_id", "source_commit", "fingerprint_sha256", "artifacts",
                        "accepted_by", "accepted_at"):
                if key not in acceptance:
                    problems.append(f"{name}: acceptance 缺字段 {key}")
            entry = next((b for b in record.get("builds", [])
                          if b.get("instance_id") == acceptance.get("instance_id")), None)
            if entry is None:
                problems.append(f"{name}: acceptance 指向的实例不存在 {acceptance.get('instance_id')}")
                continue
            if entry.get("fingerprint_sha256") != acceptance.get("fingerprint_sha256"):
                problems.append(f"{name}: acceptance 的指纹与实例不一致")
            if entry.get("source_commit") != acceptance.get("source_commit"):
                problems.append(f"{name}: acceptance 的 source_commit 与实例不一致")
            if {a["name"]: a["sha256"] for a in entry.get("artifacts", [])} != acceptance.get("artifacts", {}):
                problems.append(f"{name}: acceptance 的产物哈希与实例不一致")
            if entry.get("kind") == "exploration":
                problems.append(f"{name}: 探索记录（exploration）不能被验收")
    if checked == 0:
        rep.check("acceptance_pending", True, "尚无验收记录（未验收不阻塞门禁）", warn_only=True)
    else:
        rep.check("acceptance_binding", not problems,
                  "; ".join(problems) if problems else f"{checked} 条验收记录绑定具体实例")


def check_tool_selftest(rep):
    """把历轮发现过的判据漂移做成常驻回归：自检失败即门禁失败。"""
    try:
        selftest = load_module_from("selftest_tools.py", "dsh_selftest")   # HERE 就是 tools/
        results = selftest.run_checks()
    except Exception as exc:
        rep.check("tool_selftest", False, f"自检无法运行: {exc}")
        return
    failed = [(name, detail) for name, ok, detail in results if not ok]
    rep.check("tool_selftest", not failed,
              "; ".join(f"{n}: {d}" for n, d in failed) if failed
              else f"{len(results)} 项工具判据回归通过")


def check_delivery_binding(rep):
    """交付绑定必须绑定实例与签名提交；不一致直接失败，尚未交付只提示。"""
    modules_dir = os.path.join(REPO, "metadata", "modules")
    if not os.path.isdir(modules_dir):
        rep.check("delivery_binding", False, "metadata/modules 不存在")
        return
    try:
        ident = load_identity_module()
    except Exception as exc:
        rep.check("delivery_binding", False, f"无法加载 tools/identity.py: {exc}")
        return
    problems, checked = [], 0
    for name in sorted(os.listdir(modules_dir)):
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for binding in record.get("deliveries", []):
            checked += 1
            for key in ("instance_id", "fingerprint_sha256", "source_commit", "delivery_commit",
                        "artifacts", "signature_verified", "bound_by", "bound_at"):
                if key not in binding:
                    problems.append(f"{name}: 交付绑定缺字段 {key}")
            entry = next((b for b in record.get("builds", [])
                          if b.get("instance_id") == binding.get("instance_id")), None)
            if entry is None:
                problems.append(f"{name}: 交付绑定指向不存在的实例 {binding.get('instance_id')}")
            else:
                problems.extend(f"{name}: {p}" for p in ident.delivery_problems(entry, binding))
    if checked == 0:
        rep.check("delivery_pending", True, "尚无交付绑定（未交付不阻塞门禁）", warn_only=True)
    else:
        rep.check("delivery_binding", not problems,
                  "; ".join(problems) if problems else f"{checked} 条交付绑定校验通过")


def check_developer_artifacts(rep):
    """交接清单字段校验（机检事实；报告文风不在门禁职责内）。"""
    problems, checked = [], 0
    handoffs = os.path.join(REPO, "Developer", "reports", "handoffs")
    if os.path.isdir(handoffs):
        for name in sorted(os.listdir(handoffs)):
            if not name.endswith(".json"):
                continue
            checked += 1
            try:
                payload = json.load(open(os.path.join(handoffs, name), encoding="utf-8"))
                # 交接清单必须带 payload：候选清单用 builds[]，只交派生件的清单用 binary_ports[]。
                missing = [key for key in ("module", "handoff_by", "handoff_at") if key not in payload]
                if not (payload.get("builds") or payload.get("binary_ports")):
                    missing.append("builds 或 binary_ports")
                for key in missing:
                    problems.append(f"Developer/reports/handoffs/{name} 缺字段 {key}")
            except Exception as exc:
                problems.append(f"Developer/reports/handoffs/{name} 解析失败: {exc}")
    rep.check("developer_artifacts", not problems,
              "; ".join(problems) if problems else (f"{checked} 份交接清单格式合法" if checked else "暂无交接清单"),
              warn_only=True)


def _handoff_target(record):
    """交接记录里的目标标识：新形态是对象，旧形态是字符串。"""
    target = record.get("target")
    if isinstance(target, dict):
        return target.get("target") or target.get("name") or "?"
    return target or "?"


def check_handoff_registration(rep):
    """交接清单的每条记录都应已在模块元数据登记（软判据）。

    防两类漏登记：整份交接未导入；同一份派生字节服务多个目标时按 sha 去重误删目标身份。
    探索类交接（`*exploration*`）与无元数据的模块不在此判据范围内——前者按约定不入候选登记。
    """
    problems, checked = [], 0
    handoffs = os.path.join(REPO, "Developer", "reports", "handoffs")
    if os.path.isdir(handoffs):
        for name in sorted(os.listdir(handoffs)):
            if not name.endswith(".json") or "exploration" in name:
                continue
            try:
                payload = json.load(open(os.path.join(handoffs, name), encoding="utf-8"))
            except Exception:
                continue  # 解析失败由 developer_artifacts 报出
            module = payload.get("module")
            meta_path = os.path.join(REPO, "metadata", "modules", f"{module}.json") if module else None
            if not meta_path or not os.path.isfile(meta_path):
                continue
            meta = json.load(open(meta_path, encoding="utf-8"))
            instances = {b.get("instance_id") for b in meta.get("builds", [])}
            ports = {(p.get("derived", {}).get("sha256"), _handoff_target(p))
                     for p in meta.get("binary_ports", [])}
            fallback_target = _handoff_target(payload)  # 旧形态：目标写在清单顶层
            for build in payload.get("builds") or []:
                checked += 1
                if build.get("instance_id") not in instances:
                    problems.append(f"{name}: 实例未登记 {build.get('instance_id')}")
            for port in payload.get("binary_ports") or []:
                checked += 1
                sha = port.get("derived", {}).get("sha256")
                target = _handoff_target(port)
                if target == "?":
                    target = fallback_target
                if (sha, target) not in ports:
                    problems.append(f"{name}: 派生记录未登记 {str(sha)[:12]} @ {target}")
    rep.check("handoff_registration", not problems,
              "; ".join(problems) if problems else f"{checked} 条交接记录均已登记",
              warn_only=True)


def check_auditor_independence(rep):
    """审计工具不得把实现方/维护方工具当作结论来源（代码级检查，注释与文档字符串不算）。"""
    tools_dir = os.path.join(REPO, "Auditor", "tools")
    problems = []
    forbidden_imports = {"identity", "tools", "offset_harness", "run"}
    forbidden_paths = ("tools/identity.py", "offset_harness", "kernel_img/offset_harness")
    for name in sorted(os.listdir(tools_dir)) if os.path.isdir(tools_dir) else []:
        if not name.endswith(".py"):
            continue
        source = open(os.path.join(tools_dir, name), encoding="utf-8", errors="replace").read()
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            problems.append(f"Auditor/tools/{name} 解析失败: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_imports:
                        problems.append(f"Auditor/tools/{name} 导入了 {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in forbidden_imports:
                    problems.append(f"Auditor/tools/{name} 从 {node.module} 导入")
            elif isinstance(node, ast.Call):
                func = node.func
                fname = getattr(func, "attr", "") or getattr(func, "id", "")
                if fname not in ("run", "check_output", "call", "system", "popen", "Popen", "execv", "execvp"):
                    continue
                literals = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                joined = " ".join(literals)
                for bad in forbidden_paths:
                    if bad in joined:
                        problems.append(f"Auditor/tools/{name} 在执行调用里使用了 {bad}")
    rep.check("auditor_independence", not problems,
              "; ".join(problems) if problems else "审计工具不依赖实现方/维护方工具")


COMMIT_FIELD_NAMES = {
    "source_commit", "kernelpatch_commit", "commit", "delivery_commit", "archive_commit",
    "fix_commit", "archived_commit", "base_commit", "audited_commit", "build_commit",
}
SUBMODULE_COMMIT_FIELDS = {"kernelpatch_commit"}
REFERENCE_FIELDS = ("report", "record", "response", "data", "manifest", "handoff_manifest", "report_support")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def structured_items(node, path="", key=None):
    """遍历元数据结构，产出 (字段路径, 字段名, 标量值)。列表元素继承父字段名。"""
    if isinstance(node, dict):
        for child_key, value in node.items():
            child_path = f"{path}.{child_key}" if path else child_key
            yield from structured_items(value, child_path, child_key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from structured_items(value, f"{path}[{index}]", key)
    else:
        yield path, key, node


def resolve_commits(values, submodule=False):
    """批量核验提交标识（一次 cat-file --batch-check），避免逐条起子进程。"""
    values = list(dict.fromkeys(values))
    if not values:
        return set()
    cwd = os.path.join(REPO, "KernelPatch") if submodule else REPO
    result = subprocess.run(["git", "-C", cwd, "cat-file", "--batch-check"],
                            input=("\n".join(values) + "\n").encode(), capture_output=True)
    ok = set()
    for line in result.stdout.decode(errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "commit":
            ok.add(fields[0])
    return ok


def resolve_commit(value, submodule=False):
    return value in resolve_commits([value], submodule=submodule)


def commit_blob(commit, relpath):
    result = subprocess.run(["git", "-C", REPO, "show", f"{commit}:{relpath}"], capture_output=True)
    return result.stdout if result.returncode == 0 else None


def repo_file(relpath):
    return os.path.join(REPO, relpath)


def identity_token_problems():
    """G1：结构化提交字段必须可解析，杜绝转录笔误被引用成结论。"""
    modules_dir = os.path.join(REPO, "metadata", "modules")
    problems, checked = [], 0
    local, submodule = [], []
    for name in sorted(os.listdir(modules_dir)) if os.path.isdir(modules_dir) else []:
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for field, key, value in structured_items(record):
            if key not in COMMIT_FIELD_NAMES or not isinstance(value, str):
                continue
            if not re.fullmatch(r"[0-9a-f]{7,40}", value):
                problems.append(f"{name}:{field} 不是提交标识 {value!r}")
                continue
            checked += 1
            (submodule if key in SUBMODULE_COMMIT_FIELDS else local).append((name, field, value))
    for key_set, is_sub in ((local, False), (submodule, True)):
        resolved = resolve_commits([value for _, _, value in key_set], submodule=is_sub)
        where = "KernelPatch 子模块" if is_sub else "本仓库"
        problems.extend(f"{name}:{field} 在{where}中不可解析 {value}"
                        for name, field, value in key_set if value not in resolved)
    return problems, checked


def tracked_and_dirty():
    """一次性取全仓已跟踪文件集合与有改动的路径集合。"""
    listed = subprocess.run(["git", "-C", REPO, "ls-files", "-z"], capture_output=True)
    tracked = {p for p in listed.stdout.decode(errors="replace").split("\0") if p}
    status = subprocess.run(["git", "-C", REPO, "status", "--porcelain", "-z"], capture_output=True)
    fields = [f for f in status.stdout.decode(errors="replace").split("\0") if f]
    dirty = set()
    for field in fields:
        path = field[3:] if len(field) > 3 else field
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        dirty.add(path)
    return tracked, dirty


def referenced_paths(record):
    """收集元数据里**报告类**引用路径（排除运行期归档目录）。

    只认显式的报告/记录字段（`report`/`record`/`response`/`data`/`manifest`…）与 `blobs` 映射。
    裸 `path` 不收集：`builds[].sources[].path` 是构建输入（按其冻结提交核验，见 identity.py），
    `builds[].artifacts[].path` 是运行期归档；历史构建的输入路径允许在后续提交中被移动/删除，
    子模块内输入也不在父仓库索引中——把它们当「未入库报告」会误报。
    """
    found = set()
    for _, key, value in structured_items(record):
        if isinstance(value, str) and key in REFERENCE_FIELDS:
            if value.endswith((".md", ".json", ".txt")) and not value.startswith("http"):
                found.add(value)
    for item in record.get("report_versions", []) or []:
        if item.get("path"):
            found.add(item["path"])
    for mr in record.get("maintainer_records", []) or []:
        for path in (mr.get("blobs") or {}):
            found.add(path)
    return {p for p in found if not p.startswith(("artifacts/", "local/", "/"))}


def report_binding_hashes(record, path):
    """收集绑定到某报告字节身份的哈希：字段与路径**精确配对**，避免互相误判。"""
    pairs = {"report": ("report_sha256", "archived_report_sha256"),
             "response": ("report_sha256", "archived_report_sha256"),
             "data": ("data_sha256",)}
    hashes = set()
    stack = [record]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "append_only_baseline" in node or "unarchived_versions" in node:
                continue
            for field, keys in pairs.items():
                if node.get(field) != path:
                    continue
                for key in keys:
                    value = node.get(key)
                    if isinstance(value, str) and HASH_RE.match(value):
                        hashes.add(value)
            blobs = node.get("blobs")
            if isinstance(blobs, dict) and path in blobs and HASH_RE.match(str(blobs[path])):
                hashes.add(blobs[path])
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))
    return hashes


def check_report_integrity(rep, strict):
    """报告与记录的身份完整性（一次遍历，合并原四条判据）。

    硬判据（两种模式都失败）：版本索引最新版＝工作树字节、原文只追加、追加段哈希吻合、
    版本引用可解析、索引哈希属已知版本（软）；`unarchived_versions[]` 说明与历史缺提交同属软判据
    （常规提示、严格失败）；字节改写、追加链与非登记索引哈希为硬判据（两种模式都失败）。
    软判据（常规提示、验收/交付失败）：被引用报告必须已入库且与工作树一致。
    """
    modules_dir = os.path.join(REPO, "metadata", "modules")
    problems, soft, uncovered, reports, versions = [], [], [], 0, 0
    tracked, dirty = tracked_and_dirty()
    for name in sorted(os.listdir(modules_dir)) if os.path.isdir(modules_dir) else []:
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        items = record.get("report_versions")
        if not items and "report_versions" not in record:
            uncovered.append(name[:-5])
        for item in items or []:
            path = item.get("path") or ""
            full = repo_file(path)
            if not os.path.isfile(full):
                problems.append(f"{name}: 报告版本索引路径不存在 {path}")
                continue
            reports += 1
            current = open(full, "rb").read()
            current_sha = hashlib.sha256(current).hexdigest()
            base = item.get("append_only_baseline") or {}
            chain = ([base] if base else []) + (item.get("versions") or [])
            unarchived = item.get("unarchived_versions") or []
            if not chain:
                problems.append(f"{name}: {path} 没有任何登记版本")
                continue
            if chain[-1].get("sha256") != current_sha:
                problems.append(f"{name}: {path} 最新登记版本 {str(chain[-1].get('sha256'))[:12]} 与工作树 "
                                f"{current_sha[:12]} 不一致（追加未登记或字节被改写）")
            known = set()
            for version in chain + unarchived:
                sha = version.get("sha256")
                if sha:
                    known.add(sha)
                commit = version.get("commit")
                if commit:
                    versions += 1
                    if not resolve_commit(commit):
                        problems.append(f"{name}: {path} 版本引用的提交不可解析 {commit}")
                    else:
                        blob = commit_blob(commit, path)
                        if blob is None:
                            problems.append(f"{name}: {path} 版本引用的提交不可读 {commit}")
                        elif hashlib.sha256(blob).hexdigest() != sha:
                            problems.append(f"{name}: {path} 版本 {str(sha)[:12]} 与提交 {commit[:7]} 的 blob 不一致")
                elif version is not chain[-1]:
                    soft.append(f"{name}:{path} 历史版本 {str(sha)[:12]} 未引用提交（交接即提交未落实）")
                elif not version.get("pending_commit"):
                    soft.append(f"{name}:{path} 当前版本 {str(sha)[:12]} 未提交且未标 pending_commit")
            for version in unarchived:
                if not version.get("note"):
                    soft.append(f"{name}:{path} unarchived_versions 中的 "
                                f"{str(version.get('sha256'))[:12]} 缺少 note 说明")
            if base and base.get("commit"):
                base_bytes = commit_blob(base["commit"], path)
                if base_bytes is not None:
                    if current[:len(base_bytes)] != base_bytes:
                        problems.append(f"{name}: {path} 现行字节不是入库原文的前缀（原文被改写）")
                    else:
                        prev = base_bytes
                        chain_versions = item.get("versions") or []
                        for index, version in enumerate(chain_versions):
                            is_current = index == len(chain_versions) - 1
                            if version.get("commit"):
                                blob = commit_blob(version["commit"], path)
                                if blob is None:
                                    soft.append(f"{name}:{path} 第 {index + 1} 段提交不可读"
                                                f"（{str(version['commit'])[:7]}，历史缺项）")
                                    break
                            elif is_current:
                                blob = current          # 只有当前待提交版本才允许用工作树字节
                            else:
                                # 历史段缺提交：若登记的整份哈希与已知边界一致，说明该段未引入新字节，
                                # 边界仍可继续推导，后续段的追加哈希必须照查（DEV-032 组合反例）；
                                # 否则不猜追加内容，停止复算。
                                recorded = str(version.get("sha256") or "")
                                if recorded and hashlib.sha256(prev).hexdigest() == recorded:
                                    soft.append(f"{name}:{path} 第 {index + 1} 段缺提交"
                                                f"（历史缺项；登记哈希与已知边界一致，继续复核后续段）")
                                    continue
                                soft.append(f"{name}:{path} 第 {index + 1} 段缺提交且边界不可确定，"
                                            f"后续追加段不可复算（历史缺项）")
                                break
                            if not blob.startswith(prev):
                                problems.append(f"{name}: {path} 第 {index + 1} 段追加不是纯追加或不可复算")
                                break
                            suffix = blob[len(prev):]
                            if version.get("added_sha256") and \
                                    hashlib.sha256(suffix).hexdigest() != version["added_sha256"]:
                                problems.append(f"{name}: {path} 第 {index + 1} 段追加哈希与登记不符")
                            prev = blob
            for bound in report_binding_hashes(record, path):
                if bound not in known:
                    problems.append(f"{name}: {path} 索引哈希 {bound[:12]} 不在报告版本表中")
        for path in sorted(referenced_paths(record)):
            if not os.path.isfile(repo_file(path)):
                soft.append(f"{name}:{path}（不存在）")
            elif path not in tracked:
                soft.append(f"{name}:{path}（未入库）")
            elif path in dirty:
                soft.append(f"{name}:{path}（入库后已修改，未提交）")
    # 新表示的引用必须完整；展开后由原导入入口核验全部身份，不允许悬空引用蒙混过关。
    for directory in ("Developer/reports/handoffs", "metadata/handoffs"):
        full = os.path.join(REPO, directory)
        if not os.path.isdir(full):
            continue
        ident = None
        for name in sorted(os.listdir(full)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(full, name), encoding="utf-8") as stream:
                    payload = json.load(stream)
                if isinstance(payload, dict) and ("handoff_schema" in payload or "shared_data" in payload):
                    ident = ident or load_identity_module()
                    ident.expand_handoff(payload)
            except (ValueError, TypeError) as exc:
                # 旧格式 JSON 语法错误仍由既有清单检查负责。
                if not isinstance(exc, json.JSONDecodeError):
                    problems.append(f"{directory}/{name}: 共享输入校验失败: {exc}")
    hard_ok = not problems
    soft_note = "; ".join(soft)
    detail = "; ".join(problems) if problems else (
        f"{reports} 份报告字节身份一致（原文只追加、追加已登记，{versions} 个版本引用提交）"
        + (f"；引用未归档：{soft_note}" if soft else "；被引用路径均已入库且与工作树一致"))
    if uncovered:
        detail += f"；{len(uncovered)} 个历史模块记录未纳入报告版本索引（保持原形态）：{', '.join(uncovered)}"
    # 软判据（引用未归档/版本未引用提交）：常规模式提示，验收与交付模式失败
    rep.check("report_integrity", hard_ok and not soft, detail,
              warn_only=(not strict) and hard_ok and bool(soft))


def check_hygiene(rep):
    problems = []
    for path in iter_text_files():
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, 1):
            for pattern, why in HYGIENE_PATTERNS:
                if pattern.search(line):
                    problems.append(f"{os.path.relpath(path, REPO)}:{lineno} {why}")
    rep.check("public_file_hygiene", not problems, "; ".join(problems) if problems else "未发现本机路径/密钥/序列号明文")


def main():
    ap = argparse.ArgumentParser(description="仓库门禁")
    ap.add_argument("--strict", action="store_true", help="产物必须在场且哈希可复算")
    args = ap.parse_args()

    os.chdir(REPO)
    rep = Report()
    check_structure(rep)
    check_ci_markers(rep)
    check_doc_links(rep)
    check_metadata_schema(rep)
    check_report_integrity(rep, args.strict)
    check_identity_hashes(rep, args.strict)
    check_version_consistency(rep)
    check_acceptance(rep)
    check_delivery_binding(rep)
    check_tool_selftest(rep)
    check_developer_artifacts(rep)
    check_handoff_registration(rep)
    check_auditor_independence(rep)
    check_hygiene(rep)
    print(f"门禁模式：{'strict（验收/发布）' if args.strict else 'regular'}")
    print()
    return rep.summary()


if __name__ == "__main__":
    sys.exit(main())
