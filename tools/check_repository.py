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
    "AGENTS.md",
    "docs/README.md",
    "docs/coverage.md",
    "docs/process/01-identity.md",
    "docs/process/02-roles.md",
    "docs/process/03-round-flow.md",
    "docs/process/04-issue-ticket.md",
    "docs/process/05-maintainer-acceptance.md",
    "docs/process/06-antipatterns.md",
    "docs/process/07-escalation-device.md",
    "docs/process/developer-handbook.md",
    "docs/process/auditor-handbook.md",
    "docs/process/tester-handbook.md",
    "docs/templates/developer-report.md",
    "docs/templates/auditor-report.md",
    "docs/templates/tester-report.md",
    "docs/templates/issue-ticket.md",
    "docs/templates/escalation.md",
    "docs/templates/handoff.md",
    "metadata/README.md",
    "metadata/identity.json",
    "tools/identity.py",
    "tools/build_candidate.py",
    "tools/selftest_tools.py",
    "tools/freeze_check.py",
    "tools/check_repository.py",
    "kernel_img/README.md",
    "kernel_img/offset_harness/README.md",
    "kernel_img/offset_harness/run.py",
    "kernel_img/offset_harness/extract_kernel.py",
    "kernel_img/offset_harness/bootimg.py",
    "kernel_img/offset_harness/layout.py",
    ".github/workflows/build-kpm.yml",
    "tools/artifact_gate.py",
    "tools/selftest_artifact_gate.py",
    "Auditor/README.md",
    "Auditor/tools/artifact_audit.py",
    "Auditor/tools/static_scan.py",
    "Auditor/tools/kp_symbols_extract.py",
    "Auditor/reports/README.md",
    "Tester/README.md",
    "Tester/tools/preflight.sh",
    "Tester/tools/run_test.sh",
    "Tester/tools/selftest_scripts.sh",
    "Tester/tools/mock_device.sh",
    "Tester/tools/collect_evidence.sh",
    "Tester/reports/README.md",
    "Tester/reports/responses/README.md",
    "docs/templates/tester-response.md",
    "Developer/README.md",
    "Developer/reports/README.md",
    "Developer/reports/handoffs/README.md",
    "Developer/reports/responses/README.md",
    "docs/templates/developer-response.md",
]

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


def _looks_text(path, probe=8192):
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(probe)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
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
    missing = [p for p in REQUIRED_PATHS if not os.path.exists(os.path.join(REPO, p))]
    rep.check("structure", not missing, "缺少: " + ", ".join(missing) if missing else f"{len(REQUIRED_PATHS)} 个必需路径齐备")


def submodule_paths():
    gm = os.path.join(REPO, ".gitmodules")
    if not os.path.isfile(gm):
        return set()
    paths = set()
    for line in open(gm, encoding="utf-8", errors="replace"):
        if line.strip().startswith("path"):
            paths.add(line.split("=", 1)[1].strip().split("/")[0])
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
            target = target.split("#")[0].strip()
            if not target or re.match(r"^[a-z]+:", target) or target.startswith("/"):
                continue
            total += 1
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if not os.path.exists(resolved):
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
            for key in ("id", "severity", "owner", "status", "title", "evidence", "closure"):
                if key not in issue:
                    problems.append(f"{name}:{issue.get('id')} 缺字段 {key}")
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
    rep.check("metadata_schema", not problems, "; ".join(problems) if problems else f"{len(module_files)} 个模块记录结构合法")


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
    mismatches, missing, verified, instances = [], [], 0, set()
    for name in sorted(os.listdir(modules_dir)):
        if not name.endswith(".json"):
            continue
        record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
        for build in record.get("builds", []):
            iid = build.get("instance_id")
            if iid in instances:
                mismatches.append(f"instance_id 重复: {iid}")
            instances.add(iid)
            profile = "candidate" if strict and build.get("kind") != "exploration" else "exploration"
            result = ident.verify_build(build, profile=profile)
            for problem in result["problems"]:
                if problem.startswith("产物不在场"):
                    missing.append(f"{iid}: {problem}")
                else:
                    mismatches.append(f"{iid}: {problem}")
            verified += result.get("artifacts_verified", 0)
    detail = f"{len(record.get('builds', []))} 条构建记录 / 复算 {verified} 份产物"
    if mismatches:
        detail += "；" + "; ".join(mismatches[:3])
    if missing:
        detail += "；" + "; ".join(missing[:3])
    if mismatches:
        rep.check("identity_hashes", False, detail)
    elif missing:
        rep.check("identity_hashes", False, detail, warn_only=not strict)
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
        if os.path.isfile(makefile):
            m = re.search(r"^\s*MYKPM_VERSION\s*:?=\s*(\S+)", open(makefile, encoding="utf-8", errors="replace").read(), re.M)
            if not m or normalize_version(m.group(1)) != declared:
                problems.append(f"{module}: Makefile 版本 {m.group(1) if m else '未找到'} != 元数据 {declared}")
        readme_heading = normalize_version(record.get("version_sources", {}).get("readme_heading", ""))
        if readme_heading and readme_heading != declared:
            problems.append(f"{module}: README 最新条目 {readme_heading} != 元数据 {declared}")

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
                if expected_name is not None and embedded_name != expected_name:
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


def check_report_conformance(rep):
    problems = []
    for role, required, folder in (
        ("auditor", AUDITOR_REPORT_REQUIRED, os.path.join(REPO, "Auditor", "reports")),
        ("tester", TESTER_REPORT_REQUIRED, os.path.join(REPO, "Tester", "reports")),
    ):
        if not os.path.isdir(folder):
            problems.append(f"{role} 报告目录不存在")
            continue
        count = 0
        for dirpath, dirs, names in os.walk(folder):
            if role == "tester" and dirpath == folder:
                dirs[:] = [d for d in dirs if d != "responses"]
            for name in names:
                if not name.endswith(".md") or name == "README.md":
                    continue
                count += 1
                text = open(os.path.join(dirpath, name), encoding="utf-8", errors="replace").read()
                miss = [k for k in required if k not in text]
                if miss:
                    problems.append(f"{os.path.relpath(os.path.join(dirpath, name), REPO)} 缺章节/字段: {', '.join(miss)}")
        if count == 0:
            problems.append(f"{role} 报告目录下没有报告（本轮尚未审计/测试属正常，但门禁会记录）")
    rep.check("report_conformance", not problems, "; ".join(problems) if problems else "报告章节齐备", warn_only=True)


TOOL_REFERENCES = ("tools/identity.py", "tools/build_candidate.py", "kernel_img/offset_harness",
                   "offset_harness/run.py")
EVIDENCE_DISCLAIMERS = ("仅用于定位", "仅作定位", "未作依据", "不作依据", "不作为依据",
                        "not used as evidence", "only for diagnosis")


NEGATIONS = ("未导入", "未调用", "不调用", "不导入", "不得", "不把", "禁止", "不引用")


def _mentions_as_source(text, reference, window=12):
    """只在「把该脚本当作来源/依据」时算命中；"未调用 X" 这类否定不提。"""
    start = 0
    while True:
        idx = text.find(reference, start)
        if idx < 0:
            return False
        context = text[max(0, idx - window):idx]
        if not any(neg in context for neg in NEGATIONS):
            return True
        start = idx + len(reference)


def check_auditor_report_sources(rep):
    """P4：报告层面也要自律——引用维护方/实现方脚本时必须声明"仅用于定位"。

    门禁只能做机械检查（关键词 + 声明）；结论是否真的独立由 Auditor 自己负责，
    报告模板里的「证据来源」表用于人工复核。
    """
    reports_dir = os.path.join(REPO, "Auditor", "reports")
    problems, scanned = [], 0
    for dirpath, dirs, names in os.walk(reports_dir) if os.path.isdir(reports_dir) else []:
        dirs[:] = [d for d in dirs if d not in SKIP_WALK_DIRS]
        for name in names:
            if not name.endswith(".md") or name == "README.md":
                continue
            scanned += 1
            text = open(os.path.join(dirpath, name), encoding="utf-8", errors="replace").read()
            hits = [ref for ref in TOOL_REFERENCES if _mentions_as_source(text, ref)]
            if hits and not any(marker in text for marker in EVIDENCE_DISCLAIMERS):
                problems.append(f"{os.path.relpath(os.path.join(dirpath, name), REPO)} 引用了 "
                                f"{', '.join(hits)} 但未声明「仅用于定位，未作依据」")
    rep.check("auditor_report_sources", not problems,
              "; ".join(problems) if problems else (f"{scanned} 份审计报告的结论来源声明合规"
                                                   if scanned else "暂无审计报告"),
              warn_only=True)


BUILD_TOKEN_RE = re.compile(r"[A-Za-z0-9_.+-]*g[0-9a-f]{12,}[A-Za-z0-9_.+#-]*")


def check_tester_report_identity(rep):
    """Tester 报告与修复响应的产物引用核对在册身份串。

    只做机械匹配：抓报告里的 `…g<sha12>…` 形态字符串，跟 metadata 登记的身份对比。
    纯工具响应可只提供工具身份；引用产物时同样检查登记。
    """
    modules_dir = os.path.join(REPO, "metadata", "modules")
    known = set()
    if os.path.isdir(modules_dir):
        for name in sorted(os.listdir(modules_dir)):
            if not name.endswith(".json"):
                continue
            record = json.load(open(os.path.join(modules_dir, name), encoding="utf-8"))
            for build in record.get("builds", []):
                for key in ("instance_id", "build_id"):
                    if build.get(key):
                        known.add(build[key])
                known.update(build.get("build_id_aliases") or [])
    reports_dir = os.path.join(REPO, "Tester", "reports")
    problems, scanned, no_token = [], 0, []
    for dirpath, dirs, names in os.walk(reports_dir) if os.path.isdir(reports_dir) else []:
        dirs[:] = [d for d in dirs if d not in SKIP_WALK_DIRS]
        for name in names:
            if not name.endswith(".md") or name == "README.md":
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), REPO)
            text = open(os.path.join(dirpath, name), encoding="utf-8", errors="replace").read()
            tokens = set(BUILD_TOKEN_RE.findall(text))
            is_response = os.path.relpath(dirpath, reports_dir).split(os.sep)[0] == "responses"
            if is_response and not tokens:
                continue
            scanned += 1
            if not tokens:
                no_token.append(rel)
                continue
            for token in sorted(tokens):
                base = re.sub(r"#\d+$", "", token)
                if token in known:
                    continue
                problems.append(f"{rel} 引用了未登记的构建身份 {token}")
    detail = []
    if problems:
        detail.append("; ".join(problems[:4]))
    if no_token:
        detail.append("未引用任何构建身份：" + ", ".join(no_token[:3]))
    rep.check("tester_report_identity", not problems,
              "；".join(detail) if detail else (f"{scanned} 份 Tester 文档的产物身份串与登记一致"
                                               if scanned else "暂无产物身份引用"),
              warn_only=True)


def check_tester_responses(rep):
    """工具修复响应按自有工具身份检查；实机报告继续使用设备判据。"""
    folder = os.path.join(REPO, "Tester", "reports", "responses")
    problems, checked = [], 0
    for dirpath, dirs, names in os.walk(folder) if os.path.isdir(folder) else []:
        dirs[:] = [d for d in dirs if d not in SKIP_WALK_DIRS]
        for name in names:
            if not name.endswith(".md") or name == "README.md":
                continue
            checked += 1
            text = open(os.path.join(dirpath, name), encoding="utf-8").read()
            miss = [k for k in ("问题编号", "修复工具 commit", "冻结状态", "工具 SHA-256",
                                "修复", "证据", "验证层级", "未覆盖", "复核请求") if k not in text]
            if miss:
                rel = os.path.relpath(os.path.join(dirpath, name), REPO)
                problems.append(f"{rel} 缺字段: {', '.join(miss)}")
    rep.check("tester_responses", not problems,
              "; ".join(problems) if problems else (f"{checked} 份 Tester 修复响应格式合法" if checked else "暂无 Tester 修复响应"),
              warn_only=True)


def check_developer_artifacts(rep):
    """Developer 的修复响应与交接清单：格式可机检，内容由发现方/维护者判定。"""
    problems, checked = [], 0
    responses = os.path.join(REPO, "Developer", "reports", "responses")
    if os.path.isdir(responses):
        for name in sorted(os.listdir(responses)):
            if not name.endswith(".md") or name == "README.md":
                continue
            checked += 1
            text = open(os.path.join(responses, name), encoding="utf-8").read()
            miss = [k for k in ("问题编号", "修复 commit", "Build ID", "证据") if k not in text]
            if miss:
                problems.append(f"Developer/reports/responses/{name} 缺字段: {', '.join(miss)}")
    handoffs = os.path.join(REPO, "Developer", "reports", "handoffs")
    if os.path.isdir(handoffs):
        for name in sorted(os.listdir(handoffs)):
            if not name.endswith(".json"):
                continue
            checked += 1
            try:
                payload = json.load(open(os.path.join(handoffs, name), encoding="utf-8"))
                for key in ("module", "builds", "handoff_by", "handoff_at"):
                    if key not in payload:
                        problems.append(f"Developer/reports/handoffs/{name} 缺字段 {key}")
            except Exception as exc:
                problems.append(f"Developer/reports/handoffs/{name} 解析失败: {exc}")
    rep.check("developer_artifacts", not problems,
              "; ".join(problems) if problems else (f"{checked} 份开发者产物格式合法" if checked else "暂无修复响应/交接清单"),
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
    check_identity_hashes(rep, args.strict)
    check_version_consistency(rep)
    check_report_conformance(rep)
    check_acceptance(rep)
    check_delivery_binding(rep)
    check_tool_selftest(rep)
    check_developer_artifacts(rep)
    check_auditor_independence(rep)
    check_auditor_report_sources(rep)
    check_tester_report_identity(rep)
    check_tester_responses(rep)
    check_hygiene(rep)
    print(f"门禁模式：{'strict（验收/发布）' if args.strict else 'regular'}")
    print()
    return rep.summary()


if __name__ == "__main__":
    sys.exit(main())
