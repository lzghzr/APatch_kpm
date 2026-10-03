#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""冻结就绪检查：回答「现在能不能冻结一轮、让 Auditor/Tester 绑定身份」。

可绑定的候选要求先有干净冻结提交。签名提交需要维护者本人的密钥
（本仓库用智能卡 ssh 签名；**审计/开发环境无法代签**），脚本不代替签名，只负责在冻结前把事实
摆清楚、并在最后打印可直接执行的命令。

本工具只读，不执行 add/commit。冻结判据：

* 枚举用 `git status --porcelain -uall`，得到的是**文件**而不是被折叠的目录；
* 未被忽略的未跟踪文件分三类：
  - 流程/源码（`docs/`、`tools/`、`metadata/`、`Auditor/`… 以及任何含 Makefile 的模块目录）→ **必须进入冻结提交**；
  - 运行期文件（`*.lock`、`*.log`、`__pycache__`、`.DS_Store`、`local/**`）→ 应当被忽略，仍出现就说明漏了 `.gitignore`；
  - 其余未忽略路径 → 要么提交，要么显式忽略，不允许"默认忽略掉"。

用法:
  python3 tools/freeze_check.py [--json]
退出码: 0 可以冻结；1 有阻塞项；2 用法/环境错误。
"""

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# 流程/源码白名单（未跟踪即阻塞：必须一起进入冻结提交）
FROZEN_ROOTS = (".agents", ".github", "AGENTS.md", "Auditor", "Developer", "Tester", "docs",
                "kernel_img", "metadata", "tools", "README.md", ".gitignore")
# 运行期文件：应当被 .gitignore 覆盖；若出现在未跟踪列表里说明漏了规则
RUNTIME_PATTERNS = ("*.lock", "*.log", "*.pyc", "*.pyo", ".DS_Store", "*~", "*.swp")
RUNTIME_ROOTS = ("local/", "artifacts/")
RUNTIME_DIRS = ("__pycache__", ".pytest_cache", ".mypy_cache")


def git(args):
    return subprocess.run(["git", "-C", str(REPO)] + args, capture_output=True, text=True)


def top_level_module_dirs():
    """含 Makefile 的顶层目录 = 会被 CI 构建的模块源码。"""
    dirs = set()
    for path in REPO.iterdir():
        if path.is_dir() and (path / "Makefile").is_file():
            dirs.add(path.name)
    return dirs


def is_runtime(path):
    parts = path.split("/")
    return (any(part in RUNTIME_DIRS for part in parts)
            or path.startswith(RUNTIME_ROOTS)
            or any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(parts[-1], pattern)
                   for pattern in RUNTIME_PATTERNS))


def classify_untracked(files, module_dirs, frozen_roots=FROZEN_ROOTS):
    """把未跟踪文件分成阻塞项与说明项；返回 (blocking, notes)。"""
    blocking, notes = [], []
    for path in files:
        top = path.split("/")[0]
        if is_runtime(path):
            blocking.append(f"运行期文件未被忽略：{path} —— `git add -A` 会把它提交进仓库；"
                            "请把它加进 .gitignore（或移到 local/）")
        elif top in module_dirs:
            blocking.append(f"模块源码未被跟踪：{path} —— 冻结提交必须包含它"
                            f"（CI 会构建 {top}/）；不要把它当本地数据忽略")
        elif any(path == root or path.startswith(root + "/") for root in frozen_roots):
            blocking.append(f"流程/源码文件未被跟踪：{path} —— 冻结提交必须包含它")
        else:
            blocking.append(f"未忽略且不在冻结白名单：{path} —— 要么提交，要么显式写进 .gitignore")
    return blocking, notes


def parse_status():
    """返回 (modified, deleted, untracked) 的相对路径列表（-uall：逐文件）。"""
    out = git(["status", "--porcelain", "-uall"]).stdout.splitlines()
    modified, deleted, untracked = [], [], []
    for line in out:
        if len(line) < 4:
            continue
        code, path = line[:2], line[3:]
        if code == "??":
            untracked.append(path.rstrip("/"))
        elif "D" in code:
            deleted.append(path)
        elif code.strip():
            modified.append(path)
    return modified, deleted, untracked


def main():
    ap = argparse.ArgumentParser(description="冻结就绪检查")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    modified, deleted, untracked = parse_status()
    module_dirs = top_level_module_dirs()
    blocking, notes = classify_untracked(untracked, module_dirs)

    if modified:
        blocking.append(f"已修改未提交 {len(modified)} 个文件：" + ", ".join(modified[:5])
                        + ("…" if len(modified) > 5 else ""))
    for path in deleted:
        blocking.append(f"已删除未提交：{path} —— 确认删除范围后纳入冻结提交")

    # submodule：区分「本来就没有」与「读不到」
    has_gitmodules = (REPO / ".gitmodules").is_file()
    submodule = git(["submodule", "status"]).stdout.strip()
    if not has_gitmodules:
        notes.append("本仓库没有配置 submodule（.gitmodules 不存在）")
    elif not submodule:
        blocking.append("配置了 submodule 但读不到状态（是否在仓库根运行？）")
    elif submodule.startswith("-"):
        blocking.append("KernelPatch submodule 未初始化")
    elif submodule.startswith("+"):
        notes.append("KernelPatch submodule 与记录的 commit 不同（会改变 Build ID 里的 kp<commit>）")

    artifacts = sorted(p.name for p in (REPO / "artifacts").glob("*") if (p / "MANIFEST.json").is_file()) \
        if (REPO / "artifacts").is_dir() else []
    if not artifacts:
        notes.append("artifacts/ 下没有已登记的构建实例：冻结后需要用 build_candidate.py 产出候选")

    result = {
        "blocking": blocking, "notes": notes,
        "modified": modified, "deleted": deleted, "untracked": untracked,
        "module_dirs": sorted(module_dirs), "submodule": submodule,
        "artifact_instances": artifacts,
        "head": git(["rev-parse", "HEAD"]).stdout.strip(),
        "dirty": bool(modified or deleted or untracked),
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if blocking else 0

    print(f"HEAD: {result['head'][:12]}  submodule: {submodule or '（无）'}")
    print(f"工作树: {'不干净' if result['dirty'] else '干净'}  "
          f"修改 {len(modified)} / 删除 {len(deleted)} / 未跟踪 {len(untracked)}")
    if module_dirs:
        print(f"CI 会构建的模块目录: {', '.join(sorted(module_dirs))}")
    if artifacts:
        print(f"已登记构建实例: {len(artifacts)} 个")
    for item in notes:
        print(f"note: {item}")
    for item in blocking:
        print(f"BLOCK: {item}", file=sys.stderr)

    if blocking:
        print("\n尚不能冻结：先处理上面 BLOCK 项（把该纳入的文件 `git add`，把运行期文件写进 .gitignore）。")
        return 1
    print("\n可以冻结。维护者执行（需要智能卡签名；审计/开发环境无法代签）：")
    print('  git add -A')
    print('  git status --short          # 复核一次会提交什么（本工具已确认没有未忽略的未跟踪文件）')
    print('  git commit -S -m "流程与工具：三方角色交付标准流程落地（身份/审计/验收/交付绑定）"')
    print('  git rev-parse HEAD          # 记下冻结提交，后续 Build ID 绑定它')
    print('冻结后再跑：python3 tools/build_candidate.py re_kernel --toolchain <tag> --target "all debug"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
