#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""候选构建统一入口：冻结输入 → 清理中间产物 → 构建 → 复核输入未变 → 登记身份。

为什么需要它：`identity.py record` 只是"读现有 .kpm + 读当前源码"，无法证明产物确实由这份源码与
这些参数构建。本入口把顺序反过来，并在构建前后各取一次输入指纹，保证「产物 ↔ 输入 ↔ 参数」绑定。

用法:
  export ANDROID_NDK=<ndk 路径>
  python3 tools/build_candidate.py re_kernel --toolchain ndk26.3.11579264 --target "all debug"
  python3 tools/build_candidate.py re_kernel --toolchain ndk26.3.11579264 \
      --env ANDROID_NDK=$ANDROID_NDK --handoff Developer/reports/handoffs/re_kernel-8.0.0.json
  python3 tools/build_candidate.py re_kernel --toolchain ... --allow-dirty   # 记为 exploration

隔离与锁:
  * 构建前把模块目录里的**全部中间产物/产物**（*.o *.kpm …）移到 local/stale/<时间戳>/，
    并默认加 -B 强制重建，避免复用旧对象（--no-force 可关掉 -B）；
  * 构建后校验每个产物与中间产物的 mtime 不早于本次构建开始时间，否则拒绝登记；
  * 模块锁覆盖「输入快照 → 清理 → 构建 → 复核输入未变 → 登记」全过程。

退出码：0 成功；1 构建/校验失败；2 用法或环境错误；3 身份冲突（归档不可覆盖）。
"""

import argparse
import importlib.util
import os
import shutil
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_identity():
    spec = importlib.util.spec_from_file_location("dsh_identity", REPO / "tools" / "identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def die(message, code=2):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


# 只清理中间产物/产物；构建输入与 Git 已跟踪文件一律保护（例如模块里的 .s 汇编源码）
CLEAN_PATTERNS = ("*.o", "*.kpm", "*.d", "*.i", "*.gcno", "*.gcda", "*.mod", "*.mod.c")
AMBIGUOUS_PATTERNS = ("*.s", "*.S")          # 既可能是生成的，也可能是源码：只在未跟踪且非输入时清理


def tracked_in(module):
    """模块目录下 Git 已跟踪的文件（仓库相对路径）。"""
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", module], capture_output=True, text=True)
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def plan_cleanup(mdir, protected_rel):
    """返回 (要移走的文件, 被保护而跳过的文件)。"""
    protected = {str(Path(p).name) for p in protected_rel}
    to_move, skipped = [], []
    for pattern in CLEAN_PATTERNS + AMBIGUOUS_PATTERNS:
        for path in sorted(mdir.glob(pattern)):
            if not path.is_file():
                continue
            if path.name in protected:
                skipped.append(path.name)
                continue
            to_move.append(path)
    return to_move, skipped


def main():
    ap = argparse.ArgumentParser(description="候选构建统一入口（冻结输入 → 构建 → 登记）")
    ap.add_argument("module")
    ap.add_argument("--toolchain", required=True, help="工具链标签，如 ndk26.3.11579264")
    ap.add_argument("--target", default="all", help="传给 make 的目标（默认 all；可写 'all debug'）")
    ap.add_argument("--env", action="append", default=[], help="构建环境变量，如 ANDROID_NDK=/path")
    ap.add_argument("--by", default="Developer")
    ap.add_argument("--kind", default="candidate", choices=("candidate", "exploration"))
    ap.add_argument("--allow-dirty", action="store_true",
                    help="允许脏工作树（自动降级为 exploration，不能作为候选交接）")
    ap.add_argument("--handoff", help="只产出交接清单，不写 metadata/")
    ap.add_argument("--extra-input", action="append", help="额外构建输入（仓库相对路径）")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--no-force", action="store_true", help="不加 -B（默认强制重建，避免旧 .o 复用）")
    ap.add_argument("--no-archive", action="store_true")
    args = ap.parse_args()

    ident = load_identity()
    mdir = ident.module_dir(args.module)
    env = os.environ.copy()
    for item in args.env:
        if "=" not in item:
            die(f"--env 需要 K=V 形式：{item!r}")
        key, _, value = item.partition("=")
        env[key] = value

    kind = args.kind
    dirty = bool(ident.git(["status", "--porcelain"]))
    if dirty:
        if not args.allow_dirty:
            die("工作树不干净：候选必须从冻结提交构建。先提交（签名），"
                "或用 git worktree add ../<repo>-dev <sha> 在独立工作树构建；"
                "确实只是探索请加 --allow-dirty（会记为 exploration）")
        kind = "exploration"
        print("warn: 工作树不干净 → 本次记为 exploration（不能作为候选交接）")

    # 模块锁覆盖：输入快照 → 清理 → 构建 → 复核输入未变 → 登记
    with ident.module_lock(args.module):
        extras = sorted(set((args.extra_input or []) + ["tools/build_candidate.py", "tools/identity.py"]))
        inputs = ident.source_files(args.module, mdir, extras)
        before_tree = ident.source_tree_sha256(inputs)
        source_commit = ident.git(["rev-parse", "HEAD"])
        kp_commit = ident.git(["rev-parse", "HEAD"], cwd=REPO / "KernelPatch")
        if kind == "candidate" and (not kp_commit or ident.git(["status", "--porcelain"], cwd=REPO / "KernelPatch")):
            die("KernelPatch 依赖必须是已初始化的干净提交")
        build_cmd = shlex.join(["make", "-C", args.module] + shlex.split(args.target))
        before_recipe = ident.capture_build_recipe(build_cmd, args.env)
        if kind == "candidate" and before_recipe.get("captured") is not True:
            die("有效编译参数捕获失败，未开始候选构建")
        print(f"输入冻结: {len(inputs)} 个文件, tree={before_tree[:16]}")

        # 受保护集合：构建输入（含模块里的 .s 源码）+ Git 已跟踪文件
        protected_rel = set(inputs) | tracked_in(args.module)
        to_move, skipped = plan_cleanup(mdir, protected_rel)
        if skipped:
            print(f"保护 {len(skipped)} 个文件（构建输入/已跟踪，不清理）：{', '.join(sorted(skipped))}")
        stale = REPO / "local" / "stale" / f"{args.module}-{time.time_ns()}"
        moved = []
        for path in to_move:
            stale.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(stale / path.name))
            moved.append(path.name)
        if moved:
            print(f"已把 {len(moved)} 个旧产物/中间产物移到 {stale.relative_to(REPO)}（避免复用）")

        # 受保护文件的指纹（构建前后比对：构建不得改动/删除源码）
        protected_before = {}
        for rel in sorted(protected_rel):
            path = REPO / rel
            if path.is_file():
                protected_before[rel] = ident.sha256_file(path)

        logs = REPO / "local" / "build_logs"
        logs.mkdir(parents=True, exist_ok=True)
        log_path = logs / f"{time.strftime('%Y%m%dT%H%M%SZ')}-{args.module}.log"
        command = shlex.split(build_cmd)
        force = [] if args.no_force else ["-B"]
        print(f"构建: {' '.join(command[:1] + force + command[1:])}"
              f"（env: {', '.join(args.env) or '继承当前环境'}）")
        started = time.time()
        try:
            proc = subprocess.run(command[:1] + force + command[1:], cwd=str(REPO), env=env,
                                  capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            die(f"构建超时（>{args.timeout}s），日志见 {log_path.relative_to(REPO)}", 1)
        log_path.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        if proc.returncode != 0:
            print(f"error: 构建失败（rc={proc.returncode}），日志：{log_path.relative_to(REPO)}", file=sys.stderr)
            print("未登记任何身份（失败构建不进元数据）", file=sys.stderr)
            return 1
        print(f"构建完成（{time.time() - started:.1f}s），日志：{log_path.relative_to(REPO)}")

        # 构建期间输入不得变化；受保护的已跟踪文件也不得被改动或删除
        after_inputs = ident.source_files(args.module, mdir, extras)
        after_tree = ident.source_tree_sha256(after_inputs)
        after_recipe = ident.capture_build_recipe(build_cmd, args.env)
        if after_inputs != inputs or after_tree != before_tree:
            die("构建期间构建输入发生变化（谁改了源码？），拒绝登记；请重新构建", 1)
        if (ident.git(["rev-parse", "HEAD"]) != source_commit
                or ident.git(["rev-parse", "HEAD"], cwd=REPO / "KernelPatch") != kp_commit
                or (kind == "candidate" and ident.git(["status", "--porcelain"], cwd=REPO / "KernelPatch"))
                or after_recipe != before_recipe):
            die("构建期间提交、依赖或有效编译参数变化，拒绝登记", 1)
        touched = []
        for rel, digest in protected_before.items():
            path = REPO / rel
            if not path.is_file():
                touched.append(f"{rel}（被删除）")
            elif ident.sha256_file(path) != digest:
                touched.append(f"{rel}（内容被改）")
        if touched:
            die("构建改动了受保护文件（源码/已跟踪文件），拒绝登记：" + "；".join(touched[:4]), 1)

        # 产物与中间产物必须都是这次构建产生的（mtime 不早于构建开始）
        stale_bits = []
        for pattern in ("*.kpm", "*.o"):
            for path in sorted(mdir.glob(pattern)):
                if path.stat().st_mtime < started - 1:
                    stale_bits.append(path.name)
        produced = sorted(mdir.glob("*.kpm"))
        if not produced:
            die(f"{args.module}/ 下没有产生任何 .kpm（target={args.target}）", 1)
        if stale_bits:
            die("以下文件的时间戳早于本次构建开始，可能是残留（拒绝登记）：" + ", ".join(stale_bits), 1)
        print("产物: " + ", ".join(p.name for p in produced))

        ns = argparse.Namespace(
            module=args.module, toolchain=args.toolchain, by=args.by, kind=kind,
            variant=None, build_cmd=build_cmd,
            env=args.env, extra_input=extras, expect_source_tree=before_tree,
            handoff=args.handoff, new_instance=True, no_archive=args.no_archive,
            prepared_recipe=before_recipe,
            build_transaction={"source_commit": source_commit, "source_tree_sha256": before_tree,
                               "kernelpatch_commit": kp_commit, "recipe_sha256": before_recipe.get("dry_run_sha256"),
                               "input_unchanged": True, "returncode": proc.returncode},
        )
        rc = ident.record_locked(ns)      # 锁已持有，用内核函数避免自锁
        if rc == 0:
            print("身份登记完成（如需交接，请用 --handoff 产出清单并连同 artifacts/ 一起转移）")
        return rc


if __name__ == "__main__":
    sys.exit(main())
