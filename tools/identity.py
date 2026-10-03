#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""模块身份工具：构建输入指纹、Build ID、构建实例、产物 SHA-256 与元数据登记。

设计要点（对应 docs/process/01-identity.md）
--------------------------------------------
* **只追加**：同一 Build ID 的旧记录永不改写；复现构建登记为新的 `instance_id`。
* **Build ID 带配方摘要**：`...g<src12>.r<fingerprint[:8]>.kp<kp7>.<toolchain>`——只改编译参数/依赖/工具链
  就会自动得到新的 Build ID，不需要人为提升版本号；同一 Build ID 出现不同指纹直接报错。
* **核验分级**：`verify --profile exploration|candidate|delivery`。探索记录允许脏树与未捕获参数（只提示），
  候选/交付必须指纹可复算、参数已捕获、源码可按提交核验、产物在场且哈希一致。
* **并发与事务**：模块级文件锁 + 先校验后落盘 + 临时文件原子替换；失败不会留下半截记录。
* **严格指纹**：`build_id` 是可读的配方标签，`fingerprint_sha256` 覆盖全部构建输入
  （源文件集合 + KernelPatch commit + 工具链 + 有效编译参数），任一输入变化都会变。
* **受控写入**：`record` 只追加 `builds[]`，绝不改 `status` / `audits` / `device_tests` / `issues`；
  Developer 可以用它登记自己的候选，也可以用 `--handoff` 只产出交接清单，由维护者 `import-manifest` 导入。
* **按提交核验**：`verify` 默认从每条记录绑定的 `source_commit` 读取源码复算，
  与当前工作树无关；工作树模式需显式 `--worktree`。

用法:
  python3 tools/identity.py manifest <module> [--variant base] [--toolchain TAG] [--build-cmd CMD]
  python3 tools/identity.py record <module> --toolchain TAG [--by Developer] [--variant ...]
                                 [--build-cmd "make -C re_kernel all debug"] [--env ANDROID_NDK=...]
                                 [--handoff PATH] [--new-instance] [--no-archive]
  python3 tools/identity.py import-manifest <path> [--by 维护者]
  python3 tools/identity.py verify [--module <module>] [--profile candidate] [--worktree]
                                 [--check-build-args] [--json]
  python3 tools/build_candidate.py <module> --toolchain TAG --target "all debug"   # 冻结→构建→登记
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUILD_INPUT_EXT = (".c", ".h", ".hpp", ".S", ".s", ".ld", ".lds", ".mk", ".py", ".sh", ".json", ".yml", ".yaml")
BUILD_INPUT_NAMES = ("Makefile", "makefile", "Kbuild", "CMakeLists.txt")
IGNORED_DIRS = {".git", "__pycache__", ".vscode", "node_modules", "target", "artifacts", "local", "out"}
IGNORED_SUFFIX = (".kpm", ".o", ".i64", ".bak", ".pyc")
VARIANT_SUFFIX = {"base": "", "network": "_n", "debug": "_d", "network_debug": "_nd"}


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(args, cwd=None):
    try:
        out = subprocess.run(["git", "-C", str(cwd if cwd is not None else REPO)] + args,
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return ""


def git_blob_at(commit, relpath, filters=False):
    """按提交读取文件内容；读不到返回 None。

    filters=False → 仓库里存的字节（blob，跨机器一致）；
    filters=True  → 走 checkout 过滤后的字节（与工作树一致，受 core.autocrlf 等影响）。
    """
    if not commit:
        return None
    base = ["git", "-C", str(REPO), "cat-file"]
    cmd = base + (["--filters"] if filters else ["blob"]) + [f"{commit}:{relpath}"]
    try:
        return subprocess.run(cmd, capture_output=True, check=True).stdout
    except Exception:
        return None


def commit_exists(sha):
    if not sha:
        return False
    return subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{sha}^{{commit}}"],
                          capture_output=True).returncode == 0


def is_ancestor(older, newer):
    """older 是否为 newer 的祖先（或相等）。"""
    if not older or not newer:
        return False
    return subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", older, newer],
                          capture_output=True).returncode == 0


def signature_status(sha):
    """返回 (是否已验证签名, 说明)。gpg 不可用时视为"未验证"而不是失败。"""
    if not commit_exists(sha):
        return False, "提交不存在"
    proc = subprocess.run(["git", "-C", str(REPO), "verify-commit", sha], capture_output=True, text=True)
    if proc.returncode == 0:
        return True, "git verify-commit 通过"
    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return False, (detail[0] if detail else "git verify-commit 未通过")


def sanitize(text):
    """去掉本机绝对路径再落盘/入哈希（公开文件不写本机信息）。"""
    for prefix, tag in ((str(REPO), "<repo>"), (str(Path.home()), "<home>")):
        text = text.replace(prefix, tag)
    for var in ("ANDROID_NDK_LATEST_HOME", "ANDROID_NDK", "ANDROID_NDK_HOME"):
        value = os.environ.get(var)
        if value:
            text = text.replace(value, f"<{var}>")
    return text


# ---------------------------------------------------------------- 构建输入
def module_dir(module):
    path = REPO / module
    if not path.is_dir():
        die(f"模块目录不存在: {module}")
    return path


def parse_makefile_version(mdir):
    path = mdir / "Makefile"
    if not path.is_file():
        die(f"缺少 Makefile: {path.relative_to(REPO)}")
    m = re.search(r"^\s*MYKPM_VERSION\s*:?=\s*(\S+)", path.read_text(encoding="utf-8", errors="replace"), re.M)
    if not m:
        die(f"Makefile 里找不到 MYKPM_VERSION: {path.relative_to(REPO)}")
    return m.group(1).strip()


def source_files(module, mdir, extra=()):
    """全部构建输入：模块目录内源码/脚本/配置 + 仓库级共享头 + 显式追加。"""
    files = []
    for root, dirs, names in os.walk(mdir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in names:
            if name.endswith(IGNORED_SUFFIX):
                continue
            if name in BUILD_INPUT_NAMES or name.endswith(BUILD_INPUT_EXT):
                files.append(str(Path(root, name).relative_to(REPO)))
    shared = REPO / "kpm_utils.h"
    if shared.is_file():
        files.append("kpm_utils.h")
    files.extend(extra or [])
    return sorted(set(files))


def source_tree_sha256_from_files(pairs):
    h = hashlib.sha256()
    for rel, digest in sorted(pairs):
        h.update(f"{digest}  {rel}\n".encode())
    return h.hexdigest()


def source_tree_sha256(files):
    return source_tree_sha256_from_files([(rel, sha256_file(REPO / rel)) for rel in files])


def source_tree_at_commit(commit, files, filters=False):
    """从提交读取源码算树哈希；任一文件在该提交里不存在则返回 (None, missing)。

    返回两种表示：filters=False 是仓库 blob 字节（跨机器稳定），
    filters=True 是 checkout 后的字节（与工作树一致）。
    """
    pairs, missing = [], []
    for rel in files:
        blob = git_blob_at(commit, rel, filters=filters)
        if blob is None:
            missing.append(rel)
        else:
            pairs.append((rel, sha256_bytes(blob)))
    if missing:
        return None, missing
    return source_tree_sha256_from_files(pairs), []


def build_id_of(module, version, variant, source_tree, toolchain, kp_commit, flags_sha):
    """Build ID = 可读配方标签 + 配方摘要，保证「只改参数也是新身份」。"""
    fp = fingerprint(module, version, variant, source_tree, toolchain, kp_commit, flags_sha)
    kp_tag = (kp_commit or "nokp")[:7]
    return f"{module}-{version}{variant_tag(variant)}+g{source_tree[:12]}.r{fp[:8]}.kp{kp_tag}.{toolchain}", fp


def entry_ids(entry):
    """一个构建条目的全部标识（正名 + 历史别名）。"""
    ids = set(entry.get("build_id_aliases") or [])
    if entry.get("build_id"):
        ids.add(entry["build_id"])
    return ids


def fingerprint(module, version, variant, source_tree, toolchain, kp_commit, flags_sha):
    """严格配方指纹：覆盖全部构建输入；build_id 只是它的可读标签。"""
    payload = "\n".join([
        f"module={module}", f"version={version}", f"variant={variant}",
        f"source_tree_sha256={source_tree}", f"toolchain={toolchain}",
        f"kernelpatch_commit={kp_commit}", f"flags_sha256={flags_sha or ''}",
    ])
    return sha256_bytes(payload.encode())


def env_pairs(env_extra):
    """把 ['K=V', ...] 或 {'K': 'V'} 统一成 dict。"""
    if not env_extra:
        return {}
    if isinstance(env_extra, dict):
        return dict(env_extra)
    out = {}
    for item in env_extra:
        if "=" in item:
            key, _, value = item.partition("=")
            out[key] = value
    return out


def capture_build_recipe(build_cmd, env_extra=None):
    """用 `make -n -B` 捕获配方；递归/带 + 的规则仍按 Makefile 语义执行。"""
    if not build_cmd:
        return {"captured": False, "note": "未提供 --build-cmd，未捕获有效编译参数"}
    parts = shlex.split(build_cmd)
    if not parts or parts[0] != "make":
        return {"captured": False, "command": sanitize(build_cmd), "note": "非 make 命令，未捕获有效参数"}
    env = os.environ.copy()
    env.update(env_pairs(env_extra))
    # -B 强制重算目标；-n 的执行例外由已审阅的 Makefile 和隔离工作树控制。
    try:
        out = subprocess.run(parts[:1] + ["-n", "-B"] + parts[1:], cwd=str(REPO), env=env,
                             capture_output=True, text=True, timeout=180)
    except Exception as exc:
        return {"captured": False, "command": sanitize(build_cmd), "note": f"make -n 失败: {exc}"}
    raw_text = out.stdout + out.stderr
    text = sanitize(raw_text)
    if out.returncode != 0:
        return {"captured": False, "command": sanitize(build_cmd), "returncode": out.returncode,
                "note": f"make -n -B 返回 {out.returncode}，参数未捕获成功；请检查 --build-cmd / --env / 目标名",
                "excerpt": "\n".join(text.splitlines()[:4])}
    link_lines = [ln for ln in text.splitlines() if " -o " in ln or ln.strip().startswith("make")]
    cc = ""
    compiler_sha = ""
    for ln in raw_text.splitlines():
        try:
            token = shlex.split(ln)
        except ValueError:
            continue
        if token and ("clang" in token[0] or "gcc" in token[0] or token[0].endswith("cc")):
            cc = sanitize(token[0])
            compiler = shutil.which(token[0], path=env.get("PATH"))
            if compiler:
                compiler_sha = sha256_file(compiler)
            break
    if not compiler_sha:
        return {"captured": False, "command": sanitize(build_cmd), "returncode": 0,
                "note": "未能识别并复算编译器字节，不能建立工具链指纹"}
    return {
        "captured": True,
        "command": sanitize(build_cmd),
        "dry_run_args": "-n -B（强制重算配方）",
        "returncode": out.returncode,
        "dry_run_sha256": sha256_bytes((text + "\ncompiler_sha256=" + compiler_sha).encode()),
        "cc": cc,
        "compiler_sha256": compiler_sha,
        "excerpt": "\n".join(link_lines[:4]),
    }


# ---------------------------------------------------------------- ELF / 产物
def elf_sections(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        die("不是 ELF64 little-endian 文件")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if e_shoff == 0 or e_shnum == 0:
        die("ELF 没有节表")
    shstr_off, shstr_size = struct.unpack_from("<QQ", data, e_shoff + e_shstrndx * e_shentsize + 0x18)
    shstr = data[shstr_off:shstr_off + shstr_size]
    out = {}
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name_off, = struct.unpack_from("<I", data, base)
        offset, size = struct.unpack_from("<QQ", data, base + 0x18)
        end = shstr.find(b"\x00", name_off)
        out[shstr[name_off:end].decode("utf-8", "replace")] = data[offset:offset + size]
    return out


def parse_kpm_info(blob):
    info = {}
    for field in blob.split(b"\x00"):
        if b"=" in field:
            key, _, value = field.partition(b"=")
            info[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return info


def artifact_facts(path):
    data = Path(path).read_bytes()
    return {
        "name": Path(path).name,
        "sha256": sha256_bytes(data),
        "size": len(data),
        "embedded": parse_kpm_info(elf_sections(data).get(".kpm.info", b"")),
    }


def variant_of(name, module, version):
    stem = f"{module}_{version}"
    if not name.startswith(stem) or not name.endswith(".kpm"):
        return None
    return name[len(stem):-len(".kpm")].lstrip("_") or "base"


def variant_tag(variant):
    return "" if variant == "base" else f"_{variant}"


# ---------------------------------------------------------------- 记录读写
def records_path(module):
    return REPO / "metadata" / "modules" / f"{module}.json"


def load_record(module, required=True):
    path = records_path(module)
    if not path.is_file():
        if required:
            die(f"找不到 {path.relative_to(REPO)}")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@contextlib.contextmanager
def module_lock(module, timeout=30):
    """模块级文件锁：避免两个角色同时追加导致记录丢失。"""
    # 运行期锁文件放 local/（不进版本库、也不污染 metadata/）
    lock_path = REPO / "local" / "locks" / f"{module}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "w")
    deadline = time.time() + timeout
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            if time.time() > deadline:
                handle.close()
                die(f"等待 {module} 的记录锁超时（{timeout}s）")
            time.sleep(0.2)
    try:
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def write_record(module, record, by):
    """原子替换写回：任何失败都不会留下半截 JSON。"""
    record["updated_at"] = utcnow()
    record["updated_by"] = by
    path = records_path(module)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def artifact_map(entry):
    return {a["name"]: a["sha256"] for a in entry.get("artifacts", [])}


def acceptance_records(record):
    """验收只追加；兼容已有单项记录，原字段保持原样。"""
    return ([record["acceptance"]] if record.get("acceptance") else []) + record.get("acceptances", [])


def same_recipe(entry, new):
    """同一份输入、同一套参数、同一产物 → 视为同一次构建（幂等），不算新实例。"""
    return (entry.get("fingerprint_sha256") == new.get("fingerprint_sha256")
            and artifact_map(entry) == artifact_map(new))


def conflict_reason(existing, entry):
    """登记/导入共用的冲突判定；返回 None 表示没有冲突。

    规则（docs/process/01-identity.md）:
      * 同一配方指纹但产物哈希不同 → 归档不可覆盖，报错；
      * 同一 Build ID（含历史别名）但配方指纹不同 → 报错（应自然得到新 Build ID）；
      * 完全一致 → 幂等，由调用方跳过。
    """
    for b in existing:
        if b.get("fingerprint_sha256") and b["fingerprint_sha256"] == entry.get("fingerprint_sha256"):
            if artifact_map(b) != artifact_map(entry):
                return (f"{entry['build_id']}: 同一配方指纹下产物哈希不同（归档不可覆盖）；"
                        "请查复现性，或提升版本号/变体")
            return None
        if entry_ids(b) & entry_ids(entry):
            return (f"{entry['build_id']}: 同一 Build ID 出现不同配方指纹（构建输入/参数/工具链变了）。"
                    "Build ID 已包含配方摘要，正常应自动变化；请检查 --extra-input、KernelPatch 依赖或编译参数")
    return None


def recompute_fingerprint(entry):
    """按记录里保存的输入重算配方指纹（用于核验，不接受"字段存在"就算数）。"""
    recipe = entry.get("recipe") or {}
    flags = recipe.get("dry_run_sha256", "") if recipe.get("captured") else ""
    return fingerprint(entry.get("module"), entry.get("version"), entry.get("variant"),
                       entry.get("source_tree_sha256"), entry.get("toolchain"),
                       entry.get("kernelpatch_commit"), flags)


def instance_dir(instance_id):
    """instance_id = <build_id>#<n> → 第 1 次沿用 artifacts/<build_id>/，第 n 次用 artifacts/<build_id>#n/。"""
    build_id, _, index = instance_id.rpartition("#")
    if not build_id:
        return REPO / "artifacts" / instance_id
    return REPO / "artifacts" / (build_id if index == "1" else f"{build_id}#{index}")


def build_entry(module, mdir, version, variant, toolchain, build_cmd, env_extra,
                commit, kp_commit, extra_inputs=(), kind="candidate", prepared_recipe=None):
    files = source_files(module, mdir, extra_inputs)
    tree = source_tree_sha256(files)
    flags_sha = ""
    build_id, fp = build_id_of(module, version, variant, tree, toolchain, kp_commit, flags_sha)
    blob_tree, blob_missing = source_tree_at_commit(commit, files, filters=False) if commit else (None, files)
    sources = []
    for rel in files:
        blob = git_blob_at(commit, rel, filters=False) if commit else None
        sources.append({"path": rel, "sha256": sha256_file(REPO / rel),
                        "blob_sha256": sha256_bytes(blob) if blob is not None else None})
    recipe = prepared_recipe if prepared_recipe is not None else capture_build_recipe(build_cmd, env_extra)
    flags_sha = recipe.get("dry_run_sha256", "") if recipe.get("captured") else ""
    build_id, fp = build_id_of(module, version, variant, tree, toolchain, kp_commit, flags_sha)
    return {
        "module": module,
        "version": version,
        "kind": kind,          # candidate=可交接；exploration=探索记录（不参与候选/交付核验）
        "build_id": build_id,
        "variant": variant,
        "recorded_at": utcnow(),
        "source_commit": commit,
        "source_dirty": bool(git(["status", "--porcelain"])),
        "source_tree_sha256": tree,
        "source_tree_blob_sha256": blob_tree,
        "source_blob_missing": blob_missing if blob_tree is None else [],
        "sources": sources,
        "toolchain": toolchain,
        "kernelpatch_commit": kp_commit,
        "fingerprint_sha256": fp,
        "recipe": recipe,
    }


def cmd_manifest(args):
    mdir = module_dir(args.module)
    version = parse_makefile_version(mdir)
    files = source_files(args.module, mdir, args.extra_input or [])
    tree = source_tree_sha256(files)
    toolchain = args.toolchain or "unspecified"
    kp_commit = git(["rev-parse", "HEAD"], cwd=REPO / "KernelPatch")
    recipe = capture_build_recipe(args.build_cmd, args.env)
    flags_sha = recipe.get("dry_run_sha256", "") if recipe.get("captured") else ""
    build_id, fp = build_id_of(args.module, version, args.variant, tree, toolchain, kp_commit, flags_sha)
    print(json.dumps({
        "module": args.module,
        "version": version,
        "variant": args.variant,
        "toolchain": toolchain,
        "build_id": build_id,
        "fingerprint_sha256": fp,
        "source_tree_sha256": tree,
        "sources": files,
        "source_commit": git(["rev-parse", "HEAD"]),
        "source_dirty": bool(git(["status", "--porcelain"])),
        "kernelpatch_commit": kp_commit,
        "recipe": recipe,
    }, ensure_ascii=False, indent=2))
    return 0


def collect_artifacts(module, mdir, version, variants):
    found = []
    for name in sorted(os.listdir(mdir)):
        if not name.endswith(".kpm"):
            continue
        variant = variant_of(name, module, version)
        if variant is None or (variants and variant not in variants):
            continue
        found.append((variant, mdir / name))
    return found


def cmd_record(args):
    """公开入口：自己取模块锁后登记。"""
    with module_lock(args.module):
        return record_locked(args)


def record_locked(args):
    """已持模块锁时的登记实现（build_candidate 把锁覆盖到构建全过程）。"""
    mdir = module_dir(args.module)
    if args.handoff is not None:
        handoff_path = Path(args.handoff)
        if not handoff_path.is_absolute():
            handoff_path = REPO / handoff_path
        if handoff_path.exists():
            die("交接清单已存在，请使用新文件名（清单不可覆盖）")
    if args.kind == "candidate" and args.no_archive:
        die("候选必须归档，--no-archive 仅用于探索记录")
    version = parse_makefile_version(mdir)
    artifacts = collect_artifacts(args.module, mdir, version, args.variant)
    if not artifacts:
        die(f"{args.module}/ 下没有匹配 {args.module}_{version}*.kpm 的产物，先构建")

    kp_commit = git(["rev-parse", "HEAD"], cwd=REPO / "KernelPatch")
    commit = git(["rev-parse", "HEAD"])

    if True:
        record = load_record(args.module, required=args.handoff is None) or {"builds": []}
        record.setdefault("builds", [])

        # 产物必须由这份输入构建：登记前再确认输入没变（build_candidate 会传入期望树）
        if args.expect_source_tree:
            current = source_tree_sha256(source_files(args.module, mdir, args.extra_input or []))
            if current != args.expect_source_tree:
                die("构建输入在校验窗口内发生了变化（源码被改动？），拒绝登记；请重新构建")

        # 第一步：只构造与校验，不碰磁盘
        planned, problems, unchanged = [], [], []
        for variant, path in artifacts:
            entry = build_entry(args.module, mdir, version, variant, args.toolchain, args.build_cmd,
                                args.env, commit, kp_commit, args.extra_input or [], kind=args.kind,
                                prepared_recipe=getattr(args, "prepared_recipe", None))
            entry["recorded_by"] = args.by
            transaction = getattr(args, "build_transaction", None)
            if transaction:
                entry["build_transaction"] = transaction
                entry["recipe"] = args.prepared_recipe
                entry["build_id"], entry["fingerprint_sha256"] = build_id_of(
                    args.module, version, variant, entry["source_tree_sha256"], args.toolchain,
                    kp_commit, args.prepared_recipe["dry_run_sha256"])
            if args.kind == "candidate" and not transaction:
                problems.append("候选必须由 tools/build_candidate.py 完成构建事务；直接 record 请用 --kind exploration")
                continue
            if args.kind == "candidate" and entry["source_dirty"]:
                problems.append(f"{entry['build_id']}: 工作树不干净，不能登记为候选；"
                                "请从冻结提交构建，或显式用 --kind exploration 记为探索记录")
                continue
            if args.kind == "candidate" and (entry["recipe"].get("captured") is not True
                                             or type(entry["recipe"].get("returncode")) is not int
                                             or entry["recipe"]["returncode"] != 0):
                problems.append(f"{entry['build_id']}: 有效编译参数未捕获成功，不能登记为候选"
                                f"（recipe.note: {entry['recipe'].get('note', '未提供 --build-cmd')}）")
                continue
            entry["artifacts"] = [artifact_facts(path)]
            entry["artifacts"][0]["path"] = str(Path(path).relative_to(REPO))
            if args.kind == "candidate":
                check = verify_build(entry, profile="candidate")
                if check["problems"]:
                    problems.extend(check["problems"])
                    continue
            prior = [b for b in record["builds"] if entry_ids(b) & entry_ids(entry)]
            if any(same_recipe(p, entry) for p in prior) and not args.new_instance:
                unchanged.append(entry["build_id"])
                continue
            reason = conflict_reason(record["builds"], entry)
            if reason:
                problems.append(reason)
                continue
            index = len(prior) + 1
            while instance_dir(f"{entry['build_id']}#{index}").exists():
                index += 1
            entry["instance_id"] = f"{entry['build_id']}#{index}"
            planned.append((entry, path))
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            print("未写入任何记录（先校验后落盘）", file=sys.stderr)
            return 3

        # 第二步：归档（同一实例的归档不可覆盖）
        for entry, path in planned:
            facts = entry["artifacts"][0]
            if args.no_archive:
                facts["path"] = str(Path(path).relative_to(REPO))
                continue
            outdir = instance_dir(entry["instance_id"])
            outdir.mkdir(parents=True, exist_ok=True)
            target = outdir / facts["name"]
            if target.is_file():
                if sha256_file(target) != facts["sha256"]:
                    die(f"{target.relative_to(REPO)} 已存在且哈希不同（归档不可覆盖）")
            else:
                shutil.copy2(path, target)
            facts["path"] = str(target.relative_to(REPO))
            manifest = outdir / "MANIFEST.json"
            if manifest.is_file():
                old = json.loads(manifest.read_text(encoding="utf-8"))
                if (old.get("fingerprint_sha256") != entry["fingerprint_sha256"]
                        or old.get("instance_id") != entry["instance_id"]
                        or artifact_map(old) != artifact_map(entry)
                        or old.get("source_commit") != entry.get("source_commit")):
                    die(f"{manifest.relative_to(REPO)} 已存在且配方指纹不同（清单不可覆盖）")
            else:
                manifest.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        # 第三步：一次性追加并原子落盘
        record["builds"].extend(entry for entry, _ in planned)
        if args.handoff is not None:
            payload = {"module": args.module, "version": version, "kernelpatch_commit": kp_commit,
                       "handoff_by": args.by, "handoff_at": utcnow(),
                       "note": "归档产物需随清单一起转移：artifacts/<instance_id>/（导入时会逐个核验哈希）",
                       "builds": [entry for entry, _ in planned]}
            path = Path(args.handoff)
            if not path.is_absolute():
                path = REPO / path
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as output:
                output.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            print(f"handoff 清单: {path.relative_to(REPO)}（未写入 metadata/，由维护者 import-manifest 导入）")
        elif planned:
            write_record(args.module, record, args.by)

    for build_id in unchanged:
        print(f"  已登记且完全一致，未改动: {build_id}")
    for entry in (e for e, _ in planned):
        for art in entry["artifacts"]:
            print(f"  {entry['variant']:14s} {art['name']} sha256={art['sha256'][:16]}… instance={entry['instance_id']}")
    return 0


def cmd_import_manifest(args):
    """维护者导入交接清单：保留清单里的实例身份与归档路径，逐项核验，不允许重新编号。"""
    path = Path(args.path)
    if not path.is_absolute():
        path = REPO / path
    if not path.is_file():
        die(f"交接清单不存在: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    module = payload.get("module") or die("清单缺少 module 字段")

    with module_lock(module):
        record = load_record(module)
        builds = record.setdefault("builds", [])
        imported, skipped, problems = 0, 0, []
        for entry in payload.get("builds", []):
            entry = dict(entry)
            iid = entry.get("instance_id")
            if not iid:
                problems.append(f"{entry.get('build_id')}: 清单缺少 instance_id（请用新版 tools/identity.py 生成）")
                continue
            existing = next((b for b in builds if b.get("instance_id") == iid), None)
            if existing:
                if (existing.get("fingerprint_sha256") != entry.get("fingerprint_sha256")
                        or artifact_map(existing) != artifact_map(entry)
                        or existing.get("source_commit") != entry.get("source_commit")
                        or existing.get("sources") != entry.get("sources")):
                    problems.append(f"{iid}: 本机已有同名实例但身份不同（拒绝覆盖）")
                else:
                    skipped += 1
                continue
            profile = "candidate" if entry.get("kind") == "candidate" else "exploration"
            verified = verify_build(entry, profile=profile)
            problems.extend(f"{iid}: {problem}" for problem in verified["problems"])
            for art in entry.get("artifacts", []):
                target = REPO / art.get("path", "")
                if not target.is_file():
                    problems.append(f"{iid}: 归档产物不在场 {art.get('path')}（清单与 artifacts/<instance_id>/ 需一起转移）")
                elif sha256_file(target) != art["sha256"]:
                    problems.append(f"{iid}: 归档产物哈希不一致 {art.get('path')}")
            reason = conflict_reason(builds, entry)
            if reason:
                problems.append(reason)
                continue
            entry["imported_by"] = args.by
            entry["imported_at"] = utcnow()
            entry["handoff_manifest"] = str(path.relative_to(REPO)) if str(path).startswith(str(REPO)) else str(path)
            builds.append(entry)          # 保留原 instance_id 与 artifacts[].path
            imported += 1
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            print("未写入任何记录（先校验后落盘）", file=sys.stderr)
            return 3
        write_record(module, record, args.by)
    print(f"导入 {imported} 条（跳过重复 {skipped} 条）-> {records_path(module).relative_to(REPO)}")
    return 0


def cmd_bind_delivery(args):
    """追加交付绑定：把某个构建实例绑定到签名提交（不修改原构建记录）。"""
    with module_lock(args.module):
        record = load_record(args.module)
        builds = record.get("builds", [])
        entry = next((b for b in builds if b.get("instance_id") == args.instance_id), None)
        if entry is None:
            die(f"找不到实例 {args.instance_id}")
        candidate = verify_build(entry, profile="candidate")
        if candidate["problems"]:
            die("候选核验失败：" + "; ".join(candidate["problems"]))
        delivery_commit = args.delivery_commit or git(["rev-parse", "HEAD"])
        if not commit_exists(delivery_commit):
            die(f"交付提交不存在或不是提交对象：{delivery_commit}")
        source_commit = entry.get("source_commit")
        if source_commit and not is_ancestor(source_commit, delivery_commit):
            die(f"源码提交 {source_commit[:12]} 不是交付提交 {delivery_commit[:12]} 的祖先："
                "这份源码没有被包含在交付提交里")
        missing = [a["name"] for a in entry.get("artifacts", []) if not (REPO / a["path"]).is_file()]
        if missing:
            die("产物不在场，不能绑定交付：" + ", ".join(missing))
        deliveries = record.setdefault("deliveries", [])
        existing = next((d for d in deliveries
                         if d.get("instance_id") == args.instance_id
                         and d.get("delivery_commit") == delivery_commit), None)
        if existing:
            print(f"已存在相同交付绑定（{args.instance_id} @ {delivery_commit[:12]}），未改动")
            return 0
        signed, note = signature_status(delivery_commit)
        binding = {
            "instance_id": entry.get("instance_id"),
            "build_id": entry.get("build_id"),
            "source_commit": source_commit,
            "fingerprint_sha256": entry.get("fingerprint_sha256"),
            "delivery_commit": delivery_commit,
            "tag": args.tag or "",
            "artifacts": {a["name"]: a["sha256"] for a in entry.get("artifacts", [])},
            "signature_verified": signed,
            "signature_note": note,
            "bound_by": args.by,
            "bound_at": utcnow(),
            "note": args.note or "",
        }
        problems = delivery_problems(entry, binding)
        if problems:
            die("交付绑定失败：" + "; ".join(problems))
        deliveries.append(binding)          # 只追加，原构建记录不动
        write_record(args.module, record, args.by)
    print(f"交付绑定已追加：{binding['instance_id']} -> {delivery_commit[:12]}"
          f"（签名：{'已验证' if signed else '未验证 — ' + note}）")
    return 0


# ---------------------------------------------------------------- 核验
PROFILE_LEVELS = {"exploration": 0, "candidate": 1, "delivery": 2}


def delivery_problems(entry, binding):
    """门禁、交付核验与绑定入口共用：复验签名及交付源码，记录不能自证。"""
    problems = []
    for key in ("instance_id", "build_id", "source_commit", "fingerprint_sha256"):
        if not binding.get(key) or binding.get(key) != entry.get(key):
            problems.append(f"交付绑定的 {key} 与实例不一致")
    if binding.get("artifacts") != artifact_map(entry):
        problems.append("交付绑定的产物哈希与实例不一致")
    if entry.get("kind") != "candidate":
        problems.append("交付对象必须是 candidate")
    for key in ("bound_by", "bound_at"):
        if not binding.get(key):
            problems.append(f"交付绑定缺字段 {key}")
    commit = binding.get("delivery_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit) or not commit_exists(commit):
        problems.append("交付提交必须是存在的完整 commit SHA")
        return problems
    if not is_ancestor(entry.get("source_commit"), commit):
        problems.append("源码提交不是交付提交的祖先")
    module = entry.get("module", "")
    source_commit = entry.get("source_commit")
    # 比较整个模块树，可同时发现新增构建输入；仓库共享输入逐项比对。
    if git(["rev-parse", f"{source_commit}:{module}"]) != git(["rev-parse", f"{commit}:{module}"]):
        problems.append("交付提交中的模块树与候选源码不同")
    for src in entry.get("sources", []):
        before = git_blob_at(source_commit, src["path"])
        after = git_blob_at(commit, src["path"])
        if before is None or after != before:
            problems.append(f"交付提交中的构建输入不同：{src['path']}")
    if binding.get("signature_verified") is not True:
        problems.append("交付提交签名未验证")
    signed, note = signature_status(commit)
    if not signed:
        problems.append(f"交付提交签名复验失败：{note}")
    tag = binding.get("tag")
    if tag and git(["rev-parse", f"refs/tags/{tag}^{{commit}}"] ) != commit:
        problems.append("交付标签未指向交付提交")
    return problems


def verify_build(entry, worktree=False, check_build_args=False, profile="exploration", deliveries=None):
    """核验一条构建记录。

    profile=exploration：探索记录，缺参数/脏树只提示；
    profile=candidate ：候选交接，必须指纹可复算、参数已捕获、源码可按提交核验、产物哈希一致；
    profile=delivery  ：交付验收，另要求 delivery_commit 已登记。
    """
    requested_profile = profile
    kind = entry.get("kind", "candidate")
    if kind == "exploration" and profile != "exploration":
        profile = "exploration"
    strict = PROFILE_LEVELS[profile] >= 1
    result = {"build_id": entry.get("build_id"), "instance_id": entry.get("instance_id"),
              "kind": kind, "profile": profile, "problems": [], "notes": []}
    if kind == "exploration":
        if requested_profile != "exploration":
            result["problems"].append("探索记录（kind=exploration）不能作为候选或交付对象")
        else:
            result["notes"].append("探索记录（kind=exploration）：只核验产物与记录完整性，不按候选/交付标准判定")

    def flag(message):
        (result["problems"] if strict else result["notes"]).append(message)

    if kind not in ("candidate", "exploration"):
        flag("kind 必须为 candidate 或 exploration")
    commit = entry.get("source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit) or not commit_exists(commit):
        flag("source_commit 必须是存在的完整 commit SHA")
    if not entry.get("sources") or not entry.get("artifacts"):
        flag("构建输入与产物清单必须非空")

    # 1) 配方指纹必须可复算（不接受"字段存在"就算数）
    recorded_fp = entry.get("fingerprint_sha256")
    if not recorded_fp or set(recorded_fp) == {"0"} or len(recorded_fp) != 64:
        flag(f"fingerprint_sha256 缺失或非法（{recorded_fp!r}）")
    else:
        recomputed_fp = recompute_fingerprint(entry)
        if recomputed_fp != recorded_fp:
            flag(f"配方指纹不一致（记录 {recorded_fp[:12]}，按记录输入重算 {recomputed_fp[:12]}）")

    # 2) 有效编译参数必须捕获
    recipe = entry.get("recipe") or {}
    if recipe.get("captured") is not True:
        flag(f"有效编译参数未捕获（recipe.captured=false{', rc=' + str(recipe.get('returncode')) if recipe.get('returncode') is not None else ''}）")
    elif type(recipe.get("returncode")) is not int or recipe["returncode"] != 0:
        flag("配方捕获必须记录整数 returncode=0")
    if not re.fullmatch(r"[0-9a-f]{64}", recipe.get("dry_run_sha256", "")):
        flag("有效编译参数的 SHA-256 缺失或非法")

    # 3) 脏树不能作为候选/交付
    if entry.get("source_dirty") is not False:
        flag("构建时工作树不干净（source_dirty=true）：候选/交付必须从冻结提交构建")
    transaction = entry.get("build_transaction") or {}
    if strict:
        if not re.fullmatch(r"[0-9a-f]{64}", recipe.get("compiler_sha256", "")):
            flag("候选缺少编译器字节 SHA-256")
        if (transaction.get("source_commit") != commit
                or transaction.get("source_tree_sha256") != entry.get("source_tree_sha256")
                or transaction.get("kernelpatch_commit") != entry.get("kernelpatch_commit")
                or transaction.get("recipe_sha256") != recipe.get("dry_run_sha256")
                or transaction.get("input_unchanged") is not True
                or type(transaction.get("returncode")) is not int
                or transaction["returncode"] != 0):
            flag("候选构建事务缺失或与身份不一致")

    # 4) 交付核验：必须有**只追加**的交付绑定（deliveries[]），且与实例一致
    if profile == "delivery":
        bindings = [d for d in (deliveries or []) if d.get("instance_id") == entry.get("instance_id")]
        if not bindings:
            result["problems"].append("交付核验要求先登记交付绑定："
                                      "python3 tools/identity.py bind-delivery <module> --instance-id <id>")
        for binding in bindings:
            result["delivery"] = {"delivery_commit": binding.get("delivery_commit"),
                                  "signature_verified": binding.get("signature_verified")}
            result["problems"].extend(delivery_problems(entry, binding))

    # 5) 源码：按绑定提交逐文件核验，工作树字节与提交 blob 两表示择一匹配
    recorded = entry.get("source_tree_sha256")
    commit = entry.get("source_commit")
    per_file, mismatched, used = [], [], {}
    for src in entry.get("sources", []):
        rel = src["path"]
        recorded_file = src.get("sha256")
        candidates = {}
        if worktree:
            path = REPO / rel
            if path.is_file():
                candidates["工作树字节"] = sha256_file(path)
        else:
            raw = git_blob_at(commit, rel, filters=False) if commit else None
            if raw is not None:
                candidates["提交 blob"] = sha256_bytes(raw)
            filt = git_blob_at(commit, rel, filters=True) if commit else None
            if filt is not None:
                candidates["提交内容按 checkout 过滤"] = sha256_bytes(filt)
        expected = {recorded_file}
        if src.get("blob_sha256"):
            expected.add(src["blob_sha256"])
        hit = next((label for label, value in candidates.items() if value in expected), None)
        if hit is None:
            mismatched.append(f"{rel}（记录 {str(recorded_file)[:12]}，"
                              + (", ".join(f"{k}={v[:12]}" for k, v in candidates.items()) or "不可用") + "）")
        else:
            used[hit] = used.get(hit, 0) + 1
            per_file.append((rel, recorded_file))
    if mismatched:
        result["source_verified"] = False
        result["problems"].append("以下文件无法按绑定提交核验：" + "；".join(mismatched[:4]))
    else:
        recomputed = source_tree_sha256_from_files(per_file)
        if recomputed == recorded:
            result["source_verified"] = True
            result["notes"].append("源码核验通过（" + "，".join(f"{k} {v} 个" for k, v in sorted(used.items())) + "）")
        else:
            result["source_verified"] = False
            result["problems"].append(f"源码树哈希不一致（记录 {str(recorded)[:12]}，实算 {recomputed[:12]}）")

    # 6) 产物
    for art in entry.get("artifacts", []):
        path = REPO / art["path"]
        if not path.is_file():
            result["problems"].append(f"产物不在场: {art['path']}")
            continue
        if sha256_file(path) != art["sha256"]:
            result["problems"].append(f"产物哈希不一致: {art['name']}")
        else:
            result["artifacts_verified"] = result.get("artifacts_verified", 0) + 1

    # 7) 可选：重跑 make -n 比对参数；未捕获时必须报错，不能静默跳过
    if check_build_args:
        if not recipe.get("captured"):
            result["problems"].append("--check-build-args 要求配方已捕获，但 recipe.captured=false")
        elif recipe.get("command"):
            again = capture_build_recipe(recipe["command"])
            if again.get("captured") is not True or again.get("returncode") != 0:
                result["problems"].append("有效编译参数重新捕获失败")
            elif again.get("dry_run_sha256") != recipe.get("dry_run_sha256"):
                result["problems"].append("有效编译参数与记录不一致（工具链/环境变了？）")
        else:
            result["problems"].append("--check-build-args 要求提供 recipe.command")
    return result


def cmd_verify(args):
    modules_dir = REPO / "metadata" / "modules"
    if not modules_dir.is_dir():
        die("metadata/modules 不存在")
    results, problems_total, verified_total = [], 0, 0
    for path in sorted(modules_dir.glob("*.json")):
        module = path.stem
        if args.module and module != args.module:
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        for entry in record.get("builds", []):
            if args.instance_id and entry.get("instance_id") != args.instance_id:
                continue
            if not args.instance_id and args.profile != "exploration" and entry.get("kind") == "exploration":
                continue
            result = verify_build(entry, worktree=args.worktree, check_build_args=args.check_build_args,
                                  profile=args.profile, deliveries=record.get("deliveries", []))
            results.append(result)
            problems_total += len(result["problems"])
            verified_total += result.get("artifacts_verified", 0)
    if not results:
        problems_total += 1
        if not args.json:
            print("error: 没有匹配的构建实例可供本档位核验", file=sys.stderr)
    if args.json:
        print(json.dumps({"profile": args.profile, "builds": results, "problems": problems_total,
                          "artifacts_verified": verified_total}, ensure_ascii=False, indent=2))
    else:
        for result in results:
            for problem in result["problems"]:
                print(f"error: {result['build_id']}: {problem}", file=sys.stderr)
            for note in result["notes"]:
                print(f"note: {result['build_id']}: {note}")
        print(f"verify[{args.profile}]: 复算 {verified_total} 份产物，{len(results)} 条构建记录，"
              f"{problems_total} 处问题（源码默认按绑定提交核验）")
    return 1 if problems_total else 0


def main():
    ap = argparse.ArgumentParser(description="模块身份工具（只追加、按提交核验）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("manifest", help="输出构建输入清单、Build ID 与严格指纹")
    p.add_argument("module")
    p.add_argument("--variant", default="base", choices=sorted(VARIANT_SUFFIX))
    p.add_argument("--toolchain", default="")
    p.add_argument("--build-cmd", help="实际构建命令，用于捕获有效编译参数（如 'make -C re_kernel all debug'）")
    p.add_argument("--env", action="append", help="传给 make -n 的环境变量，如 ANDROID_NDK=/path")
    p.add_argument("--extra-input", action="append", help="额外构建输入（仓库相对路径）")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("record", help="追加构建实例记录（只写 builds[]）")
    p.add_argument("module")
    p.add_argument("--toolchain", required=True)
    p.add_argument("--by", default="Developer", help="谁登记的（Developer / 维护者）")
    p.add_argument("--kind", default="candidate", choices=("candidate", "exploration"),
                   help="candidate=可交接候选（要求冻结提交、参数已捕获）；exploration=探索记录")
    p.add_argument("--variant", action="append", choices=sorted(VARIANT_SUFFIX))
    p.add_argument("--build-cmd")
    p.add_argument("--env", action="append")
    p.add_argument("--extra-input", action="append")
    p.add_argument("--expect-source-tree", help="登记前校验输入树哈希未变（build_candidate 传入）")
    p.add_argument("--handoff", help="只写交接清单，不碰 metadata/（维护者用 import-manifest 导入）")
    p.add_argument("--new-instance", action="store_true", help="完全相同的复现也追加为新实例")
    p.add_argument("--no-archive", action="store_true", help="不复制产物到 artifacts/（本地自检）")
    p.set_defaults(func=cmd_record)

    p = sub.add_parser("import-manifest", help="维护者：把交接清单导入 metadata/")
    p.add_argument("path")
    p.add_argument("--by", default="维护者")
    p.add_argument("--new-instance", action="store_true", help="完全相同的复现也追加为新实例")
    p.set_defaults(func=cmd_import_manifest)

    p = sub.add_parser("bind-delivery", help="追加交付绑定（实例 → 签名提交；不改构建记录）")
    p.add_argument("module")
    p.add_argument("--instance-id", required=True, help="要绑定的构建实例，如 <build_id>#2")
    p.add_argument("--delivery-commit", help="交付提交（默认 HEAD）")
    p.add_argument("--tag", help="交付标签，如 re_kernel-8.0.0")
    p.add_argument("--by", default="维护者")
    p.add_argument("--note")
    p.set_defaults(func=cmd_bind_delivery)

    p = sub.add_parser("verify", help="按绑定提交复算源码树、配方指纹与产物哈希")
    p.add_argument("--module")
    p.add_argument("--instance-id", help="只核验指定实例（验收与交付建议使用）")
    p.add_argument("--profile", default="exploration", choices=sorted(PROFILE_LEVELS),
                   help="exploration=只提示；candidate=候选交接必须完整；delivery=另要求已登记交付绑定")
    p.add_argument("--worktree", action="store_true", help="改用当前工作树复算（默认按 source_commit）")
    p.add_argument("--check-build-args", action="store_true", help="重跑 make -n 比较有效编译参数")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
