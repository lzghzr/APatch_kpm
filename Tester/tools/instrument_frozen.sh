#!/usr/bin/env bash
# Tester 仪器冻结判据：将运行时实际文件与明确的冻结提交逐字节比较。
#
#   bash Tester/tools/instrument_frozen.sh --repo <dir> --frozen-commit <sha> [--paths "a b c"] [--json]
#
# 只核对判据工具、规则、模板和静态配置。Tester/reports、docs/records、动态实例登记
# 与 local 证据不属于冻结仪器；实例登记的实际字节哈希由 run_test.sh 单独写入报告。
#
# 比较冻结提交和当前文件系统的并集，不依赖 git diff/status 判断内容：
#   * 冻结版本中的文件被删除时仍会被检查；
#   * 当前新增的仪器文件会被发现；
#   * 每个文件直接读取并与提交 blob OID 比较，assume-unchanged 不会绕过检查；
#   * Git、文件读取或解析失败一律返回未冻结。
#
# 默认仪器路径包括影响判据的静态身份配置，不包含动态模块登记和状态记录。
# 退出码: 0 已冻结；1 未冻结/无法核验；2 用法错误。

set -uo pipefail

REPO=""
FROZEN_COMMIT=""
PATHS="${INSTRUMENT_PATHS:-Tester/tools tools docs/process docs/templates metadata/identity.json}"
JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || { echo "--repo 缺少参数" >&2; exit 2; }; REPO="$2"; shift 2 ;;
    --frozen-commit) [ $# -ge 2 ] || { echo "--frozen-commit 缺少参数" >&2; exit 2; }; FROZEN_COMMIT="$2"; shift 2 ;;
    --paths) [ $# -ge 2 ] || { echo "--paths 缺少参数" >&2; exit 2; }; PATHS="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "用法: instrument_frozen.sh --repo <dir> --frozen-commit <sha> [--paths \"a b c\"] [--json]" >&2; exit 2 ;;
  esac
done

[ -n "$REPO" ] && [ -d "$REPO" ] || { echo "缺少/无效 --repo" >&2; exit 2; }

python3 - "$REPO" "$FROZEN_COMMIT" "$PATHS" "$JSON" <<'PY'
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

repo = Path(sys.argv[1]).resolve()
requested_commit = sys.argv[2]
scope_arg = sys.argv[3]
json_mode = sys.argv[4] == "1"
scopes = scope_arg.split()

RUNTIME_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
RUNTIME_NAMES = ("*.lock", "*.log", "*.pyc", "*.pyo", ".DS_Store", "*~", "*.swp")


def emit(frozen, commit, instrument_paths, set_hash, reasons, exit_code):
    payload = {
        "frozen": bool(frozen),
        "frozen_commit": commit,
        "instrument_paths": instrument_paths,
        "instrument_set_sha256": set_hash,
        "reasons": reasons,
    }
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print("是" if frozen else "否")
        if commit:
            print(f"冻结基线: {commit}")
        if set_hash:
            print(f"仪器集合 sha256: {set_hash}")
        print("仪器路径: " + " ".join(instrument_paths))
        for reason in reasons:
            print(f"原因: {reason}")
    raise SystemExit(exit_code)


def git(*args, check=True, input_bytes=None):
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode:
        detail = os.fsdecode(proc.stderr).strip() or f"git {' '.join(args)} exited {proc.returncode}"
        raise RuntimeError(detail)
    return proc


def decode_path(raw):
    return os.fsdecode(raw)


def excluded(rel):
    parts = Path(rel).parts
    return (any(part in RUNTIME_PARTS for part in parts)
            or any(fnmatch.fnmatch(parts[-1], pattern) for pattern in RUNTIME_NAMES))


def committed_files(commit):
    proc = git("ls-tree", "-r", "-z", "--full-tree", commit, "--", *scopes)
    result = {}
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        meta, raw_path = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split(" ")
        rel = decode_path(raw_path)
        if not excluded(rel):
            result[rel] = (mode, oid)
    return result


def working_files():
    result = set()

    def add(rel):
        rel = os.path.normpath(rel).replace(os.sep, "/")
        if rel not in ("", ".") and not excluded(rel):
            result.add(rel)

    for scope in scopes:
        target = repo / scope
        if target.is_symlink() or target.is_file():
            add(scope)
            continue
        if not target.is_dir():
            continue

        def walk_error(exc):
            raise exc

        for current, dirs, files in os.walk(target, topdown=True, followlinks=False, onerror=walk_error):
            current_path = Path(current)
            kept_dirs = []
            for name in dirs:
                child = current_path / name
                rel = child.relative_to(repo).as_posix()
                if excluded(rel):
                    continue
                if child.is_symlink():
                    add(rel)
                else:
                    kept_dirs.append(name)
            dirs[:] = kept_dirs
            for name in files:
                child = current_path / name
                add(child.relative_to(repo).as_posix())
    return result


def working_blob(rel):
    path = repo / rel
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        mode = "120000"
        content = os.fsencode(os.readlink(path))
    elif stat.S_ISREG(info.st_mode):
        mode = "100755" if info.st_mode & 0o111 else "100644"
        content = path.read_bytes()
    else:
        raise OSError(f"不支持的仪器文件类型: {rel}")
    oid = git("hash-object", "--stdin", input_bytes=content).stdout.decode("ascii").strip()
    return mode, oid


if not scopes:
    emit(False, None, [], None, ["仪器路径为空"], 2)
if any(Path(scope).is_absolute() or ".." in Path(scope).parts for scope in scopes):
    emit(False, None, scopes, None, ["仪器路径必须是仓库内的相对路径"], 2)
if not requested_commit:
    emit(False, None, scopes, None, ["未声明完整冻结基线 commit"], 1)

try:
    resolved_proc = git("rev-parse", "--verify", "--quiet", f"{requested_commit}^{{commit}}", check=False)
    if resolved_proc.returncode:
        emit(False, None, scopes, None, [f"冻结基线不是本仓库可读取的提交: {requested_commit}"], 1)
    full_commit = git("rev-parse", f"{requested_commit}^{{commit}}").stdout.decode("ascii").strip()
    base = committed_files(full_commit)
    current = working_files()
    if not base and not current:
        emit(False, full_commit, scopes, None, ["仪器集合为空，无法核验"], 1)

    digest = hashlib.sha256()
    for rel in sorted(base, key=os.fsencode):
        mode, oid = base[rel]
        digest.update(os.fsencode(rel) + b"\0" + mode.encode("ascii") + b"\0" + oid.encode("ascii") + b"\0")
    set_hash = digest.hexdigest()

    reasons = []
    for rel in sorted(set(base) | current, key=os.fsencode):
        if rel not in base:
            reasons.append(f"仪器集合有新增文件，尚未进入冻结基线: {rel}")
            continue
        if rel not in current:
            reasons.append(f"冻结仪器文件缺失: {rel}")
            continue
        try:
            actual_mode, actual_oid = working_blob(rel)
        except (OSError, RuntimeError) as exc:
            reasons.append(f"读取/核验仪器文件失败: {rel}: {exc}")
            continue
        expected_mode, expected_oid = base[rel]
        if actual_mode != expected_mode:
            reasons.append(f"仪器文件模式变化: {rel} ({expected_mode} -> {actual_mode})")
        if actual_oid != expected_oid:
            reasons.append(f"仪器文件字节变化: {rel}")

    emit(not reasons, full_commit, scopes, set_hash, reasons, 0 if not reasons else 1)
except SystemExit:
    raise
except Exception as exc:
    emit(False, None, scopes, None, [f"Git 查询或结果解析失败，按未冻结处理: {exc}"], 1)
PY
