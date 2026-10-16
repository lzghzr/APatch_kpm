#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""准备 NoMount 配套 ZIP 的下载文件，并合并到同次 KPM 发布目录。"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from urllib.parse import quote
import zipfile

_PROPS = dict(line.split("=", 1) for line in (Path(__file__).resolve().parents[1] / "module/module.prop").read_text().splitlines() if "=" in line)
PACKAGE = "NoMount-kpm_" + _PROPS["version"].removeprefix("v") + ".zip"
MANIFEST = PACKAGE + ".json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_package(package, manifest):
    artifacts = manifest["artifacts"]
    if (manifest.get("module") != "nomount" or manifest.get("kind") != "companion-zip"
            or manifest.get("source_dirty") is not False or manifest.get("input_unchanged") is not True
            or len(artifacts) != 1 or artifacts[0]["name"] != PACKAGE
            or artifacts[0]["sha256"] != digest(package)
            or artifacts[0]["size"] != package.stat().st_size):
        raise ValueError("ZIP 构建身份或产物哈希不一致")
    with zipfile.ZipFile(package) as archive:
        props = dict(line.split("=", 1) for line in archive.read("module.prop").decode().splitlines()
                     if "=" in line and not line.startswith("#"))
    if (props.get("name") != "NoMount-kpm" or props.get("id") != "nomount"
            or props.get("version") != "v" + manifest["version"]):
        raise ValueError("ZIP 显示名、安装 ID 或版本不一致")


def write_sums(directory):
    names = sorted(path.name for path in directory.iterdir()
                   if path.is_file() and path.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text("".join(
        f"{digest(directory / name)}  {name}\n" for name in names))


def prepare(result_path, output):
    result = json.loads(result_path.read_text())
    package = Path(result["artifact"]["path"])
    manifest_path = package.parent / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    verify_package(package, manifest)
    if (result["source_commit"] != manifest["source_commit"]
            or result["instance_id"] != manifest["instance_id"]
            or result["artifact"] != manifest["artifacts"][0]):
        raise ValueError("构建输出与 ZIP 清单不一致")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(package, output / PACKAGE)
    shutil.copy2(manifest_path, output / MANIFEST)
    write_sums(output)


def merge(zip_directory, release):
    package = zip_directory / PACKAGE
    manifest_path = zip_directory / MANIFEST
    companion = json.loads(manifest_path.read_text())
    verify_package(package, companion)
    build_path = release / "BUILD_MANIFEST.json"
    build = json.loads(build_path.read_text())
    if build["source_commit"] != companion["source_commit"]:
        raise ValueError("KPM 与 ZIP 来源提交不一致")
    versions = {item["info"]["version"] for item in build["artifacts"]
                if item["info"]["name"] == "NoMount"}
    if versions != {companion["version"]}:
        raise ValueError("发布 KPM 与 ZIP 版本不一致，或缺少 NoMount KPM")
    if build.get("companions") or any((release / name).exists() for name in (PACKAGE, MANIFEST)):
        raise ValueError("发布目录已有配套 ZIP，拒绝覆盖")
    # 只修改新建发布目录的副本；构建归档及其 MANIFEST 保持原样。
    shutil.copy2(package, release / PACKAGE)
    shutil.copy2(manifest_path, release / MANIFEST)
    build["companions"] = [{
        "module": "nomount", "version": companion["version"],
        "source_commit": companion["source_commit"],
        "upstream_commit": companion["upstream_commit"],
        "instance_id": companion["instance_id"], "file": PACKAGE,
        "sha256": companion["artifacts"][0]["sha256"],
        "manifest": {"file": MANIFEST, "sha256": digest(manifest_path)},
    }]
    build_path.write_text(json.dumps(build, ensure_ascii=False, indent=2) + "\n")
    write_sums(release)


UPDATE = "NoMount-kpm.json"
CHANGELOG = "NoMount-kpm-changelog.md"


def publish_update(release, tag, repository):
    if not tag or not repository:
        raise ValueError("发布标签和仓库不能为空")
    if any((release / name).exists() for name in (UPDATE, CHANGELOG)):
        raise ValueError("发布目录已有更新信息，拒绝覆盖")
    with zipfile.ZipFile(release / PACKAGE) as archive:
        props = dict(line.split("=", 1) for line in archive.read("module.prop").decode().splitlines()
                     if "=" in line and not line.startswith("#"))
        code = int(props["versionCode"])
        changelog = archive.read("CHANGELOG.md")
    if not 0 < code < 2 ** 31:
        raise ValueError("versionCode 须为正的 32 位整数")
    base = "https://github.com/" + repository + "/releases/"
    if props.get("updateJson") != base + "latest/download/" + UPDATE:
        raise ValueError("module.prop 更新地址与发布仓库不一致")
    download = base + "download/" + quote(tag, safe="") + "/"
    update = {"version": props["version"], "versionCode": code,
              "zipUrl": download + quote(PACKAGE, safe=""),
              "changelog": download + CHANGELOG}
    (release / UPDATE).write_text(json.dumps(update, ensure_ascii=False, indent=2) + "\n")
    (release / CHANGELOG).write_bytes(changelog)
    path = release / "BUILD_MANIFEST.json"
    build = json.loads(path.read_text())
    build["companions"][0]["update"] = {"file": UPDATE, "sha256": digest(release / UPDATE)}
    build["companions"][0]["changelog"] = {"file": CHANGELOG, "sha256": digest(release / CHANGELOG)}
    path.write_text(json.dumps(build, ensure_ascii=False, indent=2) + "\n")
    write_sums(release)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("prepare", help="复制已构建 ZIP 和清单，生成下载哈希")
    stage.add_argument("--result", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    publish = commands.add_parser("merge", help="合并同次 KPM/ZIP 发布副本及哈希")
    publish.add_argument("--zip-dir", type=Path, required=True)
    publish.add_argument("--release-dir", type=Path, required=True)
    publish.add_argument("--tag", required=True)
    publish.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.result, args.output)
        else:
            merge(args.zip_dir, args.release_dir)
            publish_update(args.release_dir, args.tag, args.repository)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        parser.exit(1, f"ZIP 发布准备失败：{error}\n")
    print("NoMount 配套 ZIP 发布文件与哈希准备完成")


if __name__ == "__main__":
    main()
