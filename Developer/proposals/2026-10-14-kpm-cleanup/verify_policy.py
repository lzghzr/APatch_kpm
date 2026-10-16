#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""在临时副本核对维护者补丁；现行门禁和原有断言保持原样。"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PROPOSAL = Path(__file__).resolve().parent / "maintainer-policy.patch"
sys.path.insert(0, str(ROOT / "tools"))
import selftest_tools as st


def rejects(action, message=""):
    try:
        action()
    except ValueError as error:
        return message in str(error)
    return False


def main():
    os.chdir(ROOT)
    with tempfile.TemporaryDirectory(prefix="kpm-policy-review-") as temporary:
        scratch = Path(temporary)
        for name in re.findall(r"^--- a/(.+)$", PROPOSAL.read_text(), re.M):
            destination = scratch / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        subprocess.run(["patch", "-p1", "-i", str(PROPOSAL)], cwd=scratch,
                       check=True, capture_output=True)
        load = st.load
        gate = load("patched_gate", scratch / "tools/check_repository.py")
        artifact = load("patched_artifact", scratch / "tools/artifact_gate.py")
        # 仅替换被测实现，完整运行现有断言，包括历史冻结注册名反例。
        st.load = lambda name, path: load(
            name, scratch / "tools/check_repository.py"
            if Path(path).name == "check_repository.py" else path)
        rows = st.run_checks()
        assert all(row[1] for row in rows), [row for row in rows if not row[1]]

        record = {"module": "nomount", "version_declared": "0.5.2", "builds": [
            {"version": "0.5.2", "instance_id": "fixture#1", "artifacts": [
                {"name": "NoMount_0.5.2.kpm", "embedded": {
                    "name": "NoMount", "version": "0.5.2"}}]}]}
        fixture = Path(st._gate_repo(record, gate))
        try:
            (fixture / "nomount").mkdir()
            (fixture / "nomount/Makefile").write_text("MYKPM_VERSION := 0.5.2\n")

            def accepted(name, version):
                record["builds"][0]["artifacts"][0]["embedded"].update(
                    name=name, version=version)
                (fixture / "metadata/modules/nomount.json").write_text(json.dumps(record))
                report = gate.Report()
                gate.check_version_consistency(report)
                return not report.failures

            cases = {
                "camel_project": accepted("NoMount", "0.5.2"),
                "wrong_name_rejected": not accepted("Other", "0.5.2"),
                "wrong_version_rejected": not accepted("NoMount", "0.5.3"),
            }
        finally:
            shutil.rmtree(fixture)
            st.TEMP_DIRS.remove(str(fixture))

        handoff = json.loads((ROOT / "Developer/reports/handoffs/2026-10-14-nomount-0.5.2.json").read_text())
        base = next(build for build in handoff["builds"] if build["variant"] == "base")
        source = ROOT / base["artifacts"][0]["path"]
        directory = scratch / "artifacts"
        directory.mkdir()
        original = directory / source.name
        shutil.copy2(source, original)
        cases["artifact_set_camel"] = len(artifact.validate(directory, ["nomount"])) == 1
        cases["artifact_set_wrong_rejected"] = rejects(lambda: artifact.validate(directory, ["other"]))

        # 不同版本的真实 ELF 可在大小写不敏感文件系统上并存。
        raw = source.read_bytes()
        collision = directory / "nomount_0.5.3.kpm"
        collision.write_bytes(raw.replace(b"name=NoMount\0", b"name=nomount\0")
                             .replace(b"version=0.5.2\0", b"version=0.5.3\0"))
        cases["case_collision_rejected"] = rejects(
            lambda: artifact.validate(directory, ["nomount"]), "大小写冲突")
        collision.unlink()
        original.unlink()
        (directory / "nomount_0.5.2.kpm").write_bytes(raw)
        cases["filename_exact_rejected"] = rejects(lambda: artifact.validate(directory, ["nomount"]))

        # 使用补丁里的 debug 判断；已声明 debug 的执行失败仍必须退出失败。
        command = "make all\nif grep -Eq '^debug[[:space:]]*:' Makefile; then\n make debug\nfi\n"
        for label, makefile, expected in [
            ("ordinary", "all:\n\t@echo all\n", 0),
            ("real_debug", "all:\n\t@echo all\ndebug:\n\t@echo debug\n", 0),
            ("broken_debug", "all:\n\t@echo all\ndebug:\n\t@false\n", 2),
        ]:
            (scratch / "Makefile").write_text(makefile)
            result = subprocess.run(["bash", "-ec", command], cwd=scratch,
                                    capture_output=True, text=True)
            cases["ci_" + label] = (result.returncode == expected
                                    and (label != "real_debug" or "debug\n" in result.stdout))
        assert all(cases.values()), cases
        print(f"Existing selftests {len(rows)} PASS; policy fixtures {len(cases)} PASS")


if __name__ == "__main__":
    main()
