#!/usr/bin/env python3
"""DEV-032 冻结工具复核；仅在自动清理的临时仓库中构造报告。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[3]
FIX = "06a371bc89edb70f18bb6965d853a2c831b5578f"
SUBJECT = "tools/check_repository.py"
REPORT = "Auditor/reports/r.md"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def main():
    frozen = git(REPO, "show", f"{FIX}:{SUBJECT}")
    results = []
    with tempfile.TemporaryDirectory(prefix="dev032-frozen-") as directory:
        temp = Path(directory)
        tool = temp / "check_repository.py"
        tool.write_bytes(frozen)
        spec = importlib.util.spec_from_file_location("frozen_gate", tool)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        root = temp / "fixture"
        report = root / REPORT
        report.parent.mkdir(parents=True)
        metadata = root / "metadata/modules/mod.json"
        metadata.parent.mkdir(parents=True)
        git(root, "init", "-q")

        def commit(data, message):
            report.write_bytes(data)
            git(root, "add", REPORT)
            git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", message)
            return git(root, "rev-parse", "HEAD").decode().strip()

        base = b"original report\n"
        suffix = b"appended record\n"
        current = base + suffix
        base_commit = commit(base, "baseline")
        append_commit = commit(current, "append")
        rewritten = b"rewritten report\n" + suffix
        rewrite_commit = commit(rewritten, "rewritten report")
        good = {
            "module": "mod",
            "audits": [{"report": REPORT, "report_sha256": sha(current)}],
            "report_versions": [{
                "path": REPORT,
                "append_only_baseline": {"sha256": sha(base), "size": len(base), "commit": base_commit},
                "versions": [
                    {"sha256": sha(base), "size": len(base), "commit": base_commit},
                    {"sha256": sha(current), "size": len(current), "commit": append_commit,
                     "added_sha256": sha(suffix), "added_size": len(suffix)}],
            }],
        }
        cases = [
            ("合法纯追加", "PASS", "PASS"),
            ("历史缺提交", "WARN", "FAIL"),
            ("历史缺提交且追加哈希错误，边界已知", "FAIL", "FAIL"),
            ("真实原文改写，整份哈希与提交已登记", "FAIL", "FAIL"),
            ("追加哈希错误", "FAIL", "FAIL"),
            ("历史缺提交且边界不可推导，后续追加哈希错误", "WARN", "FAIL"),
        ]
        for name, regular, strict in cases:
            data = copy.deepcopy(good)
            versions = data["report_versions"][0]["versions"]
            contents = current
            if name.startswith("历史缺提交"):
                versions[0].pop("commit")
            if "追加哈希错误" in name:
                versions[-1]["added_sha256"] = "0" * 64
            if "边界不可推导" in name:
                # 此历史段的字节未存入 Git，登记哈希也不等于可读取基线。
                versions[0].update(sha256=sha(base + b"unavailable historical section\n"))
            if name.startswith("真实原文改写"):
                contents = rewritten
                data["audits"][0]["report_sha256"] = sha(contents)
                versions[-1].update(sha256=sha(contents), size=len(contents), commit=rewrite_commit)
            commit(contents, "fixture current bytes")
            metadata.write_text(json.dumps(data), encoding="utf-8")
            for is_strict, expected in ((False, regular), (True, strict)):
                gate.REPO = str(root)
                rep = gate.Report()
                gate.check_report_integrity(rep, strict=is_strict)
                actual = "FAIL" if rep.failures else "WARN" if rep.warnings else "PASS"
                details = " ".join(check[2] for check in rep.checks)
                diagnostic_ok = True
                if "边界已知" in name or name == "追加哈希错误":
                    diagnostic_ok = "第 2 段追加哈希与登记不符" in details
                elif "边界不可推导" in name:
                    diagnostic_ok = "边界不可确定" in details and "追加哈希与登记不符" not in details
                elif name.startswith("真实原文改写"):
                    diagnostic_ok = "原文被改写" in details
                results.append({"case": name, "strict": is_strict, "expected": expected,
                                "actual": actual, "diagnostic_ok": diagnostic_ok,
                                "matches": actual == expected and diagnostic_ok,
                                "checks": rep.checks})
        evidence = {
            "fix_commit": FIX,
            "subjects": {SUBJECT: sha(frozen)},
            "role": "Developer",
            "fixture_commits": {"baseline": base_commit, "append": append_commit,
                                 "rewrite": rewrite_commit},
            "bytes": {"baseline": base.decode(), "append": suffix.decode()},
            "known_boundary": {"baseline_sha256": sha(base), "historical_sha256": sha(base),
                               "actual_added_sha256": sha(suffix), "registered_added_sha256": "0" * 64},
            "unknown_boundary": {"historical_sha256": sha(base + b"unavailable historical section\n"),
                                 "historical_commit": None, "expected_regular": "WARN"},
            "cases": results,
            "passed": all(result["matches"] for result in results),
            "scope": "Frozen maintainer report tool only; temporary Git fixtures; no KPM build or device test.",
        }
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
