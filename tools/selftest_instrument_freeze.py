#!/usr/bin/env python3
"""维护者独立夹具：复核 Tester 仪器冻结判据，临时仓库中运行。"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parent.parent


def check_helper(helper):
    results = []
    for case in ("baseline", "records_only", "changed_file", "deleted_directory",
                 "new_instrument", "assume_unchanged", "missing_baseline"):
        with tempfile.TemporaryDirectory(prefix="instrument-freeze-") as directory:
            root = Path(directory)
            files = {"Tester/tools/fixture.sh": "echo baseline\n",
                     "tools/fixture.py": "baseline\n",
                     "docs/process/rules.md": "rules\n",
                     "docs/templates/report.md": "template\n"}
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            shutil.copyfile(helper, root / "Tester/tools/instrument_frozen.sh")
            for args in (("init", "-q"), ("add", "."),
                         ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                          "-c", "commit.gpgsign=false", "commit", "-qm", "baseline")):
                subprocess.run(["git", "-C", directory, *args], check=True, capture_output=True)
            commit = subprocess.check_output(["git", "-C", directory, "rev-parse", "HEAD"], text=True).strip()
            if case == "records_only":
                for name in ("Tester/reports/new.md", "metadata/modules/fixture.json", "docs/records/new.md"):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("observation\n")
            elif case == "changed_file":
                (root / "Tester/tools/fixture.sh").write_text("echo changed\n")
            elif case == "deleted_directory":
                shutil.rmtree(root / "tools")
            elif case == "new_instrument":
                (root / "Tester/tools/new.sh").write_text("echo new\n")
            elif case == "assume_unchanged":
                subprocess.run(["git", "-C", directory, "update-index", "--assume-unchanged",
                                "Tester/tools/fixture.sh"], check=True, capture_output=True)
                (root / "Tester/tools/fixture.sh").write_text("echo changed\n")
            command = ["bash", str(root / "Tester/tools/instrument_frozen.sh"), "--repo", directory, "--json"]
            if case != "missing_baseline":
                command.extend(["--frozen-commit", commit])
            run = subprocess.run(command, capture_output=True, text=True)
            expected = 0 if case in ("baseline", "records_only") else 1
            try:
                payload = json.loads(run.stdout)
            except (ValueError, TypeError):
                payload = None
            valid_payload = (case == "missing_baseline" or
                             isinstance(payload, dict) and payload.get("frozen") is (expected == 0)
                             and payload.get("frozen_commit") == commit)
            results.append({"case": case, "ok": run.returncode == expected and valid_payload,
                            "expected_exit_code": expected, "exit_code": run.returncode,
                            "payload": payload, "stderr": run.stderr.strip()})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=REPO / "Tester/tools/instrument_frozen.sh")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = check_helper(args.helper.resolve())
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for result in results:
            print(f"[{'PASS' if result['ok'] else 'FAIL'}] {result['case']}: "
                  f"rc={result['exit_code']} expected={result['expected_exit_code']}")
        print(f"仪器冻结夹具：{sum(result['ok'] for result in results)}/{len(results)} 通过")
    return 0 if all(result["ok"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
