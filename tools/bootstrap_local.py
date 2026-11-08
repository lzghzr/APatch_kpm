#!/usr/bin/env python3
"""为克隆出来的仓库建立本地材料骨架（不入库的那些目录）。

仓库按设计不包含 `metadata/`、`docs/records/`、三方 `reports/` 与 `artifacts/`，
因此克隆后无法直接复算身份与交付。本工具只建**目录骨架**与一份可用的
`metadata/identity.json` 起点，并打印仍需自行取得的材料清单。

用法：
    python3 tools/bootstrap_local.py                # 建骨架（已存在的文件不覆盖）
    python3 tools/bootstrap_local.py --submodules   # 顺带执行子模块初始化
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

DIRS = [
    "metadata/modules", "metadata/checks", "metadata/handoffs",
    "docs/records", "docs/proposals",
    "Developer/reports/handoffs", "Developer/reports/responses",
    "Tester/reports/responses", "Auditor/reports",
    "local/build_logs",
]

DOCS = {
    "entry": "docs/README.md",
    "roles": "docs/process/02-roles.md",
    "identity": "docs/process/01-identity.md",
    "round_flow": "docs/process/03-round-flow.md",
    "issue_ticket": "docs/process/04-issue-ticket.md",
    "acceptance": "docs/process/05-maintainer-acceptance.md",
    "antipatterns": "docs/process/06-antipatterns.md",
    "escalation_device": "docs/process/07-escalation-device.md",
    "review_economics": "docs/process/08-review-economics.md",
    "handoff": "docs/process/09-handoff.md",
    "binary_adaptation": "docs/process/10-binary-adaptation.md",
    "coverage": "docs/coverage.md",
}


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


def kernelpatch_commit() -> str | None:
    out = git("ls-tree", "HEAD", "KernelPatch")
    parts = out.split()
    return parts[2] if len(parts) >= 3 and parts[1] == "commit" else None


def main() -> int:
    ap = argparse.ArgumentParser(description="建立本地材料骨架")
    ap.add_argument("--submodules", action="store_true", help="顺带执行 git submodule update --init --recursive")
    args = ap.parse_args()

    os.chdir(REPO)
    created, skipped = [], []

    if args.submodules:
        rc = subprocess.run(["git", "-C", str(REPO), "submodule", "update", "--init", "--recursive"]).returncode
        print(f"子模块初始化：{'完成' if rc == 0 else f'失败（{rc}）'}")

    for rel in DIRS:
        path = REPO / rel
        if path.is_dir():
            skipped.append(rel)
        else:
            path.mkdir(parents=True, exist_ok=True)
            created.append(rel)

    identity_path = REPO / "metadata/identity.json"
    if identity_path.exists():
        print(f"保留现有 metadata/identity.json（未覆盖）")
    else:
        identity = {
            "process": "tri-role-delivery",
            "process_version": "1.1.0",
            "bootstrap": {
                "by": "tools/bootstrap_local.py",
                "note": "本地自建起点：按 docs/process/01-identity.md 补齐 conventions 与平台字段后再复算",
            },
            "docs": DOCS,
            "gate": {
                "entry": "tools/check_repository.py",
                "strict_flag": "--strict",
                "portable_flag": "--portable",
                "checks": [
                    "structure", "ci_build_selection", "doc_links", "metadata_schema", "report_integrity",
                    "identity_hashes", "version_consistency", "acceptance_binding", "delivery_binding",
                    "tool_selftest", "developer_artifacts", "handoff_registration", "auditor_independence",
                    "public_file_hygiene",
                ],
            },
            "platform": {
                "kernelpatch_path": "KernelPatch",
                **({"kernelpatch_commit": kernelpatch_commit()} if kernelpatch_commit() else {}),
                "toolchain_tag": "ndk26.3.11579264",
            },
            "conventions": {},
            "paths": {
                "artifacts_root": "artifacts",
                "module_records": "metadata/modules",
                "auditor_tools": "Auditor/tools",
                "auditor_reports": "Auditor/reports",
                "tester_tools": "Tester/tools",
                "tester_reports": "Tester/reports",
                "developer_reports": "Developer/reports",
            },
            "ownership": {},
        }
        identity_path.write_text(json.dumps(identity, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        created.append("metadata/identity.json")

    print("已创建：" + ("、".join(created) if created else "无"))
    print("已存在保留：" + ("、".join(skipped) if skipped else "无"))
    print()
    print("接下来仍需自行取得（仓库不包含）：")
    print("  1. 候选产物      artifacts/<build_id>#<n>/（或从冻结提交重新构建）")
    print("  2. 构建登记      metadata/modules/<模块>.json（可由 build_candidate.py 新建，或转入交接清单后 import-manifest）")
    print("  3. 裁定与记录    docs/records/（授权、验收、交付回执）")
    print("  4. 审计与实机    Auditor/reports/、Tester/reports/（用于引用与复核）")
    print("  5. 身份约定      metadata/identity.json 的 conventions（按 docs/process/01-identity.md）")
    print()
    print("自检：python3 tools/check_repository.py --portable   # 克隆侧可运行的部分")
    print("      python3 tools/check_repository.py --strict     # 材料齐备后再用")
    return 0


if __name__ == "__main__":
    sys.exit(main())
