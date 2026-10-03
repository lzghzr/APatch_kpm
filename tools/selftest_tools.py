#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""流程工具自检（维护者所有）：把历轮发现过的判据漂移做成常驻回归用夹具。

覆盖的回归项（每一项都来自一次真实发现）：
  1. signature_parity   交付签名判据：门禁与 `verify --profile delivery` 必须一致
                        （True 通过；False / None / 0 / 1 / "true" 都失败）
  2. acceptance_binding 验收指纹与实例不一致 → 门禁必须失败（不是警告）
  3. exploration_delivery 探索记录不能交付（门禁与交付档都失败）
  4. version_history    历史产物按各自构建版本核对：1.x 保留 + 当前升到 2.x 必须通过
  5. identity_conflict  改参数 → 新 Build ID；同 ID 不同指纹 / 同指纹不同产物 → 冲突
  6. cleanup_protection 构建清理必须保护构建输入与已跟踪文件（如模块内的 .s 源码）
  7. incomplete_identity 候选档拒绝：零指纹 / 参数未捕获 / 脏树

用法:
  python3 tools/selftest_tools.py            # 人读输出，失败退出 1
  python3 tools/selftest_tools.py --json     # 机器可读
门禁会把 run_checks() 的结果汇总成 tool_selftest 检查项。
"""

import importlib.util
import json
import os
import shutil
import subprocess
import contextlib
import io
import argparse
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMP_DIRS = []


def make_tmp(prefix="selftest-"):
    path = tempfile.mkdtemp(prefix=prefix)
    TEMP_DIRS.append(path)
    return path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate_repo(record, gate):
    """把门禁的仓库根指向一个临时夹具，返回临时目录。"""
    tmp = make_tmp()
    os.makedirs(os.path.join(tmp, "metadata", "modules"))
    json.dump(record, open(os.path.join(tmp, "metadata", "modules", record["module"] + ".json"), "w"))
    gate.REPO = tmp
    return tmp


def _sample_entry(identity):
    """独立临时仓库夹具：无需本地产物、历史提交或签名密钥。"""
    root = Path(make_tmp("selftest-identity-"))
    (root / "mod").mkdir()
    (root / "mod" / "Makefile").write_text("MYKPM_VERSION := 1.0\n")
    for command in (["init", "-q"], ["add", "."],
                    ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(root)] + command, check=True, capture_output=True)
    identity.REPO = root
    commit = identity.git(["rev-parse", "HEAD"], cwd=root)
    digest = identity.sha256_file(root / "mod" / "Makefile")
    tree = identity.source_tree_sha256_from_files([("mod/Makefile", digest)])
    flags = identity.sha256_bytes(b"fixture compiler arguments")
    bid, fp = identity.build_id_of("mod", "1.0", "base", tree, "fixture", commit, flags)
    artifact = root / "out.kpm"
    artifact.write_bytes(b"fixture artifact bytes")
    entry = {"module": "mod", "version": "1.0", "variant": "base", "kind": "candidate",
             "source_dirty": False, "source_commit": commit, "kernelpatch_commit": commit,
             "build_id": bid, "instance_id": bid + "#1", "toolchain": "fixture",
             "fingerprint_sha256": fp, "source_tree_sha256": tree,
             "sources": [{"path": "mod/Makefile", "sha256": digest, "blob_sha256": digest}],
             "recipe": {"captured": True, "returncode": 0, "dry_run_sha256": flags,
                        "compiler_sha256": identity.sha256_bytes(b"fixture compiler")},
             "artifacts": [{"name": "out.kpm", "path": "out.kpm", "sha256": identity.sha256_file(artifact)}],
             "build_transaction": {"source_commit": commit, "source_tree_sha256": tree,
                                   "kernelpatch_commit": commit, "recipe_sha256": flags,
                                   "input_unchanged": True, "returncode": 0}}
    return entry


def _binding(entry, signature_verified, note="fixture"):
    return {
        "instance_id": entry["instance_id"], "build_id": entry["build_id"],
        "source_commit": entry["source_commit"], "fingerprint_sha256": entry["fingerprint_sha256"],
        "delivery_commit": entry["source_commit"],
        "artifacts": {a["name"]: a["sha256"] for a in entry["artifacts"]},
        "signature_verified": signature_verified, "signature_note": note,
        "bound_by": "selftest", "bound_at": "fixture",
    }


def _run_checks():
    """返回 [(名称, 是否通过, 说明)]；不写任何仓库文件（只用临时目录）。"""
    results = []
    identity = load("selftest_identity", REPO / "tools" / "identity.py")
    gate = load("selftest_gate", REPO / "tools" / "check_repository.py")
    builder = load("selftest_builder", REPO / "tools" / "build_candidate.py")

    # 1) 签名判据一致性
    entry = _sample_entry(identity)
    gate.load_identity_module = lambda: identity
    # 签名枚举测试只模拟校验后端；另用真实无签名提交检查复验拒绝路径。
    real_signature_status = identity.signature_status
    identity.signature_status = lambda sha: (True, "fixture verifier")
    mismatches = []
    for value in (True, False, None, 0, 1, "true"):
        _gate_repo({"module": "re_kernel", "builds": [entry],
                    "deliveries": [_binding(entry, value)]}, gate)
        rep = gate.Report()
        gate.check_delivery_binding(rep)
        gate_ok = not rep.failures
        verify_res = identity.verify_build(entry, profile="delivery",
                                           deliveries=[_binding(entry, value)])
        verify_ok = not verify_res["problems"]
        if gate_ok != verify_ok:
            mismatches.append(f"{value!r}: 门禁{'PASS' if gate_ok else 'FAIL'} vs "
                              f"交付档{'PASS' if verify_ok else 'FAIL'}")
        if value is True and not (gate_ok and verify_ok):
            mismatches.append("True 应当通过")
        if value is not True and (gate_ok or verify_ok):
            mismatches.append(f"{value!r} 应当失败")
    results.append(("signature_parity", not mismatches, "; ".join(mismatches) or "6 种取值两处判据一致"))

    # 2) 验收指纹不一致 → 门禁失败
    bad_entry = dict(entry)
    _gate_repo({"module": "re_kernel", "builds": [bad_entry],
                "acceptance": {"instance_id": entry["instance_id"], "source_commit": entry["source_commit"],
                               "fingerprint_sha256": "0" * 64,
                               "artifacts": {a["name"]: a["sha256"] for a in entry["artifacts"]},
                               "accepted_by": "selftest", "accepted_at": "fixture"}}, gate)
    rep = gate.Report()
    gate.check_acceptance(rep)
    results.append(("acceptance_binding", bool(rep.failures), "; ".join(rep.failures) or "未失败（异常）"))

    # 3) 探索记录不能交付
    exploration = dict(entry)
    exploration["kind"] = "exploration"
    _gate_repo({"module": "re_kernel", "builds": [exploration],
                "deliveries": [_binding(exploration, True)]}, gate)
    rep = gate.Report()
    gate.check_delivery_binding(rep)
    verify_res = identity.verify_build(exploration, profile="delivery",
                                       deliveries=[_binding(exploration, True)])
    ok = bool(rep.failures) and bool(verify_res["problems"])
    results.append(("exploration_delivery", ok,
                    "两处都失败" if ok else f"门禁={'FAIL' if rep.failures else 'PASS'} "
                                            f"交付档={'FAIL' if verify_res['problems'] else 'PASS'}"))

    # 4) 版本历史：1.x 保留 + 当前 2.x
    record = {
        "module": "mod", "version_declared": "2.0", "version_sources": {"makefile": "2.0", "readme_heading": "2.0"},
        "builds": [
            {"instance_id": "b1", "version": "1.0",
             "artifacts": [{"name": "a.kpm", "embedded": {"name": "mod", "version": "1.0"}}]},
            {"instance_id": "b2", "version": "2.0",
             "artifacts": [{"name": "b.kpm", "embedded": {"name": "mod", "version": "2.0"}}]},
        ],
    }
    tmp = _gate_repo(record, gate)
    os.makedirs(os.path.join(tmp, "mod"))
    open(os.path.join(tmp, "mod", "Makefile"), "w").write("MYKPM_VERSION := 2.0\n")
    rep = gate.Report()
    gate.check_version_consistency(rep)
    ok_bump = not rep.failures
    bad = json.loads(json.dumps(record))
    bad["builds"][0]["artifacts"][0]["embedded"]["version"] = "1.5"
    tmp_bad = _gate_repo(bad, gate)
    os.makedirs(os.path.join(tmp_bad, "mod"), exist_ok=True)
    open(os.path.join(tmp_bad, "mod", "Makefile"), "w").write("MYKPM_VERSION := 2.0\n")
    rep_bad = gate.Report()
    gate.check_version_consistency(rep_bad)
    ok = ok_bump and bool(rep_bad.failures)
    results.append(("version_history", ok,
                    f"升级通过={ok_bump}，产物与自身版本不符被拒={bool(rep_bad.failures)}"))

    # 5) 身份冲突判定
    tree = "267bfa1c2efcc7548b89d631d4952defaf7161fe8d33efb6db75fdc9b648f90f"
    id_a, fp_a = identity.build_id_of("re_kernel", "8.0.0", "base", tree, "tag", "b51197aaba8f", "aaaa")
    id_b, fp_b = identity.build_id_of("re_kernel", "8.0.0", "base", tree, "tag", "b51197aaba8f", "bbbb")
    existing = [{"build_id": id_a, "fingerprint_sha256": fp_a,
                 "artifacts": [{"name": "x.kpm", "sha256": "1" * 64}]}]
    same_id_diff_fp = identity.conflict_reason(existing, {"build_id": id_a, "fingerprint_sha256": fp_b,
                                                         "artifacts": [{"name": "x.kpm", "sha256": "1" * 64}]})
    same_fp_diff_art = identity.conflict_reason(existing, {"build_id": id_b, "fingerprint_sha256": fp_a,
                                                          "artifacts": [{"name": "x.kpm", "sha256": "2" * 64}]})
    ok = id_a != id_b and bool(same_id_diff_fp) and bool(same_fp_diff_art)
    results.append(("identity_conflict", ok,
                    f"参数变化换 ID={id_a != id_b}，同 ID 不同指纹被拒={bool(same_id_diff_fp)}，"
                    f"同指纹不同产物被拒={bool(same_fp_diff_art)}"))

    # 6) 清理保护
    tmp = Path(make_tmp(prefix="selftest-clean-"))
    for name in ("helper.s", "main.o", "out.kpm", "gen.s"):
        (tmp / name).write_text(name)
    to_move, skipped = builder.plan_cleanup(tmp, {"helper.s"})
    moved = {p.name for p in to_move}
    ok = skipped == ["helper.s"] and "helper.s" not in moved and {"main.o", "out.kpm"}.issubset(moved)
    results.append(("cleanup_protection", ok, f"移动={sorted(moved)} 保护={skipped}"))

    # 7) 不完整身份在候选档被拒
    cases = {}
    tampered = dict(entry, fingerprint_sha256="0" * 64)
    cases["零指纹"] = bool(identity.verify_build(tampered, profile="candidate")["problems"])
    no_recipe = dict(entry, recipe={"captured": False, "note": "fixture"})
    cases["参数未捕获"] = bool(identity.verify_build(no_recipe, profile="candidate")["problems"])
    dirty = dict(entry, source_dirty=True)
    cases["脏树"] = bool(identity.verify_build(dirty, profile="candidate")["problems"])
    results.append(("incomplete_identity", all(cases.values()), str(cases)))

    # 8) 审计报告来源声明：引用维护方脚本必须写「仅用于定位」
    tmp = Path(make_tmp(prefix="selftest-reports-"))
    os.makedirs(tmp / "Auditor" / "reports", exist_ok=True)
    (tmp / "Auditor" / "reports" / "bad.md").write_text("我用 tools/identity.py 的哈希作为依据。\n", encoding="utf-8")
    gate.REPO = str(tmp)
    rep = gate.Report()
    gate.check_auditor_report_sources(rep)
    caught = bool(rep.failures) or any(status == "WARN" for _n, status, _d in rep.checks)
    (tmp / "Auditor" / "reports" / "bad.md").write_text(
        "运行过 tools/identity.py，**仅用于定位，未作依据**。\n", encoding="utf-8")
    rep2 = gate.Report()
    gate.check_auditor_report_sources(rep2)
    clean = not rep2.failures and all(status == "PASS" for _n, status, _d in rep2.checks)
    results.append(("auditor_report_sources", caught and clean,
                    f"未声明被扣={caught}，声明「仅用于定位」后通过={clean}"))

    # 9) 镜像不含 kallsyms → SKIP（不是 FAIL）
    harness_dir = REPO / "kernel_img" / "offset_harness"
    sys.path.insert(0, str(harness_dir))
    try:
        import importlib
        runner = importlib.import_module("run")
        kernel_image = importlib.import_module("kernel_image")
        blank = kernel_image.KernelImage(b"\x00" * 0x1000, "<fixture>")
        out_dir = Path(make_tmp(prefix="selftest-skip-"))
        ks, source, notes = runner.select_symbols("fixture", blank, [], out_dir)
        ok = ks is None and source == "no-kallsyms"
        detail = f"select_symbols -> {source!r}（应为 'no-kallsyms'）"
    except Exception as exc:
        ok, detail = False, f"无法验证: {exc}"
    finally:
        if str(harness_dir) in sys.path:
            sys.path.remove(str(harness_dir))
    results.append(("harness_no_kallsyms_skip", ok, detail))

    # 10) 冻结检查的枚举与分类（AUD-014 回归）
    freeze = load("selftest_freeze", REPO / "tools" / "freeze_check.py")
    cases = {
        "模块源码未跟踪": freeze.classify_untracked(["fixture_module/main.c"], {"fixture_module"})[0],
        "运行期锁文件未忽略": freeze.classify_untracked(["metadata/modules/.re_kernel.lock"], set())[0],
        "流程文件未跟踪": freeze.classify_untracked(["docs/new.md"], set())[0],
        "白名单外路径": freeze.classify_untracked(["weird_top/data.bin"], set())[0],
    }
    expect = {"模块源码未跟踪": "模块源码", "运行期锁文件未忽略": "运行期文件",
              "流程文件未跟踪": "流程/源码", "白名单外路径": "白名单"}
    bad = [name for name, blocking in cases.items() if not blocking or expect[name] not in blocking[0]]
    lock_body = (REPO / "tools" / "identity.py").read_text(encoding="utf-8").split("def module_lock")[1][:400]
    lock_outside_metadata = '"local"' in lock_body
    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    ok = not bad and lock_outside_metadata and "*.lock" in gitignore
    results.append(("freeze_check_classification", ok,
                    f"分类错误={bad or '无'}；锁文件在 local/={lock_outside_metadata}；"
                    f".gitignore 含 *.lock={'*.lock' in gitignore}"))

    # 11) 实机报告身份串：未登记的构建身份要被点名（TST-009 回归）
    instance_id = entry["instance_id"]
    tmp = Path(make_tmp(prefix="selftest-tester-"))
    os.makedirs(tmp / "Tester" / "reports", exist_ok=True)
    os.makedirs(tmp / "metadata" / "modules", exist_ok=True)
    json.dump({"module": "re_kernel", "builds": [{"instance_id": instance_id,
                                                 "build_id": entry["build_id"],
                                                 "build_id_aliases": entry.get("build_id_aliases", [])}]},
              open(tmp / "metadata" / "modules" / "re_kernel.json", "w"))
    report = tmp / "Tester" / "reports" / "run.md"
    report.write_text("实测对象：re_kernel-8.0.0+gdeadbeefcafe.ndk26.3.11579264\n", encoding="utf-8")
    gate.REPO = str(tmp)
    rep = gate.Report()
    gate.check_tester_report_identity(rep)
    caught = any(status == "WARN" for _n, status, _d in rep.checks)
    report.write_text(f"实测对象：{instance_id}\n", encoding="utf-8")
    rep2 = gate.Report()
    gate.check_tester_report_identity(rep2)
    clean = all(status == "PASS" for _n, status, _d in rep2.checks)
    results.append(("tester_report_identity", caught and clean,
                    f"未登记身份被点名={caught}，改用 instance_id 后通过={clean}"))

    # 12) Tester 脚本：看门狗返回码不得被管道吞掉（T7/T8 回归）+ C4 基线在场
    run_test = (REPO / "Tester" / "tools" / "run_test.sh").read_text(encoding="utf-8")
    preflight = (REPO / "Tester" / "tools" / "preflight.sh").read_text(encoding="utf-8")
    selftest_sh = (REPO / "Tester" / "tools" / "selftest_scripts.sh").read_text(encoding="utf-8")
    def _real_pipe(line):
        # `||` / `|&` 不是管道；只有真正的 `| cmd` 才会吞掉看门狗返回码
        return "|" in line.replace("||", "").replace("|&", "")

    piped_watchdog = [ln.strip() for ln in run_test.splitlines()
                      if "run_to" in ln and _real_pipe(ln) and not ln.strip().startswith("#")]
    checks = {
        "timed_out 双保险": "timed_out()" in run_test and "-ge 128" in run_test,
        "无 run_to 管道": not piped_watchdog,
        "C4 基线四项": all(key in preflight for key in ("boot_id", "uptime", "pstore", "module list")),
        "无响应→90 回归": "90" in selftest_sh and "无响应" in selftest_sh,
    }
    ok = all(checks.values())
    results.append(("tester_watchdog_semantics", ok,
                    "; ".join(f"{k}={'OK' if v else '缺失'}" for k, v in checks.items())
                    + (f"; 管道行={piped_watchdog[:1]}" if piped_watchdog else "")))

    # 13) 真实无签名提交必须被复验拒绝，即使记录写着 true。
    identity.signature_status = real_signature_status
    refused = bool(identity.delivery_problems(entry, _binding(entry, True)))
    identity.signature_status = lambda sha: (True, "fixture verifier")
    results.append(("signature_reverification", refused, "真实无签名临时提交被拒"))

    # 14) 祖先关系不够：后续提交修改模块输入或增加文件必须拒绝。
    root = identity.REPO
    (root / "mod" / "extra.h").write_text("fixture added input\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "changed input"], check=True, capture_output=True)
    changed = identity.git(["rev-parse", "HEAD"], cwd=root)
    binding = dict(_binding(entry, True), delivery_commit=changed)
    refused = bool(identity.delivery_problems(entry, binding))
    bad_source = dict(_binding(entry, True), source_commit=changed)
    refused_source = bool(identity.delivery_problems(entry, bad_source))
    results.append(("delivery_source_binding", refused and refused_source,
                    f"新增输入被拒={refused}，伪造源码绑定被拒={refused_source}"))

    # 15) 缺失/伪布尔值、缺事务、探索对象在候选档不能通过。
    cases = []
    for captured in (None, 0, 1, "true"):
        recipe = dict(entry["recipe"], captured=captured)
        cases.append(bool(identity.verify_build(dict(entry, recipe=recipe), profile="candidate")["problems"]))
    for returncode in (None, False, 1):
        recipe = dict(entry["recipe"], returncode=returncode)
        cases.append(bool(identity.verify_build(dict(entry, recipe=recipe), profile="candidate")["problems"]))
    for dirty in (None, 0, "false"):
        cases.append(bool(identity.verify_build(dict(entry, source_dirty=dirty), profile="candidate")["problems"]))
    for bad in (dict(entry, build_transaction=None), dict(entry, kind="exploration")):
        cases.append(bool(identity.verify_build(bad, profile="candidate")["problems"]))
    results.append(("candidate_strict_fields", all(cases), f"{sum(cases)}/{len(cases)} 非法身份被拒"))

    # 16) 不存在的实例号与带后缀的近似身份不能借用已登记前缀。
    tmp = _gate_repo({"module": "mod", "builds": [entry]}, gate)
    report_dir = Path(tmp) / "Tester" / "reports"
    report_dir.mkdir(parents=True)
    caught = []
    for token in (entry["build_id"] + "#999", entry["build_id"] + ".unexpected"):
        (report_dir / "run.md").write_text(token)
        rep = gate.Report()
        gate.check_tester_report_identity(rep)
        caught.append(any(status != "PASS" for _, status, _ in rep.checks))
    results.append(("report_instance_exact", all(caught), "未登记实例与近似前缀均被点名"))

    # 17) record 只追加 builds，保持维护者字段与旧实例原样。
    module_dir = root / "mod"
    module_dir.joinpath("mod_1.0.kpm").write_bytes(b"fixture bytes")
    record = {"module": "mod", "status": "accepted", "version_declared": "old",
              "version_sources": {"makefile": "old"}, "builds": [entry],
              "audits": [{"verdict": "fixture"}], "issues": []}
    (root / "metadata" / "modules").mkdir(parents=True)
    (root / "metadata" / "modules" / "mod.json").write_text(json.dumps(record))
    identity.artifact_facts = lambda path: {"name": path.name, "sha256": identity.sha256_file(path)}
    identity.capture_build_recipe = lambda *args: dict(entry["recipe"])
    identity.build_entry = lambda *args, **kwargs: dict(entry, build_id="fixture-new", fingerprint_sha256="a" * 64)
    args = argparse.Namespace(module="mod", variant=None, toolchain="fixture", by="Developer",
                              kind="exploration", build_cmd=None, env=None, extra_input=None,
                              expect_source_tree=None, handoff=None, new_instance=True, no_archive=True)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = identity.record_locked(args)
    after = json.loads((root / "metadata" / "modules" / "mod.json").read_text())
    unchanged = all(after[k] == v for k, v in record.items() if k != "builds")
    unchanged = unchanged and after["builds"][:-1] == record["builds"] and len(after["builds"]) == 2
    results.append(("record_write_scope", rc == 0 and unchanged, "维护者字段与旧实例保持一致"))

    # 18) 实际运行统一入口：临时工具链构建两次，归档实例不同，输入变更被拒。
    root = Path(make_tmp("selftest-builder-"))
    for name in ("tools", "mod", "metadata/modules", "KernelPatch"):
        (root / name).mkdir(parents=True)
    for name in ("identity.py", "build_candidate.py"):
        shutil.copy2(REPO / "tools" / name, root / "tools" / name)
    (root / ".gitignore").write_text("*.kpm\nlocal/\nartifacts/\nKernelPatch/\n__pycache__/\n")
    names = b"\x00.shstrtab\x00.kpm.info\x00"
    info = b"name=mod\x00version=1.0\x00"
    elf = bytearray(64 + 3 * 64)
    elf[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", elf, 0x28, 64)
    struct.pack_into("<HHH", elf, 0x3A, 64, 3, 1)
    struct.pack_into("<I", elf, 128, 1)
    struct.pack_into("<QQ", elf, 128 + 0x18, len(elf), len(names))
    struct.pack_into("<I", elf, 192, 11)
    struct.pack_into("<QQ", elf, 192 + 0x18, len(elf) + len(names), len(info))
    (root / "payload.bin").write_bytes(elf + names + info)
    compiler = root / "mock-clang"
    compiler.write_text(f"#!/bin/sh\ncp {root}/payload.bin mod_1.0.kpm\n")
    compiler.chmod(0o755)
    (root / "mod" / "Makefile").write_text(
        f"MYKPM_VERSION := 1.0\nall:\n\t{compiler} -o mod_1.0.kpm\n")
    (root / "metadata/modules/mod.json").write_text(json.dumps({
        "module": "mod", "status": "candidate", "version_declared": "1.0",
        "version_sources": {}, "builds": [], "audits": [], "device_tests": [], "issues": []}))

    def fixture_commit(directory, message):
        subprocess.run(["git", "-C", str(directory), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(directory), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "--allow-empty", "-qm", message], check=True, capture_output=True)

    for directory in (root, root / "KernelPatch"):
        subprocess.run(["git", "-C", str(directory), "init", "-q"], check=True, capture_output=True)
    (root / "KernelPatch" / "fixture.h").write_text("fixture dependency\n")
    fixture_commit(root / "KernelPatch", "dependency")
    fixture_commit(root, "inputs")
    command = [sys.executable, str(root / "tools/build_candidate.py"), "mod", "--toolchain", "fixture",
               "--extra-input", "payload.bin"]
    first = subprocess.run(command, cwd=root, capture_output=True, text=True)
    fixture_commit(root, "first registration")
    second = subprocess.run(command, cwd=root, capture_output=True, text=True)
    registered = json.loads((root / "metadata/modules/mod.json").read_text())["builds"]
    repeated = (first.returncode == second.returncode == 0 and len(registered) == 2
                and registered[0]["instance_id"] != registered[1]["instance_id"])
    fixture_commit(root, "second registration")
    compiler.write_text(f"#!/bin/sh\ncp {root}/payload.bin mod_1.0.kpm\nprintf 'generated input' > new.h\n")
    fixture_commit(root, "compiler changes inputs")
    rejected = subprocess.run(command, cwd=root, capture_output=True, text=True)
    unchanged_count = len(json.loads((root / "metadata/modules/mod.json").read_text())["builds"]) == 2
    results.append(("candidate_build_transaction", repeated and rejected.returncode != 0 and unchanged_count,
                    f"两次构建新实例={repeated}，输入变更拒绝登记={rejected.returncode != 0 and unchanged_count}"
                    + ("；" + (first.stderr + second.stderr)[-500:] if not repeated else "")))

    # 19) 验收数组逐条核验；历史单项与新增数组同时保留。
    acceptance = {"instance_id": entry["instance_id"], "source_commit": entry["source_commit"],
                  "fingerprint_sha256": entry["fingerprint_sha256"],
                  "artifacts": identity.artifact_map(entry), "accepted_by": "fixture", "accepted_at": "fixture"}
    record = {"module": "mod", "builds": [entry], "acceptance": acceptance,
              "acceptances": [dict(acceptance)]}
    _gate_repo(record, gate)
    good = gate.Report()
    gate.check_acceptance(good)
    record["acceptances"][0]["fingerprint_sha256"] = "0" * 64
    _gate_repo(record, gate)
    bad = gate.Report()
    gate.check_acceptance(bad)
    results.append(("acceptance_append_history", not good.failures and bool(bad.failures),
                    "历史单项与追加数组一起核验，数组中的错误绑定被拒"))

    # 20) 工具修复响应独立分类；实机报告与审计来源断言仍然生效。
    tmp = Path(make_tmp("selftest-response-"))
    gate.REPO = str(tmp)
    for folder in ("Tester/reports/responses", "Tester/reports/runs", "Auditor/reports/responses"):
        (tmp / folder).mkdir(parents=True)
    response = tmp / "Tester/reports/responses/fixture.md"
    response.write_text("问题编号 MNT-008\n修复工具 commit 待冻结\n冻结状态 未冻结\n工具 SHA-256 fixture\n"
                        "修复 fixture\n证据 fixture\n验证层级 mock\n未覆盖 真机\n复核请求 维护者\n")
    (tmp / "Tester/reports/runs/device.md").write_text("\n".join(gate.TESTER_REPORT_REQUIRED))
    (tmp / "Auditor/reports/report.md").write_text("\n".join(gate.AUDITOR_REPORT_REQUIRED))
    good = gate.Report()
    gate.check_report_conformance(good)
    gate.check_tester_responses(good)
    gate.check_tester_report_identity(good)
    with response.open("a") as stream:
        stream.write("被测产物 instance_id=mod+gabcdefabcdef#999\n")
    response_identity = gate.Report()
    gate.check_tester_report_identity(response_identity)
    (tmp / "metadata/modules").mkdir(parents=True)
    (tmp / "metadata/modules/mod.json").write_text(json.dumps({"builds": [{"instance_id": "mod+gabcdefabcdef#1"}]}))
    response.write_text(response.read_text().replace("mod+gabcdefabcdef#999", "mod+gabcdefabcdef#1"))
    registered_response = gate.Report()
    gate.check_tester_report_identity(registered_response)
    response.write_text("问题编号 MNT-008\n修复 fixture\n")
    malformed = gate.Report()
    gate.check_tester_responses(malformed)
    (tmp / "Tester/reports/runs/device.md").write_text("missing device fields\nmod+gabcdefabcdef#999\n")
    device = gate.Report()
    gate.check_report_conformance(device)
    gate.check_tester_report_identity(device)
    (tmp / "Auditor/reports/responses/fixture.md").write_text("依据 tools/identity.py 输出结论\n")
    auditor = gate.Report()
    gate.check_auditor_report_sources(auditor)
    results.append(("tester_response_classification",
                    not good.warnings and bool(malformed.warnings) and len(device.warnings) == 2
                    and bool(auditor.warnings) and bool(response_identity.warnings) and not registered_response.warnings,
                    "纯工具响应按工具字段检查；响应与实机报告的未登记产物身份、缺字段和同源审计依据均被检出"))

    # 21) 已迁移模块保留历史身份：从冻结提交核对旧注册名，现行模块继续严格同名。
    archived = {"module": "old_mod", "status": "archived", "superseded_by": "new_mod",
                "version_declared": "1.0", "version_sources": {},
                "builds": [{"version": "1.0", "instance_id": "old#1",
                            "sources": [{"path": "old_mod/main.c"}],
                            "artifacts": [{"name": "old.kpm", "embedded": {
                                "name": "old_runtime", "version": "1.0"}}]}]}
    tmp = Path(_gate_repo(archived, gate))
    (tmp / "old_mod").mkdir()
    (tmp / "old_mod/main.c").write_text('KPM_NAME("old_runtime");\n')
    for command in (["init", "-q"], ["add", "old_mod"],
                    ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "-qm", "historical module"]):
        subprocess.run(["git", "-C", str(tmp)] + command, check=True, capture_output=True)
    archived["builds"][0]["source_commit"] = subprocess.check_output(
        ["git", "-C", str(tmp), "rev-parse", "HEAD"], text=True).strip()
    shutil.rmtree(tmp / "old_mod")
    (tmp / "new_mod").mkdir()
    (tmp / "new_mod/Makefile").write_text("MYKPM_VERSION := 2.0\n")
    (tmp / "metadata/modules/new_mod.json").write_text(json.dumps({
        "module": "new_mod", "version_declared": "2.0", "builds": []}))
    def archived_check(value):
        (tmp / "metadata/modules/old_mod.json").write_text(json.dumps(value))
        report = gate.Report()
        gate.check_version_consistency(report)
        return not report.failures
    accepted = archived_check(archived)
    rejected = {}
    for label, mutate in (
        ("错误历史注册名", lambda v: v["builds"][0]["artifacts"][0]["embedded"].update(name="forged")),
        ("历史提交不可读", lambda v: v["builds"][0].update(source_commit="0" * 40)),
        ("缺少替代模块", lambda v: v.update(superseded_by="missing")),
        ("现行模块同名断言", lambda v: v.update(status="candidate")),
    ):
        bad = json.loads(json.dumps(archived))
        mutate(bad)
        rejected[label] = not archived_check(bad)
    (tmp / "old_mod").mkdir()
    rejected["归档目录仍在场"] = not archived_check(archived)
    results.append(("archived_module_name", accepted and all(rejected.values()),
                    f"历史冻结注册名通过={accepted}；反例拒绝={rejected}"))

    return results


def run_checks():
    try:
        return _run_checks()
    finally:
        for path in TEMP_DIRS:
            shutil.rmtree(path, ignore_errors=True)
        TEMP_DIRS.clear()


def main():
    results = run_checks()
    if "--json" in sys.argv:
        print(json.dumps([{"name": n, "ok": ok, "detail": d} for n, ok, d in results],
                         ensure_ascii=False, indent=2))
    else:
        for name, ok, detail in results:
            print(f"[{'PASS' if ok else 'FAIL'}] {name:22s} {detail}")
        failed = [n for n, ok, _ in results if not ok]
        print(f"\n工具自检：{len(results) - len(failed)}/{len(results)} 通过")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
