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


def _schema_repo(record, gate):
    """元数据门禁夹具：合法 identity.json（去掉 docs 路径）+ 模块记录 + 可解析的提交标识。"""
    tmp = make_tmp()
    os.makedirs(os.path.join(tmp, "metadata", "modules"))
    payload = json.load(open(REPO / "metadata" / "identity.json", encoding="utf-8"))
    payload.pop("docs", None)
    json.dump(payload, open(os.path.join(tmp, "metadata", "identity.json"), "w"))
    env = ["-c", "user.name=F", "-c", "user.email=f@example.invalid", "-c", "commit.gpgsign=false"]
    shas = []
    for sub in ("", "KernelPatch"):
        repo = os.path.join(tmp, sub)
        os.makedirs(repo, exist_ok=True)
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True, capture_output=True)
        open(os.path.join(repo, "f.txt"), "w").write("x")
        subprocess.run(["git", "-C", repo, "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo] + env + ["commit", "-qm", "i"], check=True, capture_output=True)
        shas.append(subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                   capture_output=True, text=True).stdout.strip())
    if record is not None:
        json.dump(record, open(os.path.join(tmp, "metadata", "modules", record["module"] + ".json"), "w"))
    gate.REPO = tmp
    return tmp, shas[0], shas[1]


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

    # 4b) 版本声明滞后 vs 事实矛盾：滞后只在提示（交接前在途），矛盾必须失败
    def version_case(declared, makefile, build_versions):
        record = {"module": "vermod", "version_declared": declared,
                  "version_sources": {"makefile": declared, "readme_heading": declared},
                  "builds": [{"instance_id": f"b{i}", "version": v,
                              "artifacts": [{"name": f"a{i}.kpm", "embedded": {"name": "vermod", "version": v}}]}
                             for i, v in enumerate(build_versions)]}
        tmp = _gate_repo(record, gate)
        os.makedirs(os.path.join(tmp, "vermod"), exist_ok=True)
        open(os.path.join(tmp, "vermod", "Makefile"), "w").write(f"MYKPM_VERSION := {makefile}\n")
        rep = gate.Report()
        gate.check_version_consistency(rep)
        return not rep.failures

    version_cases = {
        "源码升版、声明滞后（在途）通过": version_case("2.0", "3.0", ["2.0"]),
        "声明高于源码被拒": not version_case("3.0", "2.0", ["2.0"]),
        "新版本已登记构建却未同步声明被拒": not version_case("3.0", "4.0", ["3.0", "4.0"]),
    }
    results.append(("version_declared_lag", all(version_cases.values()), str(version_cases)))

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
    # 14b) 压平历史：交付提交与源码提交无祖先关系，但内容逐字节一致 → 接受（只记录 source_ancestor）
    tree = identity.git(["rev-parse", f"{entry['source_commit']}^{{tree}}"], cwd=root)
    flat = identity.git(["commit-tree", tree, "-m", "flattened export"], cwd=root)
    flat_binding = dict(_binding(entry, True), delivery_commit=flat)
    problems = identity.delivery_problems(entry, flat_binding)
    accepted = not problems and flat_binding.get("source_ancestor") is False
    results.append(("delivery_flattened_history", refused and refused_source and accepted,
                    f"新增输入被拒={refused}，伪造源码绑定被拒={refused_source}，"
                    f"内容一致但非祖先被接受={accepted}"))

    # 14c) DEV-031：模块目录在两侧都不存在时，两次查询失败不得被当成「内容相等」
    ghost = dict(entry, module="ghost_mod")
    ghost_problems = identity.delivery_problems(ghost, _binding(ghost, True))
    ghost_rejected = any("不存在模块目录" in p for p in ghost_problems)
    results.append(("delivery_missing_module", ghost_rejected,
                    f"缺模块被拒={ghost_rejected}；{ghost_problems[:1]}"))

    # 14d) 交接清单 schema：候选清单用 builds[]，只交派生件的清单用 binary_ports[]；
    #      两者都必须带 module/handoff_by/handoff_at，且 payload 不得为空
    import tempfile as _tf
    tmp = Path(_tf.mkdtemp())
    hod = tmp / "Developer" / "reports" / "handoffs"
    hod.mkdir(parents=True)
    base = {"module": "mod", "handoff_by": "Developer", "handoff_at": "2026-01-01T00:00:00Z"}
    (hod / "candidate.json").write_text(json.dumps(dict(base, builds=[{"instance_id": "x"}])), encoding="utf-8")
    (hod / "ports.json").write_text(json.dumps(dict(base, binary_ports=[{"derived": {"name": "a.kpm"}}])), encoding="utf-8")
    saved = gate.REPO
    gate.REPO = str(tmp)
    rep_ok = gate.Report()
    gate.check_developer_artifacts(rep_ok)
    positives_ok = not rep_ok.failures and not rep_ok.warnings
    # 负例：缺 handoff_by/handoff_at，且 payload 为空 → 必须拒绝
    (hod / "bad.json").write_text(json.dumps({"module": "mod", "builds": []}), encoding="utf-8")
    rep_bad = gate.Report()
    gate.check_developer_artifacts(rep_bad)          # 该判据为软判据：缺字段报 WARN
    negative_rejected = bool(rep_bad.warnings or rep_bad.failures)
    gate.REPO = saved
    results.append(("handoff_payload_schema", positives_ok and negative_rejected,
                    f"候选与派生件清单被接受={positives_ok}，缺字段/空 payload 被提示={negative_rejected}"))

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

    # 22) identity_tokens：结构化提交字段必须可解析（本轮 MNT-014 的笔误回归）
    root = Path(make_tmp(prefix="selftest-tokens-"))
    (root / "metadata" / "modules").mkdir(parents=True)
    (root / "KernelPatch").mkdir()
    for repo in (root, root / "KernelPatch"):
        for command in (["init", "-q"], ["add", "-A"],
                        ["-c", "user.name=F", "-c", "user.email=f@example.invalid",
                         "-c", "commit.gpgsign=false", "commit", "-qm", "fixture", "--allow-empty"]):
            subprocess.run(["git", "-C", str(repo)] + command, check=True, capture_output=True)
    main_commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                 capture_output=True, text=True).stdout.strip()
    kp_commit = subprocess.run(["git", "-C", str(root / "KernelPatch"), "rev-parse", "HEAD"],
                               capture_output=True, text=True).stdout.strip()
    tokens_path = root / "metadata" / "modules" / "token_mod.json"

    def tokens_check(source_commit, kernelpatch_commit):
        tokens_path.write_text(json.dumps({"module": "token_mod", "source_commit": source_commit,
                                           "kernelpatch_commit": kernelpatch_commit}))
        gate.REPO = str(root)
        problems, _checked = gate.identity_token_problems()
        return not problems
    token_cases = {
        "真实提交通过": tokens_check(main_commit, kp_commit),
        "本仓不存在提交被拒": not tokens_check("deadbeef" + "0" * 32, kp_commit),
        "子模块不存在提交被拒": not tokens_check(main_commit, "deadbeef" + "0" * 32),
        "非十六进制被拒": not tokens_check("b51197aba", kp_commit),
    }
    results.append(("identity_tokens", all(token_cases.values()), str(token_cases)))

    # 23) report_versions：原文只追加 + 追加登记 + 索引哈希须为已知版本
    root = Path(make_tmp(prefix="selftest-reportver-"))
    (root / "metadata" / "modules").mkdir(parents=True)
    (root / "Auditor" / "reports").mkdir(parents=True)
    report = root / "Auditor" / "reports" / "r.md"
    report.write_text("base content\n", encoding="utf-8")
    for command in (["init", "-q"], ["add", "-A"],
                    ["-c", "user.name=F", "-c", "user.email=f@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(root)] + command, check=True, capture_output=True)
    base_commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                 capture_output=True, text=True).stdout.strip()
    import hashlib as _hashlib
    base_bytes = report.read_bytes()
    base_sha = _hashlib.sha256(base_bytes).hexdigest()
    report.write_text("base content\nappended section\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=F", "-c", "user.email=f@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "append"], check=True, capture_output=True)
    append_commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                   capture_output=True, text=True).stdout.strip()
    current_bytes = report.read_bytes()
    current_sha = _hashlib.sha256(current_bytes).hexdigest()
    added_sha = _hashlib.sha256(current_bytes[len(base_bytes):]).hexdigest()
    versions_path = root / "metadata" / "modules" / "ver_mod.json"
    good_record = {
        "module": "ver_mod",
        "audits": [{"report": "Auditor/reports/r.md", "report_sha256": current_sha}],
        "report_versions": [{
            "path": "Auditor/reports/r.md",
            "append_only_baseline": {"sha256": base_sha, "size": len(base_bytes), "commit": base_commit},
            "versions": [{"sha256": base_sha, "size": len(base_bytes), "commit": base_commit},
                         {"sha256": current_sha, "size": len(current_bytes), "commit": append_commit,
                          "added_sha256": added_sha, "added_size": len(current_bytes) - len(base_bytes)}]}]}

    def versions_check(record, mutate=None, report_bytes=None):
        report.write_bytes(report_bytes if report_bytes is not None else current_bytes)
        data = json.loads(json.dumps(record))
        if mutate:
            mutate(data)
        versions_path.write_text(json.dumps(data))
        gate.REPO = str(root)
        rep = gate.Report()
        gate.check_report_integrity(rep, strict=True)
        return not rep.failures
    version_cases = {
        "纯追加版本通过": versions_check(good_record),
        "未登记的追加被拒": not versions_check(good_record, lambda r: r["report_versions"][0]["versions"].pop()),
        "改写原文前缀被拒": not versions_check(good_record, report_bytes=b"tampered content\nappended section\n"),
        "索引哈希非已知版本被拒": not versions_check(
            good_record, lambda r: r["audits"][0].update(report_sha256="0" * 64)),
    }
    report.write_bytes(current_bytes)
    results.append(("report_versions", all(version_cases.values()), str(version_cases)))

    # 24) referenced_reports_archived：先入库再引用（常规提示 / 严格失败）
    committed = root / "Auditor" / "reports" / "committed.md"
    committed.write_text("committed report\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=F", "-c", "user.email=f@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "report"], check=True, capture_output=True)
    (root / "Auditor" / "reports" / "uncommitted.md").write_text("not committed\n", encoding="utf-8")

    def archived_check_refs(tracked_only):
        record = {"module": "ref_mod",
                  "audits": [{"report": "Auditor/reports/committed.md"}]}
        if not tracked_only:
            record["audits"].append({"report": "Auditor/reports/uncommitted.md"})
        versions_path.write_text(json.dumps(record))
        gate.REPO = str(root)
        rep = gate.Report()
        gate.check_report_integrity(rep, strict=True)
        return not rep.failures
    # 构建输入（含子模块内与历史已移动路径）不是报告引用，不得据此判失败
    versions_path.write_text(json.dumps({"module": "ref_mod", "audits": [{"report": "Auditor/reports/committed.md"}],
                                         "builds": [{"sources": [{"path": "mod/upstream/zstd/CMakeLists.txt"},
                                                                 {"path": "mod/moved-away.json"}]}]}))
    gate.REPO = str(root)
    rep_src = gate.Report()
    gate.check_report_integrity(rep_src, strict=True)
    ref_cases = {"已入库引用通过": archived_check_refs(True),
                 "未入库引用在严格模式失败": not archived_check_refs(False),
                 "构建输入路径不误报": not rep_src.failures}
    gate.REPO = str(root)
    rep_warn = gate.Report()
    versions_path.write_text(json.dumps({"module": "ref_mod", "audits": [
        {"report": "Auditor/reports/committed.md"}, {"report": "Auditor/reports/uncommitted.md"}]}))
    gate.check_report_integrity(rep_warn, strict=False)
    ref_cases["常规模式仅提示"] = (not rep_warn.failures and bool(rep_warn.warnings))
    results.append(("referenced_reports_archived", all(ref_cases.values()), str(ref_cases)))

    # 25) report_version_commits：交接即提交（历史版本必须引用提交）
    def commits_check(with_pending=True, drop_history=False, mutate=None, strict=True):
        data = json.loads(json.dumps(good_record))
        versions = data["report_versions"][0]["versions"]
        versions[-1]["commit"] = None
        versions[-1].pop("pending_commit", None)
        if with_pending:
            versions[-1]["pending_commit"] = True
        if drop_history:
            versions[0]["commit"] = None
        if mutate:
            mutate(data)
        versions_path.write_text(json.dumps(data))
        gate.REPO = str(root)
        rep = gate.Report()
        gate.check_report_integrity(rep, strict=strict)
        return (not rep.failures) if strict else (not rep.failures and bool(rep.warnings))
    commit_cases = {
        "基线有提交+当前待提交通过": commits_check(strict=True),
        "历史版本缺提交被拒": not commits_check(drop_history=True, strict=True),
        "当前版未标待提交被拒": not commits_check(with_pending=False, strict=True),
        "常规模式仅提示": commits_check(with_pending=False, strict=False),
        "unarchived 缺说明被拒": not commits_check(
            mutate=lambda r: r["report_versions"][0].update(unarchived_versions=[{"sha256": "0" * 64}]), strict=True),
        # DEV-032：历史版本缺提交不得拿当前字节顶替——常规只提示、严格失败
        "历史缺提交常规仅提示": commits_check(drop_history=True, strict=False),
        # DEV-032 组合反例：缺提交但边界可推导时，后续段的追加哈希错误在常规模式也必须 FAIL
        "历史缺提交+追加哈希错误仍拒": not commits_check(
            drop_history=True, strict=False,
            mutate=lambda r: r["report_versions"][0]["versions"][-1].update(added_sha256="0" * 64)),
        # 边界不可推导（登记哈希与已知边界不符）时不猜追加内容，只报历史缺项
        "边界不可推导不误判": not commits_check(
            drop_history=True, strict=True,
            mutate=lambda r: r["report_versions"][0]["versions"][0].update(sha256="0" * 64)),
    }
    results.append(("report_version_commits", all(commit_cases.values()), str(commit_cases)))

    # 26) git_blob_at：子模块内容按父提交冻结的 gitlink 取字节（legacy/子模块支持回归）
    saved_repo = identity.REPO
    try:
        root = Path(make_tmp(prefix="selftest-submodule-"))
        env = ["-c", "user.name=F", "-c", "user.email=f@example.invalid", "-c", "commit.gpgsign=false"]
        sub = root / "upstream"
        (sub / "src").mkdir(parents=True)
        (sub / "src" / "file.txt").write_text("A\n", encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "-A"], env + ["commit", "-qm", "A"]):
            subprocess.run(["git", "-C", str(sub)] + cmd, check=True, capture_output=True)
        parent = root / "parent"
        parent.mkdir()
        (parent / "outside.txt").write_text("x\n", encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "-A"], env + ["commit", "-qm", "init"]):
            subprocess.run(["git", "-C", str(parent)] + cmd, check=True, capture_output=True)
        added = subprocess.run(["git", "-C", str(parent), "-c", "protocol.file.allow=always",
                                "submodule", "add", str(sub), "mod"],
                               capture_output=True, text=True)
        if added.returncode:
            results.append(("identity_submodule_blob", False,
                            f"无法构建子模块夹具: {added.stderr.strip()[:120]}"))
            return results
        subprocess.run(["git", "-C", str(parent)] + env + ["commit", "-qm", "add submodule"],
                       check=True, capture_output=True)
        frozen = subprocess.run(["git", "-C", str(parent), "rev-parse", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
        # 前移子模块 HEAD：父提交冻结的字节必须仍然取自 gitlink
        (sub / "src" / "file.txt").write_text("B\n", encoding="utf-8")
        for cmd in (["add", "-A"], env + ["commit", "-qm", "B"]):
            subprocess.run(["git", "-C", str(sub)] + cmd, check=True, capture_output=True)
        identity.REPO = parent
        cases = {
            "冻结 gitlink 字节": identity.git_blob_at(frozen, "mod/src/file.txt") == b"A\n",
            "子模块工作区已前移仍取冻结值":
                identity.git_blob_at(frozen, "mod/src/file.txt") != (sub / "src" / "file.txt").read_bytes(),
            "缺失路径为 None": identity.git_blob_at(frozen, "mod/src/missing.txt") is None,
            "--filters 路径可用": identity.blobs_at(frozen, ["mod/src/file.txt"], filters=True).get("mod/src/file.txt") == b"A\n",
            "未知提交为 None": identity.git_blob_at("0" * 40, "mod/src/file.txt") is None,
        }
        # 子模块迁移：冻结提交引用旧路径，工作树已改名 → 通过冻结 .gitmodules 的稳定名读对象库
        moved = subprocess.run(["git", "-C", str(parent), "mv", "mod", "mod2"], capture_output=True, text=True)
        subprocess.run(["git", "-C", str(parent)] + env + ["commit", "-qm", "move submodule"],
                       check=True, capture_output=True)
        if moved.returncode == 0:
            cases["迁移后仍可读冻结旧路径"] = identity.git_blob_at(frozen, "mod/src/file.txt") == b"A\n"
            cases["迁移后新路径可读"] = identity.git_blob_at(frozen, "mod2/src/file.txt") is None
        results.append(("identity_submodule_blob", all(cases.values()), str(cases)))
    finally:
        identity.REPO = saved_repo

    # 27) legacy_info：转接后同步 kp_compat 元信息（维护者侧回归）
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("_sag", str(REPO / "tools" / "selftest_artifact_gate.py"))
        _sag = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_sag)
        _pspec = _ilu.spec_from_file_location("_po", str(REPO / "patch_offsets.py"))
        _po = _ilu.module_from_spec(_pspec); _pspec.loader.exec_module(_po)
        modern, _ = _sag.fixture(kp_compat="modern")
        patched, ranges = _po.legacy_info(modern)
        offset = ranges[0]["offset"] if ranges else -1
        again, again_ranges = _po.legacy_info(patched)
        try:
            _po.legacy_info(_sag.fixture(kp_compat="weird")[0])
            rejected = False
        except ValueError:
            rejected = True
        cases = {
            "modern→legacy 同步": len(patched) == len(modern) and patched[offset:offset + 6] == b"legacy"
                                  and modern[offset:offset + 6] == b"modern",
            "范围记录": ranges == [{"offset": offset, "size": 6}],
            "已是 legacy 不改写": again == patched and again_ranges == [],
            "非法取值被拒": rejected,
        }
        results.append(("legacy_info_metadata", all(cases.values()), str(cases)))
    except Exception as exc:
        results.append(("legacy_info_metadata", False, f"夹具异常: {exc}"))

    # 28) structure：只查关键路径 + 目录级（模板/手册不再逐一点名）
    tmp = make_tmp()
    for rel, suffix, least in gate.REQUIRED_DIRS:
        os.makedirs(os.path.join(tmp, rel), exist_ok=True)
        for index in range(least if suffix else 0):
            open(os.path.join(tmp, rel, f"f{index}{suffix}"), "w").write("x")
    for rel in gate.REQUIRED_PATHS:
        target = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        open(target, "w").write("x")
    gate.REPO = tmp
    ok_rep = gate.Report()
    gate.check_structure(ok_rep)
    os.remove(os.path.join(tmp, "metadata", "identity.json"))
    bad_rep = gate.Report()
    gate.check_structure(bad_rep)
    results.append(("structure_core", not ok_rep.failures and bool(bad_rep.failures),
                    f"关键路径齐备通过={not ok_rep.failures}，缺 identity.json 被拒={bool(bad_rep.failures)}"))

    # 29) 问题单仪式：未关闭要 closure；已关闭要 resolution 或 closure
    def schema_ok(issue):
        _, main_sha, kp_sha = _schema_repo({"module": "mod", "status": "candidate", "version_declared": "1.0",
                                            "version_sources": {"makefile": "1.0"}, "builds": [], "issues": [issue]}, gate)
        rep = gate.Report()
        gate.check_metadata_schema(rep)
        return not rep.failures

    open_issue = {"id": "MNT-001", "severity": "中", "owner": "Developer", "status": "open",
                  "title": "t", "evidence": "e", "closure": "c"}
    closed_base = {"id": "MNT-001", "severity": "中", "owner": "Developer", "status": "closed",
                   "title": "t", "evidence": "e", "closed_by": "维护者"}
    closure_cases = {
        "open 带 closure 通过": schema_ok(dict(open_issue)),
        "open 缺 closure 被拒": not schema_ok({k: v for k, v in open_issue.items() if k != "closure"}),
        "closed 只有 resolution 通过": schema_ok(dict(closed_base, resolution="r")),
        "closed 两者皆无被拒": not schema_ok(dict(closed_base)),
    }
    results.append(("issue_closure_ceremony", all(closure_cases.values()), str(closure_cases)))

    # 30) 实机复测必须绑定在册字节（事实判据，替代原先查报告 token）
    def device_ok(test):
        tmp, main_sha, kp_sha = _schema_repo(None, gate)
        art = {"name": "m_1.0.kpm", "sha256": "a" * 64}
        record = {"module": "mod", "status": "candidate", "version_declared": "1.0",
                  "version_sources": {"makefile": "1.0"}, "issues": [],
                  "builds": [{"build_id": "b", "instance_id": "m-1.0#1", "source_commit": main_sha,
                              "source_tree_sha256": "1" * 64, "fingerprint_sha256": "2" * 64, "toolchain": "t",
                              "kernelpatch_commit": kp_sha, "recipe": {}, "sources": [], "artifacts": [art]}],
                  "device_tests": [test]}
        json.dump(record, open(os.path.join(tmp, "metadata", "modules", "mod.json"), "w"))
        rep = gate.Report()
        gate.check_metadata_schema(rep)
        return not rep.failures

    good_test = {"kind": "retest-in-registry", "instance_id": "m-1.0#1",
                 "tested_bytes": {"sha256": "a" * 64, "registered": True, "in_registry_match": True}}
    def port_ok(derived_sha):
        tmp, main_sha, kp_sha = _schema_repo(None, gate)
        art = {"name": "m_1.0.kpm", "sha256": "a" * 64}
        record = {"module": "mod", "status": "candidate", "version_declared": "1.0",
                  "version_sources": {"makefile": "1.0"}, "issues": [],
                  "builds": [{"build_id": "b", "instance_id": "m-1.0#1", "source_commit": main_sha,
                              "source_tree_sha256": "1" * 64, "fingerprint_sha256": "2" * 64, "toolchain": "t",
                              "kernelpatch_commit": kp_sha, "recipe": {}, "sources": [], "artifacts": [art]}],
                  "binary_ports": [{"kind": "binary-port", "base_instance_id": "m-1.0#1",
                                    "derived": {"name": "m_1.0.kpm", "sha256": "c" * 64}}],
                  "device_tests": [{"kind": "retest-in-registry", "instance_id": "m-1.0#1",
                                    "tested_bytes": {"sha256": derived_sha, "registered": True,
                                                     "in_registry_match": True}}]}
        json.dump(record, open(os.path.join(tmp, "metadata", "modules", "mod.json"), "w"))
        rep = gate.Report()
        gate.check_metadata_schema(rep)
        return not rep.failures

    device_cases = {
        "在册绑定通过": device_ok(dict(good_test)),
        "派生件绑定通过": port_ok("c" * 64),
        "非本实例派生件被拒": not port_ok("d" * 64),
        "未声明一致被拒": not device_ok(dict(good_test, tested_bytes={"sha256": "a" * 64})),
        "哈希不在产物中被拒": not device_ok(dict(good_test, tested_bytes=dict(good_test["tested_bytes"], sha256="b" * 64))),
        "非复测条目不检查": device_ok({"kind": "destructive-risk-verification", "instance_id": "m-1.0#1"}),
    }
    results.append(("device_test_binding", all(device_cases.values()), str(device_cases)))

    # 31) README 标题只作提示：版本事实由 Makefile ↔ version_declared 判定
    tmp = _gate_repo({"module": "rmod", "version_declared": "2.0",
                      "version_sources": {"makefile": "2.0", "readme_heading": "1.9"},
                      "builds": [{"instance_id": "b", "version": "2.0",
                                  "artifacts": [{"name": "a.kpm", "embedded": {"name": "rmod", "version": "2.0"}}]}]}, gate)
    os.makedirs(os.path.join(tmp, "rmod"), exist_ok=True)
    open(os.path.join(tmp, "rmod", "Makefile"), "w").write("MYKPM_VERSION := 2.0\n")
    rep = gate.Report()
    gate.check_version_consistency(rep)
    noted = any("README" in detail for _n, _s, detail in rep.checks)
    results.append(("readme_heading_note", not rep.failures and noted,
                    f"无失败={not rep.failures}，README 差异仅提示={noted}"))

    # 32) 卫生检查必须扫到中文为主的报告（探测边界切在多字节字符中间时曾整份跳过）
    tmp = make_tmp()
    subprocess.run(["git", "-C", tmp, "init", "-q"], check=True, capture_output=True)
    os.makedirs(os.path.join(tmp, "docs"), exist_ok=True)
    filler = "中" * ((65536 - 1) // 3)          # 3 字节汉字：恰好把 65536 边界切开
    absolute = "/" + "Users" + "/someone/Library/Android/sdk/ndk/26.3"
    report = Path(tmp) / "docs" / "report.md"
    report.write_text(filler + "\nANDROID_NDK=" + absolute + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", tmp, "add", "-A"], check=True, capture_output=True)
    gate.REPO = tmp
    rep = gate.Report()
    gate.check_hygiene(rep)
    caught = bool(rep.failures)
    report.write_text(filler + "\nANDROID_NDK=<NDK>\n", encoding="utf-8")
    rep2 = gate.Report()
    gate.check_hygiene(rep2)
    clean = not rep2.failures
    results.append(("hygiene_cjk_text", caught and clean,
                    f"中文报告里的绝对路径被检出={caught}，脱敏后通过={clean}"))

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
