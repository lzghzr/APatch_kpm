#!/usr/bin/env python3
"""维护者宿主回归：实例选择机制及共享清单协议；不产生独立审计/设备结论。"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protocol_decode(payload):
    """按协议另写的参考解码，不调用生产解码/哈希助手；仅作宿主对照。"""
    fields = {"sources": list, "recipe": dict, "build_transaction": dict}
    result = copy.deepcopy(payload)
    if "handoff_schema" not in result and "shared_data" not in result:
        if any(isinstance(b.get(f), dict) and "data_ref" in b[f]
               for b in result.get("builds", []) for f in fields):
            raise ValueError("missing schema")
        return result
    schema = result.pop("handoff_schema", None)
    if type(schema) is not int or schema != 2:
        raise ValueError("schema")
    table = result.pop("shared_data", None)
    if not isinstance(table, dict) or not table or not isinstance(result.get("builds"), list):
        raise ValueError("table/builds")
    for key, value in table.items():
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if key != hashlib.sha256(encoded).hexdigest():
            raise ValueError("digest")
    used = set()
    for build in result["builds"]:
        if not isinstance(build, dict):
            raise ValueError("build")
        for field, expected in fields.items():
            ref = build.get(field)
            if not isinstance(ref, dict) or "data_ref" not in ref:
                continue
            if list(ref) != ["data_ref"] or not isinstance(ref["data_ref"], str):
                raise ValueError("reference")
            key = ref["data_ref"]
            if key not in table or not isinstance(table[key], expected):
                raise ValueError("missing/type")
            if isinstance(table[key], dict) and "data_ref" in table[key]:
                raise ValueError("nested")
            build[field] = copy.deepcopy(table[key])
            used.add(key)
    if used != set(table):
        raise ValueError("unused")
    return result


def run_checks():
    audit = load("report_scope_audit", ROOT / "Auditor/tools/artifact_audit.py")
    identity = load("report_shared_identity", ROOT / "tools/identity.py")
    cases = {}
    with tempfile.TemporaryDirectory(prefix="report-generation-") as temp:
        root = Path(temp)
        (root / "metadata/modules").mkdir(parents=True)
        (root / "artifacts").mkdir()
        snapshot = root / "snapshot.json"
        snapshot.write_text(json.dumps({"kernelpatch_commit": "a" * 40, "symbols": {}}))
        builds = []
        for instance, name in [("b#1", "a"), ("b#2", "b"), ("c#1", "c")]:
            p = root / "artifacts" / (name + ".kpm")
            p.write_bytes(name.encode())
            builds.append({"instance_id": instance, "build_id": instance.split("#")[0],
                           "source_commit": "a" * 40, "version": "1.0",
                           "artifacts": [{"path": str(p.relative_to(root)), "name": p.name,
                                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}]})
        record = {"module": "fixture", "builds": builds}
        record_path = root / "metadata/modules/fixture.json"
        calls = []

        def fake_audit(path, selected, *args, **kwargs):
            calls.append((Path(path).name, [b["instance_id"] for b in selected["builds"]]))
            facts = {"name": Path(path).name, "size": 1, "sha256": "f" * 64,
                     "embedded": {}, "undefined_symbols": [], "unresolved_symbols": [],
                     "relocations": {"count": 0, "bad": 0, "types": {}},
                     "kernel_symbol_dependencies": {}}
            findings = [("error", "fixture_error", "synthetic selected finding")] if fail_selected else []
            return facts, findings

        fail_selected = False

        def invoke(*extra):
            record_path.write_text(json.dumps(record))
            output = root / "out.json"
            output.unlink(missing_ok=True)
            argv = ["audit", "--module", "fixture", "--snapshot", str(snapshot),
                    "--corpus", str(root / "no-corpus"), "--json", str(output), *extra]
            calls.clear()
            with patch.object(audit, "REPO", str(root)), patch.object(sys, "argv", argv), \
                    patch.object(audit, "audit_artifact", fake_audit), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = audit.main()
            return rc, json.loads(output.read_text()) if output.exists() else None, copy.deepcopy(calls)

        rc, report, hits = invoke()
        cases["default_all"] = rc == 0 and len(hits) == 3
        rc, report, hits = invoke("--instance-id", "b#2")
        cases["exact_same_build_id"] = rc == 0 and hits == [("b.kpm", ["b#2"])]
        cases["scope_receipt"] = report["selection"]["audited_instances"] == ["b#2"] and \
            report["artifacts"][0]["instance_id"] == "b#2" and report["artifacts"][0]["source_commit"] == "a" * 40
        rc, _, hits = invoke("--instance-id", "b#1", "--instance-id", "c#1")
        cases["multiple_exact"] = rc == 0 and len(hits) == 2
        rc, _, hits = invoke("--instance-id", "b#1", "--instance-id", "b#1")
        cases["duplicate_request"] = rc == 0 and len(hits) == 1
        for label, options in {
            "prefix_rejected": ["--instance-id", "b"],
            "unknown_rejected": ["--instance-id", "unknown#1"],
            "one_unknown_rejected": ["--instance-id", "b#1", "--instance-id", "unknown#1"],
            "build_conflict": ["--instance-id", "b#1", "--build-id", "c"],
            "version_conflict": ["--instance-id", "b#1", "--version", "2.0"],
        }.items():
            rc, report, hits = invoke(*options)
            cases[label] = rc == 2 and report is None and not hits
        saved = builds[0]["artifacts"]
        builds[0]["artifacts"] = []
        cases["empty_artifacts_rejected"] = invoke("--instance-id", "b#1")[0] == 2
        builds[0]["artifacts"] = saved + [{"path": "artifacts/missing.kpm", "sha256": "d" * 64}]
        cases["partial_artifacts_rejected"] = invoke("--instance-id", "b#1")[0] == 2
        builds[0]["artifacts"] = saved
        (root / "artifacts/a.kpm").unlink()
        cases["missing_selected_rejected"] = invoke("--instance-id", "b#1")[0] == 2
        rc, report, _ = invoke("--instance-id", "b#2")
        cases["historical_missing_still_scanned"] = rc == 0 and any(
            f["kind"] == "registered_artifact_missing" for f in report["findings"])
        (root / "artifacts/unknown.kpm").write_bytes(b"unknown")
        rc, report, _ = invoke("--instance-id", "b#2")
        cases["global_unregistered_preserved"] = rc == 0 and any(
            f["kind"] == "unregistered_artifact" for f in report["findings"])
        cases["strict_unregistered_preserved"] = invoke("--instance-id", "b#2", "--strict-unregistered")[0] == 1
        fail_selected = True
        cases["selected_error_preserved"] = invoke("--instance-id", "b#2")[0] == 1
        fail_selected = False
        cases["old_build_filter"] = len(invoke("--build-id", "b")[2]) == 1  # a.kpm remains absent

    plain = {"builds": [{"sources": [{"path": "x", "sha256": "a" * 64}] * 20,
                         "recipe": {"command": "命令" * 300, "captured": False, "returncode": 0}}
                        for _ in range(2)]}
    shared = identity.compact_handoff(plain)
    canonical = lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    cases["reference_decoder_lossless"] = canonical(protocol_decode(shared)) == canonical(plain)
    cases["reference_legacy"] = canonical(protocol_decode(plain)) == canonical(plain)
    for label, mutate in {
        "tampered": lambda x: x["shared_data"].__setitem__(next(iter(x["shared_data"])), []),
        "missing": lambda x: x["shared_data"].clear(),
        "boolean_schema": lambda x: x.__setitem__("handoff_schema", True),
        "pointer_extra": lambda x: x["builds"][0]["sources"].update(extra=True),
        "wrong_type": lambda x: x["builds"][0].__setitem__("recipe", copy.deepcopy(x["builds"][0]["sources"])),
    }.items():
        bad = copy.deepcopy(shared)
        mutate(bad)
        rejected = []
        for decode in (protocol_decode, identity.expand_handoff):
            try:
                decode(bad)
                rejected.append(False)
            except (ValueError, TypeError):
                rejected.append(True)
        cases["dual_decoder_" + label] = all(rejected)
    return cases


if __name__ == "__main__":
    results = run_checks()
    print(json.dumps(results, ensure_ascii=False, indent=2))
    sys.exit(0 if all(results.values()) else 1)
