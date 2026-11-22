#!/usr/bin/env python3
"""核对实际静态 KPM 在无旁车时的导出、离线修改、拒绝及旧版兼容。"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patch_offsets import configuration_sections, embedded_layout_fields


def command(*args, error=None):
    result = subprocess.run([sys.executable, str(ROOT / "patch_offsets.py"), *map(str, args)],
                            text=True, capture_output=True)
    if error is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0 and error in result.stderr, result


def companion(kpm):
    return kpm.with_suffix(kpm.suffix + ".json")


def check(legacy, embedded, source, temp):
    image, original = embedded.read_bytes(), legacy.read_bytes()
    start, length, abi, raw = configuration_sections(image)
    old_start, old_length, old_abi, old_raw = configuration_sections(original)
    assert raw is not None and old_raw is None
    assert (length, abi) == (old_length, old_abi)
    assert image[start:start + length] == original[old_start:old_start + old_length]
    fields = embedded_layout_fields(raw, length, abi)
    old_layout = json.loads(companion(legacy).read_text())
    new_layout = json.loads(companion(embedded).read_text())
    for key in ("fields", "schema", "offsets", "table_size", "binder_abi"):
        assert old_layout.get(key) == new_layout.get(key), key
    assert fields == new_layout["fields"]

    alone = temp / embedded.name
    shutil.copyfile(embedded, alone)
    assert not companion(alone).exists()
    extracted, legacy_dump, new_dump = (temp / name for name in ("layout.json", "legacy.bin", "new.bin"))
    command("baseline", alone, "--output", extracted)
    assert extracted.read_bytes() == companion(embedded).read_bytes()
    command("baseline", alone, "--source", source, "--output", temp / "from-source.json")
    assert extracted.read_bytes() == (temp / "from-source.json").read_bytes()
    command("dump", legacy, "--output", legacy_dump)
    command("dump", alone, "--output", new_dump)
    assert legacy_dump.read_bytes() == new_dump.read_bytes()

    values = new_layout["offsets"].copy()
    field = "binder_release_abi" if "binder_release_abi" in fields else fields[0]
    values[field] = 5 if field == "binder_release_abi" else 0
    target = temp / "fixture-target.json"
    target.write_text(json.dumps(values))
    patched = temp / "new-target.kpm"
    command("patch", alone, "--offsets", target, "--output", patched)
    new_bytes = patched.read_bytes()
    assert image != new_bytes
    assert image[:start] == new_bytes[:start] and image[start + length:] == new_bytes[start + length:]
    assert configuration_sections(new_bytes)[3] == raw
    legacy_target = temp / "legacy-target.kpm"
    payload = temp / "target.bin"
    payload.write_bytes(new_bytes[start:start + length])
    command("patch", legacy, "--blob", payload, "--output", legacy_target)
    old_bytes = legacy_target.read_bytes()
    assert old_bytes[:old_start] == original[:old_start] and old_bytes[old_start + length:] == original[old_start + length:]
    assert old_bytes[old_start:old_start + length] == payload.read_bytes()
    command("baseline", patched, "--output", temp / "patched-layout.json")
    assert json.loads((temp / "patched-layout.json").read_text()) == {
        key: value for key, value in json.loads(companion(patched).read_text()).items() if key != "parent_sha256"
    }

    wrong_order = temp / "wrong-order.json"
    wrong_order.write_text(json.dumps(dict(new_layout, fields=fields[1:2] + fields[:1] + fields[2:])))
    command("dump", alone, "--layout", wrong_order, "--output", temp / "wrong-order.bin",
            error="explicit sidecar and embedded layout field order differ")

    bad = temp / "invalid-format.kpm"
    assert image.count(raw) == 1 and raw.count(b'"format":1') == 1
    corrupted = image.replace(raw, raw.replace(b'"format":1', b'"format":9'), 1)
    bad.write_bytes(corrupted)
    # 保持外部布局与文件哈希相符，确保拒绝确实来自损坏的内嵌布局。
    sidecar = dict(new_layout, kpm=bad.name, sha256=hashlib.sha256(corrupted).hexdigest())
    companion(bad).write_text(json.dumps(sidecar))
    command("dump", bad, "--layout", companion(bad), "--output", temp / "invalid.bin",
            error="invalid embedded layout")
    assert not (temp / "invalid.bin").exists()

    print(f"{embedded.name}: {len(fields)} fields; no-sidecar export/patch, legacy dump and fail-closed PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("legacy", type=Path)
    parser.add_argument("embedded", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kpm-embedded-") as directory:
        check(args.legacy, args.embedded, args.source, Path(directory))


if __name__ == "__main__":
    main()
